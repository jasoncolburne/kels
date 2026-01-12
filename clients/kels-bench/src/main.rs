//! kels-bench - KELS Load Testing Tool
//!
//! Measures end-to-end query latency and throughput against a running KELS server.
//! Includes setup phase to create test KELs with various event types.
//!
//! # Examples
//!
//! ```bash
//! # Run with default settings (creates test KELs, then benchmarks)
//! kels-bench --url http://localhost:80
//!
//! # Run 10 concurrent workers for 30 seconds
//! kels-bench --url http://localhost:80 --concurrency 10 --duration 30
//!
//! # Skip setup (use existing KELs)
//! kels-bench --url http://localhost:80 --skip-setup --prefix <existing_prefix>
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use hdrhistogram::Histogram;
use kels::{KelsClient, KeyEventBuilder, KeyProvider};
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use verifiable_storage::compute_said;

/// Generate a proper 44-character SAID for test data
fn test_said(name: &str) -> String {
    compute_said(&name.to_string()).expect("valid said computation")
}

const DEFAULT_KELS_URL: &str = "http://kels.kels-node-a.local";

/// KELS Load Testing Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// KELS server URL
    #[arg(short, long, default_value = DEFAULT_KELS_URL)]
    url: String,

    /// Number of concurrent workers
    #[arg(short, long, default_value = "1")]
    concurrency: usize,

    /// Test duration in seconds
    #[arg(short, long, default_value = "10")]
    duration: u64,

    /// Skip setup (use existing KELs)
    #[arg(long)]
    skip_setup: bool,

    /// KEL prefix to query (for single-KEL benchmark with --skip-setup)
    #[arg(long)]
    prefix: Option<String>,

    /// Warmup duration in seconds (not counted in statistics)
    #[arg(short, long, default_value = "1")]
    warmup: u64,

    /// Show detailed percentile breakdown
    #[arg(long)]
    verbose: bool,

    /// Skip latency tracking for maximum throughput measurement
    #[arg(long)]
    throughput_only: bool,
}

/// Test KEL configuration
struct TestKelConfig {
    /// Number of events in the KEL
    event_count: usize,
    /// The prefix after creation
    prefix: Option<String>,
}

/// Statistics collector using HDR histogram
struct Stats {
    histogram: Mutex<Histogram<u64>>,
    success_count: AtomicU64,
    error_count: AtomicU64,
    throughput_only: bool,
}

impl Stats {
    fn new(throughput_only: bool) -> Self {
        Self {
            // Track latencies from 1µs to 60s with 3 significant figures
            histogram: Mutex::new(
                Histogram::new_with_bounds(1, 60_000_000, 3).expect("Failed to create histogram"),
            ),
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            throughput_only,
        }
    }

    async fn record_success(&self, latency_us: u64) {
        if !self.throughput_only {
            self.histogram.lock().await.record(latency_us).unwrap_or(());
        }
        self.success_count.fetch_add(1, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    async fn reset(&self) {
        let mut histogram = self.histogram.lock().await;
        histogram.reset();
        self.success_count.store(0, Ordering::Relaxed);
        self.error_count.store(0, Ordering::Relaxed);
    }

    async fn print_results(&self, elapsed: Duration, test_name: &str) {
        let histogram = self.histogram.lock().await;
        let success = self.success_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let total = success + errors;
        let throughput = success as f64 / elapsed.as_secs_f64();

        println!();
        println!("{}", format!("=== {} Results ===", test_name).cyan().bold());
        println!();

        // Summary
        println!("{}", "Summary:".yellow().bold());
        println!("  Duration:    {:>10.2}s", elapsed.as_secs_f64());
        println!("  Requests:    {:>10}", total);
        println!("  Successes:   {:>10}", success);
        println!("  Errors:      {:>10}", errors);
        println!("  Throughput:  {:>10.2} req/s", throughput);
        println!();

        if success == 0 {
            println!(
                "{}",
                "No successful requests to report latency statistics.".red()
            );
            return;
        }

        // Latency statistics
        println!("{}", "Latency (µs):".yellow().bold());
        println!("  Min:         {:>10.0}", histogram.min() as f64);
        println!("  Mean:        {:>10.2}", histogram.mean());
        println!("  Max:         {:>10.0}", histogram.max() as f64);
        println!("  Std Dev:     {:>10.2}", histogram.stdev());
        println!();

        // Percentiles
        println!("{}", "Percentiles (µs):".yellow().bold());
        println!("  p50:         {:>10}", histogram.value_at_quantile(0.50));
        println!("  p75:         {:>10}", histogram.value_at_quantile(0.75));
        println!("  p90:         {:>10}", histogram.value_at_quantile(0.90));
        println!("  p95:         {:>10}", histogram.value_at_quantile(0.95));
        println!("  p99:         {:>10}", histogram.value_at_quantile(0.99));
        println!("  p99.9:       {:>10}", histogram.value_at_quantile(0.999));
    }
}

/// Create a test KEL with the specified number of events
async fn create_test_kel(client: &KelsClient, event_count: usize) -> Result<String> {
    let mut builder = KeyEventBuilder::new(KeyProvider::software(), Some(client.clone()));

    // Start with inception (auto-submitted to KELS)
    let (icp_event, _) = builder.incept().await?;
    let prefix = icp_event.prefix.clone();

    // Add remaining events (event_count - 1 more events after inception)
    for i in 1..event_count {
        // Choose event type: rotate every 5th event, otherwise interaction
        if i % 5 == 0 {
            builder.rotate().await?;
        } else {
            let anchor = test_said(&format!("test_anchor_{}", i));
            builder.interact(&anchor).await?;
        }
    }

    Ok(prefix)
}

/// Setup test KELs
async fn setup_test_kels(client: &KelsClient) -> Result<(TestKelConfig, Vec<TestKelConfig>)> {
    println!("{}", "Setting up test KELs...".green().bold());

    // Create one large KEL (32 events)
    println!("  Creating 32-event KEL...");
    let large_prefix = create_test_kel(client, 32).await?;
    println!("    Created: {}", large_prefix);

    let large_kel = TestKelConfig {
        event_count: 32,
        prefix: Some(large_prefix),
    };

    // Create 5 smaller KELs (8 events each)
    println!("  Creating 5 x 8-event KELs for batch testing...");
    let mut batch_kels = Vec::new();
    for i in 0..5 {
        let prefix = create_test_kel(client, 8).await?;
        println!("    KEL {}: {}", i + 1, prefix);
        batch_kels.push(TestKelConfig {
            event_count: 8,
            prefix: Some(prefix),
        });
    }

    println!("{}", "Setup complete!".green());
    Ok((large_kel, batch_kels))
}

#[derive(Clone)]
enum BenchmarkType {
    Health,
    GetKel { prefix: String },
    GetKels { prefixes: Vec<String> },
}

async fn run_worker(
    url: String,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    benchmark_type: BenchmarkType,
) {
    let client = KelsClient::new(&url);

    while running.load(Ordering::Relaxed) {
        let start = Instant::now();
        let result = match &benchmark_type {
            BenchmarkType::Health => client.health().await.map(|_| ()),
            BenchmarkType::GetKel { prefix } => {
                client.fetch_full_kel_unverified(prefix).await.map(|_| ())
            }
            BenchmarkType::GetKels { prefixes } => {
                let prefix_refs: Vec<&str> = prefixes.iter().map(|s| s.as_str()).collect();
                client.fetch_kels_unverified(&prefix_refs).await.map(|_| ())
            }
        };

        let latency_us = start.elapsed().as_micros() as u64;

        match result {
            Ok(_) => stats.record_success(latency_us).await,
            Err(_) => stats.record_error(),
        }
    }
}

async fn run_benchmark(
    args: &Args,
    stats: Arc<Stats>,
    benchmark_type: BenchmarkType,
    test_name: &str,
) -> Result<()> {
    println!(
        "{}",
        format!("\nStarting {} benchmark...", test_name)
            .green()
            .bold()
    );
    println!("  URL:         {}", args.url);
    println!("  Concurrency: {}", args.concurrency);
    println!("  Duration:    {}s", args.duration);
    if args.warmup > 0 {
        println!("  Warmup:      {}s", args.warmup);
    }

    let running = Arc::new(AtomicBool::new(true));

    // Spawn worker tasks
    let mut tasks = JoinSet::new();
    for _ in 0..args.concurrency {
        let url = args.url.clone();
        let stats = stats.clone();
        let running = running.clone();
        let benchmark_type = benchmark_type.clone();

        tasks.spawn(async move {
            run_worker(url, stats, running, benchmark_type).await;
        });
    }

    // Warmup phase
    if args.warmup > 0 {
        println!("\n{}", "Warming up...".yellow());
        tokio::time::sleep(Duration::from_secs(args.warmup)).await;
        stats.reset().await;
    }

    // Measurement phase
    println!("{}", "Running benchmark... (Ctrl+C to stop early)".green());
    let start = Instant::now();

    // Wait for either duration to elapse or Ctrl+C
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(args.duration)) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\n{}", "Interrupted! Stopping benchmark...".yellow());
        }
    }
    let elapsed = start.elapsed();

    // Stop workers
    running.store(false, Ordering::Relaxed);

    // Wait for workers to finish
    while (tasks.join_next().await).is_some() {}

    // Print results
    stats.print_results(elapsed, test_name).await;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let client = KelsClient::new(&args.url);

    // Health check first
    println!("{}", "Checking KELS server health...".yellow());
    match client.health().await {
        Ok(_) => println!("{}", "KELS server is healthy!".green()),
        Err(e) => {
            eprintln!("{}", format!("KELS server not available: {}", e).red());
            std::process::exit(1);
        }
    }

    // Setup or use existing KELs
    let (large_kel, batch_kels) = if args.skip_setup {
        if let Some(prefix) = &args.prefix {
            println!("{}", "Skipping setup, using provided prefix...".yellow());
            (
                TestKelConfig {
                    event_count: 0,
                    prefix: Some(prefix.clone()),
                },
                vec![],
            )
        } else {
            anyhow::bail!("--skip-setup requires --prefix to be specified");
        }
    } else {
        setup_test_kels(&client).await?
    };

    let stats = Arc::new(Stats::new(args.throughput_only));

    // Benchmark 1: Health check (baseline)
    run_benchmark(
        &args,
        stats.clone(),
        BenchmarkType::Health,
        "health (baseline)",
    )
    .await?;

    // Reset stats between benchmarks
    stats.reset().await;

    // Benchmark 2: Get single KEL (32 events)
    if let Some(prefix) = &large_kel.prefix {
        run_benchmark(
            &args,
            stats.clone(),
            BenchmarkType::GetKel {
                prefix: prefix.clone(),
            },
            &format!("get_kel ({} events)", large_kel.event_count),
        )
        .await?;
    }

    // Reset stats between benchmarks
    stats.reset().await;

    // Benchmark 3: Get multiple KELs (batch)
    if !batch_kels.is_empty() {
        let prefixes: Vec<String> = batch_kels.iter().filter_map(|k| k.prefix.clone()).collect();

        if !prefixes.is_empty() {
            run_benchmark(
                &args,
                stats.clone(),
                BenchmarkType::GetKels { prefixes },
                &format!("get_kels (batch of {} KELs)", batch_kels.len()),
            )
            .await?;
        }
    }

    println!();
    println!("{}", "All benchmarks complete!".green().bold());

    Ok(())
}
