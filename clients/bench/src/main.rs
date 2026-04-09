//! kels-bench - KELS Load Testing Tool

use std::{
    process,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::JoinSet};

use anyhow::{anyhow, Result};
use cesr::Matter;
use clap::Parser;
use colored::Colorize;
use hdrhistogram::Histogram;
use http_body_util::BodyExt;
use kels_core::{
    HttpKelSource, KelsClient, KeyEventBuilder, SoftwareKeyProvider, VerificationKeyCode,
};

fn parse_algorithm(algorithm: &str) -> VerificationKeyCode {
    match algorithm {
        "secp256r1" => VerificationKeyCode::Secp256r1,
        "ml-dsa-65" => VerificationKeyCode::MlDsa65,
        "ml-dsa-87" => VerificationKeyCode::MlDsa87,
        other => {
            eprintln!(
                "Unknown algorithm '{}'. Valid options: secp256r1, ml-dsa-65, ml-dsa-87",
                other
            );
            std::process::exit(1);
        }
    }
}

fn test_anchor(name: &str) -> cesr::Digest {
    cesr::Digest::blake3_256(name.as_bytes())
}

const DEFAULT_KELS_URL: &str = "http://kels.node-a.kels";

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

    /// Signing algorithm (secp256r1, ml-dsa-65, or ml-dsa-87)
    #[arg(long, default_value = "ml-dsa-65")]
    algorithm: String,
}

struct TestKelConfig {
    event_count: usize,
    kel_bytes: u64,
    prefix: String,
}

struct Stats {
    histogram: Mutex<Histogram<u64>>,
    success_count: AtomicU64,
    error_count: AtomicU64,
    throughput_only: bool,
}

fn format_throughput(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}

impl Stats {
    fn new(throughput_only: bool) -> Self {
        Self {
            histogram: Mutex::new(
                #[allow(clippy::expect_used)]
                Histogram::new_with_bounds(1, 60_000_000, 3).expect("Failed to create histogram"),
            ),
            success_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            throughput_only,
        }
    }

    async fn record_success(&self, latency_us: u64) {
        if !self.throughput_only {
            #[allow(clippy::expect_used)]
            self.histogram
                .lock()
                .await
                .record(latency_us)
                .expect("histogram record failed: value exceeds configured max");
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

    async fn print_results(&self, elapsed: Duration, test_name: &str, bytes_per_request: u64) {
        let histogram = self.histogram.lock().await;
        let success = self.success_count.load(Ordering::Relaxed);
        let errors = self.error_count.load(Ordering::Relaxed);
        let total = success + errors;
        let throughput = success as f64 / elapsed.as_secs_f64();
        let bytes_per_sec = success as f64 * bytes_per_request as f64 / elapsed.as_secs_f64();

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
        println!("  Data:        {:>10}", format_throughput(bytes_per_sec));
        println!();

        if success == 0 || self.throughput_only {
            return;
        }

        // Latency statistics
        println!("{}", "Latency (µs):".yellow().bold());
        println!("  Min:         {:>10.0}", histogram.min() as f64);
        println!("  Mean:        {:>10.2}", histogram.mean());
        println!("  Max:         {:>10.0}", histogram.max() as f64);
        println!("  Std Dev:     {:>10.2}", histogram.stdev());
        println!();
        println!("{}", "Percentiles (µs):".yellow().bold());
        println!("  p50:         {:>10}", histogram.value_at_quantile(0.50));
        println!("  p75:         {:>10}", histogram.value_at_quantile(0.75));
        println!("  p90:         {:>10}", histogram.value_at_quantile(0.90));
        println!("  p95:         {:>10}", histogram.value_at_quantile(0.95));
        println!("  p99:         {:>10}", histogram.value_at_quantile(0.99));
        println!("  p99.9:       {:>10}", histogram.value_at_quantile(0.999));
    }
}

/// Resolve a KEL once to measure event count and serialized byte size.
async fn measure_kel(url: &str, prefix: &str) -> Result<TestKelConfig> {
    let prefix_digest = cesr::Digest::from_qb64(prefix)?;
    let source = HttpKelSource::new(url, "/api/v1/kels/kel/{prefix}")?;
    let events = kels_core::resolve_key_events(
        &prefix_digest,
        &source,
        kels_core::page_size(),
        kels_core::max_pages(),
        None,
    )
    .await?;
    #[allow(clippy::expect_used)]
    let kel_bytes = serde_json::to_string(&events)
        .map(|s| s.len() as u64)
        .expect("failed to serialize events for size calculation");
    Ok(TestKelConfig {
        event_count: events.len(),
        kel_bytes,
        prefix: prefix.to_string(),
    })
}

async fn create_test_kel(
    client: &KelsClient,
    event_count: usize,
    algorithm: VerificationKeyCode,
) -> Result<String> {
    // Build events offline (no client) then batch-submit to avoid per-event rate limits.
    let mut builder = KeyEventBuilder::new(SoftwareKeyProvider::new(algorithm, algorithm), None);
    let icp = builder.incept().await?;
    let prefix = icp.event.prefix;

    for i in 1..event_count {
        if i == 33 {
            builder.rotate_recovery().await?; // prevents an additional event at 64 events
        } else if i % 5 == 0 {
            builder.rotate().await?;
        } else {
            let anchor = test_anchor(&format!("test_anchor_{}", i));
            builder.interact(&anchor).await?;
        }
    }

    let response = client.submit_events(builder.pending_events()).await?;
    if !response.applied {
        anyhow::bail!("Failed to create test KEL: events were not applied");
    }
    Ok(prefix.to_string())
}

async fn setup_new_kels(
    client: &KelsClient,
    url: &str,
    algorithm: VerificationKeyCode,
) -> Result<Vec<TestKelConfig>> {
    println!("{}", "Setting up test KELs...".green().bold());

    let lengths = [1, 2, 4, 8, 16, 32, 64];
    let mut singular_kels = Vec::new();
    for &len in &lengths {
        println!("  Creating {}-event KEL...", len);
        let prefix = create_test_kel(client, len, algorithm).await?;
        println!("    Created: {}", prefix);
        let config = measure_kel(url, &prefix).await?;
        singular_kels.push(config);
    }

    println!("{}", "Setup complete!".green());
    Ok(singular_kels)
}

async fn setup_existing_kels(url: &str, prefix: &str) -> Result<Vec<TestKelConfig>> {
    println!("{}", "Skipping setup, using provided prefix...".yellow());
    let config = measure_kel(url, prefix).await?;
    Ok(vec![config])
}

type BenchClient = hyper_util::client::legacy::Client<
    hyper_util::client::legacy::connect::HttpConnector,
    http_body_util::Empty<hyper::body::Bytes>,
>;

async fn run_worker(
    client: BenchClient,
    uri: hyper::Uri,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::Relaxed) {
        let start = Instant::now();
        let ok = match client.get(uri.clone()).await {
            Ok(resp) => {
                // Drain body frame-by-frame without large allocations
                let mut body = resp.into_body();
                let mut success = true;
                while let Some(frame) = body.frame().await {
                    if frame.is_err() {
                        success = false;
                        break;
                    }
                }
                success
            }
            Err(_) => false,
        };

        let latency_us = start.elapsed().as_micros() as u64;

        if ok {
            stats.record_success(latency_us).await;
        } else {
            stats.record_error();
        }
    }
}

async fn run_benchmark(
    args: &Args,
    hyper_client: &BenchClient,
    stats: Arc<Stats>,
    uri: hyper::Uri,
    test_name: &str,
    bytes_per_request: u64,
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
    let mut tasks = JoinSet::new();
    for _ in 0..args.concurrency {
        let client = hyper_client.clone();
        let uri = uri.clone();
        let stats = stats.clone();
        let running = running.clone();

        tasks.spawn(async move {
            run_worker(client, uri, stats, running).await;
        });
    }

    if args.warmup > 0 {
        println!("\n{}", "Warming up...".yellow());
        tokio::time::sleep(Duration::from_secs(args.warmup)).await;
        stats.reset().await;
    }

    println!("{}", "Running benchmark... (Ctrl+C to stop early)".green());
    let start = Instant::now();
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(args.duration)) => {}
        _ = tokio::signal::ctrl_c() => {
            println!("\n{}", "Interrupted! Stopping benchmark...".yellow());
        }
    }
    let elapsed = start.elapsed();
    running.store(false, Ordering::Relaxed);
    while (tasks.join_next().await).is_some() {}
    stats
        .print_results(elapsed, test_name, bytes_per_request)
        .await;

    Ok(())
}

async fn run_benchmarks(args: &Args, singular_kels: &[TestKelConfig]) -> Result<()> {
    let stats = Arc::new(Stats::new(args.throughput_only));
    let hyper_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>();

    #[allow(clippy::expect_used)]
    let health_uri: hyper::Uri = format!("{}/api/v1/health", args.url)
        .parse()
        .expect("Invalid health URL");
    run_benchmark(
        args,
        &hyper_client,
        stats.clone(),
        health_uri,
        "health (baseline)",
        0,
    )
    .await?;
    stats.reset().await;

    #[allow(clippy::expect_used)]
    for config in singular_kels {
        let kel_uri: hyper::Uri = format!(
            "{}/api/v1/kels/kel/{}?limit={}",
            args.url,
            config.prefix,
            kels_core::page_size()
        )
        .parse()
        .expect("Invalid KEL URL");
        run_benchmark(
            args,
            &hyper_client,
            stats.clone(),
            kel_uri,
            &format!("get_kel ({} events)", config.event_count),
            config.kel_bytes,
        )
        .await?;
        stats.reset().await;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = KelsClient::new(&args.url)?;
    println!("{}", "Checking KELS server health...".yellow());
    match client.health().await {
        Ok(_) => println!("{}", "KELS server is healthy!".green()),
        Err(e) => {
            eprintln!("{}", format!("KELS server not available: {}", e).red());
            process::exit(1);
        }
    }

    let algorithm = parse_algorithm(&args.algorithm);

    let singular_kels = if args.skip_setup {
        let prefix = args
            .prefix
            .as_deref()
            .ok_or_else(|| anyhow!("--skip-setup requires --prefix to be specified"))?;
        setup_existing_kels(&args.url, prefix).await?
    } else {
        setup_new_kels(&client, &args.url, algorithm).await?
    };

    run_benchmarks(&args, &singular_kels).await?;

    println!();
    println!("{}", "All benchmarks complete!".green().bold());

    Ok(())
}
