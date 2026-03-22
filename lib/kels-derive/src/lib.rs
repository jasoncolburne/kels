use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Lit, parse_macro_input};

/// Derive macro for SignedEvents - generates signature storage methods for a KeyEvent repository.
///
/// This macro generates methods for storing and retrieving signed key events:
/// - `SIGNATURES_TABLE_NAME` constant
/// - `create_with_signatures(item, signatures)` for storing events with signatures
/// - `get_signatures_by_saids(saids)` for batch signature retrieval
/// - `get_signed_history(prefix, limit, offset)` for getting paginated signed events
/// - `save_with_merge(prefix, events)` for full merge with verification and divergence handling
///
/// Also generates `SignedEventRepository` trait implementation.
///
/// Requires `Stored` derive to be present (uses `Self::TABLE_NAME`).
///
/// ## Attributes
///
/// - `signatures_table`: The signatures table name (required)
/// - `recovery_table`: Recovery tracking table for async adversary archival (required)
///
/// ## Example
///
/// ```text
/// #[derive(Stored, SignedEvents)]
/// #[stored(item_type = KeyEvent, table = "kels_key_events")]
/// #[signed_events(signatures_table = "kels_key_event_signatures", recovery_table = "kels_recovery")]
/// pub struct KeyEventRepository {
///     pub pool: PgPool,
/// }
/// ```
#[proc_macro_derive(SignedEvents, attributes(signed_events))]
pub fn derive_signed_events(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let repo_name = &input.ident;

    // Parse #[signed_events(...)] attribute
    let signed_events_attr = input
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("signed_events"))
        .expect("No #[signed_events(...)] attribute found");

    let mut signatures_table: Option<String> = None;
    let mut recovery_table: Option<String> = None;

    signed_events_attr
        .parse_nested_meta(|meta| {
            if meta.path.is_ident("signatures_table") {
                meta.input.parse::<syn::Token![=]>()?;
                let lit: Lit = meta.input.parse()?;
                if let Lit::Str(s) = lit {
                    signatures_table = Some(s.value());
                }
            } else if meta.path.is_ident("recovery_table") {
                meta.input.parse::<syn::Token![=]>()?;
                let lit: Lit = meta.input.parse()?;
                if let Lit::Str(s) = lit {
                    recovery_table = Some(s.value());
                }
            }
            Ok(())
        })
        .expect("Failed to parse #[signed_events(...)] attribute");

    let signatures_table =
        signatures_table.expect("Missing signatures_table in #[signed_events(...)]");

    let recovery_table = recovery_table.expect("Missing recovery_table in #[signed_events(...)]");

    // Generate the methods
    let methods = quote! {
        impl #repo_name {
            /// The signatures table name for this repository.
            pub const SIGNATURES_TABLE_NAME: &'static str = #signatures_table;

            /// Store an item with its signatures in a transaction.
            pub async fn create_with_signatures(
                &self,
                item: kels::KeyEvent,
                signatures: Vec<kels::EventSignature>,
            ) -> Result<kels::KeyEvent, verifiable_storage::StorageError> {
                use verifiable_storage::SelfAddressed;

                let mut tx = self
                    .pool
                    .inner()
                    .begin()
                    .await
                    .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;

                // Insert the item
                verifiable_storage_postgres::bind_insert_with_table_tx(&mut tx, &item, Self::TABLE_NAME).await?;

                // Store the signatures
                for signature in &signatures {
                    let sig = kels::EventSignature::create(
                        item.said.clone(),
                        signature.label.clone(),
                        signature.signature.clone(),
                    ).map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;
                    verifiable_storage_postgres::bind_insert_with_table_tx(&mut tx, &sig, Self::SIGNATURES_TABLE_NAME).await?;
                }

                tx.commit()
                    .await
                    .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;

                Ok(item)
            }

            /// Get signatures for multiple SAIDs in one query.
            pub async fn get_signatures_by_saids(
                &self,
                saids: &[String],
            ) -> Result<std::collections::HashMap<String, Vec<kels::EventSignature>>, verifiable_storage::StorageError> {
                use verifiable_storage_postgres::QueryExecutor;

                let query = verifiable_storage_postgres::Query::<kels::EventSignature>::for_table(Self::SIGNATURES_TABLE_NAME)
                    .r#in("event_said", saids.to_vec());
                let sigs = self.pool.fetch(query).await?;

                let mut map: std::collections::HashMap<String, Vec<kels::EventSignature>> =
                    std::collections::HashMap::new();
                for sig in sigs {
                    map.entry(sig.event_said.clone()).or_default().push(sig);
                }

                Ok(map)
            }

            /// Get a single signature by event SAID.
            pub async fn get_signature_by_said(
                &self,
                said: &str,
            ) -> Result<Option<kels::EventSignature>, verifiable_storage::StorageError> {
                use verifiable_storage_postgres::QueryExecutor;

                let query = verifiable_storage_postgres::Query::<kels::EventSignature>::for_table(Self::SIGNATURES_TABLE_NAME)
                    .eq("event_said", said)
                    .limit(1);
                self.pool.fetch_optional(query).await
            }

            /// Query the recovery serial cap for a prefix. Returns `Some(serial)` if
            /// an active (non-recovered) recovery exists, `None` otherwise.
            async fn recovery_serial_cap(
                tx: &mut impl verifiable_storage::TransactionExecutor,
                prefix: &str,
            ) -> Result<Option<u64>, verifiable_storage::StorageError> {
                let query = verifiable_storage::Query::<kels::RecoveryRecord>::for_table(#recovery_table)
                    .eq("kel_prefix", prefix)
                    .order_by("version", verifiable_storage::Order::Desc)
                    .limit(1);
                let records: Vec<kels::RecoveryRecord> = tx.fetch(query).await?;
                Ok(records.into_iter().next().and_then(|r| {
                    if r.state != kels::RecoveryState::Recovered {
                        Some(r.recovery_serial)
                    } else {
                        None
                    }
                }))
            }

            /// Get a paginated page of signed events for a prefix.
            ///
            /// Returns `(events, has_more)` — fetches `limit + 1` rows and pops the extra
            /// to determine whether more pages exist.
            /// Events are ordered by `serial ASC, kind sort_priority ASC, said ASC` for deterministic pagination.
            /// During active recovery, events are capped at the recovery serial.
            pub async fn get_signed_history(
                &self,
                prefix: &str,
                limit: u64,
                offset: u64,
            ) -> Result<(Vec<kels::SignedKeyEvent>, bool), verifiable_storage::StorageError> {
                use verifiable_storage::{QueryExecutor, TransactionExecutor};

                let mut tx = self.pool.begin_transaction().await?;
                let max_serial = Self::recovery_serial_cap(&mut tx, prefix).await?;
                let result = kels::load_signed_history(
                    &mut tx,
                    Self::TABLE_NAME,
                    Self::SIGNATURES_TABLE_NAME,
                    prefix,
                    limit,
                    offset,
                    max_serial,
                )
                .await
                .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;
                tx.commit().await?;
                Ok(result)
            }

            /// Get signed events after a given SAID (delta fetch — the since event itself is not returned).
            ///
            /// Uses a scalar subquery to find the serial of the since event, then fetches
            /// events with `serial >= that serial`, filtering out the since event itself.
            /// Returns `(events, has_more)` using the limit+2 pop pattern.
            /// Events are ordered by `serial ASC, kind sort_priority ASC, said ASC` for deterministic pagination.
            /// During active recovery, events are capped at the recovery serial.
            pub async fn get_signed_history_since(
                &self,
                prefix: &str,
                since_said: &str,
                limit: u64,
            ) -> Result<(Vec<kels::SignedKeyEvent>, bool), verifiable_storage::StorageError> {
                use verifiable_storage::{QueryExecutor, TransactionExecutor};

                let mut tx = self.pool.begin_transaction().await?;
                let max_serial = Self::recovery_serial_cap(&mut tx, prefix).await?;

                let subquery = verifiable_storage::ScalarSubquery::new(
                    Self::TABLE_NAME,
                    "serial",
                    vec![verifiable_storage::Filter::Eq(
                        "said".to_string(),
                        verifiable_storage::Value::String(since_said.to_string()),
                    )],
                );

                // Fetch limit + 2 to account for two sentinel events:
                //   +1: the since event itself — included by `>= serial` but filtered
                //       out by `retain()` below (we need `>=` not `>` to catch divergent
                //       events at the same serial as the since event)
                //   +1: the has_more sentinel — if we get more than `limit` events after
                //       filtering, there are additional pages
                // After `retain()` removes at most 1 event (the since event), we check
                // `events.len() > limit` to detect has_more, then truncate to `limit`.
                // Clamp to prevent i64 overflow when cast for PostgreSQL LIMIT
                let clamped_limit = limit.min(kels::page_size() as u64);
                let mut query = verifiable_storage::Query::<kels::KeyEvent>::for_table(Self::TABLE_NAME)
                    .eq("prefix", prefix)
                    .gte_scalar_subquery("serial", subquery)
                    .order_by("serial", verifiable_storage::Order::Asc)
                    .order_by_case("kind", &kels::EventKind::sort_priority_mapping(), verifiable_storage::Order::Asc)
                    .order_by("said", verifiable_storage::Order::Asc)
                    .limit(clamped_limit + 2);
                if let Some(cap) = max_serial {
                    query = query.lte("serial", cap);
                }
                let mut events: Vec<kels::KeyEvent> = tx.fetch(query).await?;
                tx.commit().await?;

                // Filter out the since event itself (we want events *after* it,
                // but we need >= its serial to include divergent events at the same serial)
                events.retain(|e| e.said != since_said);

                let has_more = events.len() > clamped_limit as usize;
                if has_more {
                    events.truncate(clamped_limit as usize);
                }

                if events.is_empty() {
                    return Ok((vec![], false));
                }

                let saids: Vec<String> = events.iter().map(|e| e.said.clone()).collect();
                let signatures = self.get_signatures_by_saids(&saids).await?;

                let mut signed_events = Vec::with_capacity(events.len());
                for event in events {
                    let sigs = signatures.get(&event.said).ok_or_else(|| {
                        verifiable_storage::StorageError::StorageError(format!(
                            "No signatures found for event {}",
                            event.said
                        ))
                    })?;
                    let sig_pairs: Vec<(String, String)> = sigs
                        .iter()
                        .map(|s| (s.label.clone(), s.signature.clone()))
                        .collect();
                    signed_events.push(kels::SignedKeyEvent::from_signatures(event, sig_pairs));
                }

                Ok((signed_events, has_more))
            }

            /// Compute the effective SAID for a prefix by finding tip events (events with no successor).
            ///
            /// Uses a NOT EXISTS subquery to find tips directly in SQL rather than loading
            /// all events into memory. Returns the tip SAID for non-divergent KELs, or a
            /// deterministic hash of sorted tip SAIDs for divergent KELs.
            pub async fn compute_prefix_effective_said(
                &self,
                prefix: &str,
            ) -> Result<Option<(String, bool)>, verifiable_storage::StorageError> {
                use verifiable_storage_postgres::QueryExecutor;

                let query = verifiable_storage::ColumnQuery::new(Self::TABLE_NAME, "said")
                    .filter(verifiable_storage::Filter::Eq(
                        "prefix".to_string(),
                        verifiable_storage::Value::String(prefix.to_string()),
                    ))
                    .filter(verifiable_storage::Filter::NotExists(verifiable_storage::CorrelatedSubquery::new(
                        Self::TABLE_NAME,
                        "_cs",
                        Self::TABLE_NAME,
                        vec![("previous".to_string(), "said".to_string())],
                        vec![verifiable_storage::Filter::Eq(
                            "_cs.prefix".to_string(),
                            verifiable_storage::Value::String(prefix.to_string()),
                        )],
                    )))
                    .order(verifiable_storage_postgres::Order::Asc);

                let tip_saids: Vec<String> = self.pool.fetch_column(query).await?;

                match tip_saids.len() {
                    0 => Ok(None),
                    1 => Ok(Some((tip_saids.into_iter().next().unwrap_or_default(), false))),
                    _ => {
                        let refs: Vec<&str> = tip_saids.iter().map(|s| s.as_str()).collect();
                        Ok(Some((kels::hash_tip_saids(&refs), true)))
                    }
                }
            }

            /// Store multiple items with their signatures in a single transaction.
            /// Ensures atomicity when saving multiple events (e.g., recovery + rotation).
            pub async fn create_batch_with_signatures(
                &self,
                events: Vec<(kels::KeyEvent, Vec<kels::EventSignature>)>,
            ) -> Result<(), verifiable_storage::StorageError> {
                use verifiable_storage::SelfAddressed;

                if events.is_empty() {
                    return Ok(());
                }

                let mut tx = self
                    .pool
                    .inner()
                    .begin()
                    .await
                    .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;

                for (item, signatures) in events {
                    // Insert the item
                    verifiable_storage_postgres::bind_insert_with_table_tx(&mut tx, &item, Self::TABLE_NAME).await?;

                    // Store the signatures
                    for signature in &signatures {
                        let sig = kels::EventSignature::create(
                            item.said.clone(),
                            signature.label.clone(),
                            signature.signature.clone(),
                        ).map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;
                        verifiable_storage_postgres::bind_insert_with_table_tx(&mut tx, &sig, Self::SIGNATURES_TABLE_NAME).await?;
                    }
                }

                tx.commit()
                    .await
                    .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))?;

                Ok(())
            }

            /// Save signed events with full merge (verification, divergence detection, recovery).
            /// Uses an advisory lock on the prefix to serialize operations.
            pub async fn save_with_merge(
                &self,
                prefix: &str,
                events: &[kels::SignedKeyEvent],
            ) -> Result<kels::MergeOutcome, kels::KelsError> {
                use verifiable_storage::{QueryExecutor, TransactionExecutor};

                if events.is_empty() {
                    return Ok(kels::MergeOutcome::empty());
                }

                let mut tx = self.pool.begin_transaction().await?;
                tx.acquire_advisory_lock(prefix).await?;

                let mut merge_tx = kels::MergeTransaction::new(
                    tx,
                    prefix.to_string(),
                    Self::TABLE_NAME,
                    Self::SIGNATURES_TABLE_NAME,
                    #recovery_table,
                );

                match merge_tx.merge_events(events).await {
                    Ok(outcome) => {
                        merge_tx.commit().await?;
                        Ok(outcome)
                    }
                    Err(e) => {
                        let _ = merge_tx.rollback().await;
                        Err(e)
                    }
                }
            }
        }
    };

    let trait_impl = quote! {
        #[async_trait::async_trait]
        impl kels::SignedEventRepository for #repo_name {
            async fn get_signed_history(
                &self,
                prefix: &str,
                limit: u64,
                offset: u64,
            ) -> Result<(Vec<kels::SignedKeyEvent>, bool), kels::KelsError> {
                #repo_name::get_signed_history(self, prefix, limit, offset)
                    .await
                    .map_err(|e| kels::KelsError::StorageError(e.to_string()))
            }

            async fn get_signature_by_said(
                &self,
                said: &str,
            ) -> Result<Option<kels::EventSignature>, kels::KelsError> {
                #repo_name::get_signature_by_said(self, said)
                    .await
                    .map_err(|e| kels::KelsError::StorageError(e.to_string()))
            }

            async fn create_with_signatures(
                &self,
                event: kels::KeyEvent,
                signatures: Vec<kels::EventSignature>,
            ) -> Result<kels::KeyEvent, kels::KelsError> {
                #repo_name::create_with_signatures(self, event, signatures)
                    .await
                    .map_err(|e| kels::KelsError::StorageError(e.to_string()))
            }

            async fn create_batch_with_signatures(
                &self,
                events: Vec<(kels::KeyEvent, Vec<kels::EventSignature>)>,
            ) -> Result<(), kels::KelsError> {
                #repo_name::create_batch_with_signatures(self, events)
                    .await
                    .map_err(|e| kels::KelsError::StorageError(e.to_string()))
            }

            async fn save_with_merge(
                &self,
                prefix: &str,
                events: &[kels::SignedKeyEvent],
            ) -> Result<kels::MergeOutcome, kels::KelsError> {
                #repo_name::save_with_merge(self, prefix, events).await
            }
        }
    };

    let kel_server_impl = quote! {
        #[async_trait::async_trait]
        impl kels::KelServer for #repo_name {
            async fn load_page(
                &self,
                prefix: &str,
                limit: u64,
                offset: u64,
            ) -> Result<(Vec<kels::SignedKeyEvent>, bool), kels::KelsError> {
                self.get_signed_history(prefix, limit, offset)
                    .await
                    .map_err(kels::KelsError::from)
            }

            async fn load_page_since(
                &self,
                prefix: &str,
                since_said: &str,
                limit: u64,
            ) -> Result<(Vec<kels::SignedKeyEvent>, bool), kels::KelsError> {
                self.get_signed_history_since(prefix, since_said, limit)
                    .await
                    .map_err(kels::KelsError::from)
            }

            async fn effective_said(&self, prefix: &str) -> Result<Option<String>, kels::KelsError> {
                self.compute_prefix_effective_said(prefix)
                    .await
                    .map(|opt| opt.map(|(said, _)| said))
                    .map_err(kels::KelsError::from)
            }

            async fn event_prefix_by_said(&self, said: &str) -> Result<Option<String>, kels::KelsError> {
                use verifiable_storage::ChainedRepository;
                let event: Option<kels::KeyEvent> = self.get_by_said(said).await.map_err(kels::KelsError::from)?;
                Ok(event.map(|e| e.prefix))
            }
        }
    };

    let expanded = quote! {
        #methods
        #trait_impl
        #kel_server_impl
    };

    TokenStream::from(expanded)
}
