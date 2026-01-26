use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Lit, parse_macro_input};

/// Derive macro for SignedEvents - generates signature storage methods for a KeyEvent repository.
///
/// This macro generates methods for storing and retrieving signed key events:
/// - `SIGNATURES_TABLE_NAME` constant
/// - `create_with_signatures(item, signatures)` for storing events with signatures
/// - `get_signatures_by_saids(saids)` for batch signature retrieval
/// - `get_signed_history(prefix)` for getting all signed events
/// - `get_kel(prefix)` for getting the full KEL
///
/// Also generates `SignedEventRepository` trait implementation.
///
/// Requires `Stored` derive to be present (uses `Self::TABLE_NAME`).
///
/// ## Attributes
///
/// - `signatures_table`: The signatures table name (required)
///
/// ## Example
///
/// ```text
/// #[derive(Stored, SignedEvents)]
/// #[stored(item_type = KeyEvent, table = "kels_key_events")]
/// #[signed_events(signatures_table = "kels_key_event_signatures")]
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

    signed_events_attr
        .parse_nested_meta(|meta| {
            if meta.path.is_ident("signatures_table") {
                meta.input.parse::<syn::Token![=]>()?;
                let lit: Lit = meta.input.parse()?;
                if let Lit::Str(s) = lit {
                    signatures_table = Some(s.value());
                }
            }
            Ok(())
        })
        .expect("Failed to parse #[signed_events(...)] attribute");

    let signatures_table =
        signatures_table.expect("Missing signatures_table in #[signed_events(...)]");

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
                        signature.public_key.clone(),
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

            /// Get the full signed history for a prefix.
            pub async fn get_signed_history(
                &self,
                prefix: &str,
            ) -> Result<Vec<kels::SignedKeyEvent>, verifiable_storage::StorageError> {
                use verifiable_storage::VersionedRepository;

                let events =
                    <Self as verifiable_storage::VersionedRepository<kels::KeyEvent>>::get_history(self, prefix).await?;
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
                        .map(|s| (s.public_key.clone(), s.signature.clone()))
                        .collect();
                    signed_events.push(kels::SignedKeyEvent::from_signatures(event, sig_pairs));
                }

                Ok(signed_events)
            }

            /// Get the full KEL for a prefix as a Kel struct.
            pub async fn get_kel(
                &self,
                prefix: &str,
            ) -> Result<kels::Kel, verifiable_storage::StorageError> {
                let signed_events = self.get_signed_history(prefix).await?;
                kels::Kel::from_events(signed_events, false)
                    .map_err(|e| verifiable_storage::StorageError::StorageError(e.to_string()))
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
                            signature.public_key.clone(),
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
        }
    };

    let trait_impl = quote! {
        #[async_trait::async_trait]
        impl kels::SignedEventRepository for #repo_name {
            async fn get_kel(&self, prefix: &str) -> Result<kels::Kel, kels::KelsError> {
                #repo_name::get_kel(self, prefix)
                    .await
                    .map_err(|e| kels::KelsError::ServerError(e.to_string()))
            }

            async fn get_signature_by_said(
                &self,
                said: &str,
            ) -> Result<Option<kels::EventSignature>, kels::KelsError> {
                #repo_name::get_signature_by_said(self, said)
                    .await
                    .map_err(|e| kels::KelsError::ServerError(e.to_string()))
            }

            async fn create_with_signatures(
                &self,
                event: kels::KeyEvent,
                signatures: Vec<kels::EventSignature>,
            ) -> Result<kels::KeyEvent, kels::KelsError> {
                #repo_name::create_with_signatures(self, event, signatures)
                    .await
                    .map_err(|e| kels::KelsError::ServerError(e.to_string()))
            }

            async fn create_batch_with_signatures(
                &self,
                events: Vec<(kels::KeyEvent, Vec<kels::EventSignature>)>,
            ) -> Result<(), kels::KelsError> {
                #repo_name::create_batch_with_signatures(self, events)
                    .await
                    .map_err(|e| kels::KelsError::ServerError(e.to_string()))
            }
        }
    };

    let expanded = quote! {
        #methods
        #trait_impl
    };

    TokenStream::from(expanded)
}
