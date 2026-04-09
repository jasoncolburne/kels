use std::collections::HashMap;

use kels_core::SadStore;

use crate::{compaction::compact_with_schema, error::CredentialError, schema::Schema};

/// Compact credential values using schema-aware compaction and store all
/// resulting chunks in a single batch.
pub async fn store_credentials(
    mut values: Vec<serde_json::Value>,
    schema: &Schema,
    sad_store: &dyn SadStore,
) -> Result<(), CredentialError> {
    let mut all_chunks = HashMap::new();
    for value in &mut values {
        let cred_schema = value
            .get("schema")
            .and_then(|s| s.as_str())
            .ok_or_else(|| {
                CredentialError::InvalidCredential("credential has no schema field".to_string())
            })?;
        if cred_schema != schema.said.as_ref() {
            return Err(CredentialError::InvalidSchema(format!(
                "schema SAID mismatch: credential references {cred_schema}, \
                 provided schema has {}",
                schema.said
            )));
        }
        let chunks = compact_with_schema(value, schema)?;
        all_chunks.extend(chunks);
    }
    sad_store.store_batch(&all_chunks).await?;
    Ok(())
}
