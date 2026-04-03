//! S3-compatible blob store for ESSR envelope storage.
//!
//! Wraps `aws-sdk-s3` to provide PUT/GET/DELETE/HEAD operations keyed by blob digest.
//! Envelopes are stored as opaque binary blobs in MinIO.

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    primitives::ByteStream,
};
use tracing::{debug, info};

#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    #[error("S3 error: {0}")]
    S3(String),
    #[error("Blob not found: {0}")]
    NotFound(String),
}

/// S3-compatible blob store for ESSR envelopes.
pub struct BlobStore {
    client: Client,
    bucket: String,
}

impl BlobStore {
    /// Create a new blob store client.
    pub fn new(
        endpoint: &str,
        region: &str,
        bucket_name: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Self {
        let credentials = Credentials::new(access_key, secret_key, None, None, "static");

        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.to_string()))
            .endpoint_url(endpoint)
            .credentials_provider(credentials)
            .force_path_style(true)
            .build();

        let client = Client::from_conf(config);

        Self {
            client,
            bucket: bucket_name.to_string(),
        }
    }

    /// Ensure the bucket exists, creating it if necessary.
    pub async fn ensure_bucket(&self) -> Result<(), BlobStoreError> {
        match self.client.head_bucket().bucket(&self.bucket).send().await {
            Ok(_) => {
                debug!("Bucket {} exists", self.bucket);
                Ok(())
            }
            Err(err) if is_not_found(&err) => {
                info!("Bucket {} not found, creating...", self.bucket);
                self.client
                    .create_bucket()
                    .bucket(&self.bucket)
                    .send()
                    .await
                    .map_err(|e| BlobStoreError::S3(format!("Failed to create bucket: {}", e)))?;
                info!("Created bucket {}", self.bucket);
                Ok(())
            }
            Err(err) => Err(BlobStoreError::S3(format!(
                "Failed to check bucket {}: {}",
                self.bucket, err
            ))),
        }
    }

    /// Store an envelope blob by its digest.
    pub async fn put(&self, blob_digest: &str, data: &[u8]) -> Result<(), BlobStoreError> {
        let key = format!("messages/{}", blob_digest);
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type("application/octet-stream")
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(|e| BlobStoreError::S3(e.to_string()))?;

        debug!("Stored envelope blob: {}", blob_digest);
        Ok(())
    }

    /// Retrieve an envelope blob by its digest.
    pub async fn get(&self, blob_digest: &str) -> Result<Vec<u8>, BlobStoreError> {
        let key = format!("messages/{}", blob_digest);
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return if is_not_found(&e) {
                    Err(BlobStoreError::NotFound(blob_digest.to_string()))
                } else {
                    Err(BlobStoreError::S3(e.to_string()))
                };
            }
        };

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| BlobStoreError::S3(e.to_string()))?;

        Ok(bytes.to_vec())
    }

    /// Delete an envelope blob by its digest.
    pub async fn delete(&self, blob_digest: &str) -> Result<(), BlobStoreError> {
        let key = format!("messages/{}", blob_digest);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| BlobStoreError::S3(e.to_string()))?;

        debug!("Deleted envelope blob: {}", blob_digest);
        Ok(())
    }
}

/// Check if an SDK error is a "not found" (404) response.
fn is_not_found<E: std::fmt::Debug>(err: &aws_sdk_s3::error::SdkError<E>) -> bool {
    matches!(
        err,
        aws_sdk_s3::error::SdkError::ServiceError(context)
            if context.raw().status().as_u16() == 404
    )
}
