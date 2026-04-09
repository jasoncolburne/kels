//! S3-compatible object store client for SAD objects.
//!
//! Wraps `aws-sdk-s3` to provide PUT/GET/HEAD operations keyed by SAID.
//! Objects are stored as JSON blobs in MinIO.

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    primitives::ByteStream,
};
use tracing::{debug, info};

#[derive(Debug, thiserror::Error)]
pub enum ObjectStoreError {
    #[error("S3 error: {0}")]
    S3(String),
    #[error("Object not found: {0}")]
    NotFound(String),
}

/// S3-compatible object store for SAD objects.
pub struct ObjectStore {
    client: Client,
    bucket: String,
}

impl ObjectStore {
    /// Create a new object store client.
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
    pub async fn ensure_bucket(&self) -> Result<(), ObjectStoreError> {
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
                    .map_err(|e| ObjectStoreError::S3(format!("Failed to create bucket: {}", e)))?;
                info!("Created bucket {}", self.bucket);
                Ok(())
            }
            Err(err) => Err(ObjectStoreError::S3(format!(
                "Failed to check bucket {}: {}",
                self.bucket, err
            ))),
        }
    }

    /// Check if an object exists by SAID.
    pub async fn exists(&self, said: &cesr::Digest) -> Result<bool, ObjectStoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(said.as_ref())
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(err) => {
                if is_not_found(&err) {
                    Ok(false)
                } else {
                    Err(ObjectStoreError::S3(err.to_string()))
                }
            }
        }
    }

    /// Store a JSON object by SAID.
    pub async fn put(&self, said: &cesr::Digest, data: &[u8]) -> Result<(), ObjectStoreError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(said.as_ref())
            .content_type("application/json")
            .body(ByteStream::from(data.to_vec()))
            .send()
            .await
            .map_err(|e| ObjectStoreError::S3(e.to_string()))?;

        debug!("Stored SAD object: {}", said);
        Ok(())
    }

    /// Retrieve a JSON object by SAID.
    pub async fn get(&self, said: &cesr::Digest) -> Result<Vec<u8>, ObjectStoreError> {
        let response = match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(said.as_ref())
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return if is_not_found(&e) {
                    Err(ObjectStoreError::NotFound(said.to_string()))
                } else {
                    Err(ObjectStoreError::S3(e.to_string()))
                };
            }
        };

        let bytes = response
            .body
            .collect()
            .await
            .map_err(|e| ObjectStoreError::S3(e.to_string()))?;

        Ok(bytes.to_vec())
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
