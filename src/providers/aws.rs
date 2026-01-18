//! AWS SQS provider implementation using HTTP REST API.
//!
//! This module provides production-ready AWS SQS integration using direct HTTP calls
//! instead of the AWS SDK. This approach enables proper unit testing with mocked HTTP
//! responses, similar to the Azure provider implementation.
//!
//! ## Key Features
//!
//! - **HTTP REST API**: Direct calls to AWS SQS REST API endpoints
//! - **AWS Signature V4**: Manual request signing for authentication
//! - **Standard queues**: High-throughput scenarios (near-unlimited throughput)
//! - **FIFO queues**: Strict message ordering (3000 msgs/sec with batching)
//! - **Session support**: Via FIFO message groups
//! - **Dead letter queues**: Native AWS SQS DLQ integration
//! - **Batch operations**: Up to 10 messages per batch
//! - **Queue URL caching**: Performance optimization
//! - **Test-friendly**: Mock HTTP responses in unit tests
//!
//! ## Authentication
//!
//! Implements AWS Signature Version 4 signing with automatic credential chain:
//!
//! 1. **Explicit Credentials**: Access key and secret key from configuration
//! 2. **Environment Variables**: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
//! 3. **ECS Task Metadata**: Via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI (for ECS/Fargate)
//! 4. **EC2 Instance Metadata**: Via IMDSv2 at 169.254.169.254 (for EC2 instances)
//!
//! Temporary credentials are automatically cached and refreshed before expiration.
//!
//! ## Queue Types
//!
//! ### Standard Queues
//! - Near-unlimited throughput
//! - At-least-once delivery
//! - Best-effort ordering
//! - Use for high-throughput scenarios
//!
//! ### FIFO Queues
//! - Strict message ordering within message groups
//! - Exactly-once processing with deduplication
//! - Up to 3000 messages/second with batching
//! - Requires `.fifo` suffix in queue name
//! - Use for ordered processing requirements
//!
//! ## Session Support
//!
//! AWS SQS emulates sessions via FIFO queue message groups:
//! - SessionId maps to MessageGroupId
//! - Messages in same group processed in order
//! - Different groups can process concurrently
//! - Standard queues do not support sessions
//!
//! ## Benefits of HTTP Approach
//!
//! 1. **Testable**: Mock HTTP responses in unit tests
//! 2. **Transparent**: Full control over request/response handling
//! 3. **Lightweight**: No heavy SDK dependencies
//! 4. **Consistent**: Matches Azure provider pattern
//!
//! ## AWS Signature V4 Process
//!
//! All requests are signed using AWS Signature Version 4:
//!
//! 1. **Canonical Request**: Standardized request format
//!    - HTTP method (POST for all SQS operations)
//!    - Canonical URI (/)
//!    - Canonical query string (sorted parameters)
//!    - Canonical headers (host, x-amz-date)
//!    - Hashed payload (SHA-256)
//!
//! 2. **String to Sign**: Combines algorithm, timestamp, scope, and hashed canonical request
//!
//! 3. **Signing Key Derivation**: 4-level HMAC chain
//!    - kSecret = AWS secret access key
//!    - kDate = HMAC-SHA256(kSecret, date)
//!    - kRegion = HMAC-SHA256(kDate, region)
//!    - kService = HMAC-SHA256(kRegion, "sqs")
//!    - kSigning = HMAC-SHA256(kService, "aws4_request")
//!
//! 4. **Authorization Header**: Includes access key, credential scope, signed headers, and signature
//!
//! ## Testing
//!
//! The HTTP-based approach enables comprehensive unit testing:
//!
//! ```rust
//! use queue_runtime::providers::AwsSqsProvider;
//! use queue_runtime::AwsSqsConfig;
//!
//! # async fn test_example() {
//! // Create provider with test credentials
//! let config = AwsSqsConfig {
//!     region: "us-east-1".to_string(),
//!     access_key_id: Some("AKIAIOSFODNN7EXAMPLE".to_string()),
//!     secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string()),
//!     use_fifo_queues: false,
//! };
//!
//! let provider = AwsSqsProvider::new(config).await.unwrap();
//!
//! // Operations will fail with test credentials (expected)
//! // This tests the logic without requiring real AWS infrastructure
//! # }
//! ```
//!
//! For integration tests with LocalStack:
//!
//! ```bash
//! # Start LocalStack with SQS
//! docker run -d -p 4566:4566 -e SERVICES=sqs localstack/localstack
//!
//! # Run integration tests
//! cargo test --package queue-runtime-integration-tests
//! ```
//!
//! ## Example
//!
//! ### Using Explicit Credentials
//!
//! ```no_run
//! use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, AwsSqsConfig};
//! use queue_runtime::{Message, QueueName};
//! use bytes::Bytes;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Configure AWS SQS provider with explicit credentials
//! let config = QueueConfig {
//!     provider: ProviderConfig::AwsSqs(AwsSqsConfig {
//!         region: "us-east-1".to_string(),
//!         access_key_id: Some("your-access-key".to_string()),
//!         secret_access_key: Some("your-secret-key".to_string()),
//!         use_fifo_queues: true,
//!     }),
//!     ..Default::default()
//! };
//!
//! // Create client
//! let client = QueueClientFactory::create_client(config).await?;
//!
//! // Send a message
//! let queue = QueueName::new("my-queue".to_string())?;
//! let message = Message::new(Bytes::from("Hello, SQS!"));
//! let message_id = client.send_message(&queue, message).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Using IAM Roles (EC2/ECS)
//!
//! ```no_run
//! use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, AwsSqsConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // No explicit credentials needed - will use instance/task role
//! let config = QueueConfig {
//!     provider: ProviderConfig::AwsSqs(AwsSqsConfig {
//!         region: "us-east-1".to_string(),
//!         access_key_id: None,
//!         secret_access_key: None,
//!         use_fifo_queues: false,
//!     }),
//!     ..Default::default()
//! };
//!
//! let client = QueueClientFactory::create_client(config).await?;
//! // Credentials will be fetched automatically from instance/task metadata
//! # Ok(())
//! # }
//! ```
//!
//! ## Additional Examples
//!
//! ```no_run
//! # use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, AwsSqsConfig};
//! # use queue_runtime::{Message, QueueName};
//! # use bytes::Bytes;
//! # async fn receive_example() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = QueueClientFactory::create_client(QueueConfig::default()).await?;
//! # let queue = QueueName::new("my-queue".to_string())?;
//! // Receive messages
//! use chrono::Duration;
//! if let Some(received) = client.receive_message(&queue, Duration::seconds(10)).await? {
//!     println!("Received: {:?}", received.body);
//!     
//!     // Complete the message
//!     client.complete_message(received.receipt_handle).await?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## FIFO Queue Example
//!
//! ```no_run
//! use queue_runtime::{Message, QueueName, SessionId};
//! use bytes::Bytes;
//! # use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, AwsSqsConfig};
//!
//! # async fn fifo_example() -> Result<(), Box<dyn std::error::Error>> {
//! # let client = QueueClientFactory::create_client(QueueConfig::default()).await?;
//! // FIFO queues require session IDs for ordering
//! let queue = QueueName::new("my-queue-fifo".to_string())?;  // Note: .fifo suffix
//! let session_id = SessionId::new("order-12345".to_string())?;
//!
//! // Messages with same session ID are processed in order
//! let msg1 = Message::new(Bytes::from("First")).with_session_id(session_id.clone());
//! let msg2 = Message::new(Bytes::from("Second")).with_session_id(session_id.clone());
//!
//! client.send_message(&queue, msg1).await?;
//! client.send_message(&queue, msg2).await?;
//! # Ok(())
//! # }
//! ```

use crate::client::{QueueProvider, SessionProvider};
use crate::error::{ConfigurationError, QueueError, SerializationError};
use crate::message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceivedMessage, SessionId, Timestamp,
};
use crate::provider::{AwsSqsConfig, ProviderType, SessionSupport};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client as HttpClient;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(test)]
#[path = "aws_tests.rs"]
mod tests;

// ============================================================================
// Error Types
// ============================================================================

/// AWS SQS specific errors
#[derive(Debug, thiserror::Error)]
pub enum AwsError {
    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("SQS service error: {0}")]
    ServiceError(String),

    #[error("Queue not found: {0}")]
    QueueNotFound(String),

    #[error("Invalid receipt handle: {0}")]
    InvalidReceipt(String),

    #[error("Message too large: {size} bytes (max: {max_size})")]
    MessageTooLarge { size: usize, max_size: usize },

    #[error("Invalid configuration: {0}")]
    ConfigurationError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Sessions not supported on standard queues")]
    SessionsNotSupported,
}

impl AwsError {
    /// Check if error is transient and should be retried
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Authentication(_) => false,
            Self::NetworkError(_) => true,
            Self::ServiceError(_) => true, // Most SQS errors are transient
            Self::QueueNotFound(_) => false,
            Self::InvalidReceipt(_) => false,
            Self::MessageTooLarge { .. } => false,
            Self::ConfigurationError(_) => false,
            Self::SerializationError(_) => false,
            Self::SessionsNotSupported => false,
        }
    }

    /// Map AWS error to QueueError
    pub fn to_queue_error(self) -> QueueError {
        match self {
            Self::Authentication(msg) => QueueError::AuthenticationFailed { message: msg },
            Self::NetworkError(msg) => QueueError::ConnectionFailed { message: msg },
            Self::ServiceError(msg) => QueueError::ProviderError {
                provider: "AwsSqs".to_string(),
                code: "ServiceError".to_string(),
                message: msg,
            },
            Self::QueueNotFound(queue) => QueueError::QueueNotFound { queue_name: queue },
            Self::InvalidReceipt(receipt) => QueueError::MessageNotFound { receipt },
            Self::MessageTooLarge { size, max_size } => {
                QueueError::MessageTooLarge { size, max_size }
            }
            Self::ConfigurationError(msg) => {
                QueueError::ConfigurationError(ConfigurationError::Invalid { message: msg })
            }
            Self::SerializationError(msg) => QueueError::SerializationError(
                SerializationError::JsonError(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    msg,
                ))),
            ),
            Self::SessionsNotSupported => QueueError::ProviderError {
                provider: "AwsSqs".to_string(),
                code: "SessionsNotSupported".to_string(),
                message:
                    "Standard queues do not support session-based operations. Use FIFO queues."
                        .to_string(),
            },
        }
    }
}

// ============================================================================
// AWS Signature V4 Signing
// ============================================================================

type HmacSha256 = Hmac<Sha256>;

/// AWS Signature Version 4 signer for request authentication
///
/// Implements the AWS Signature V4 signing process:
/// 1. Create canonical request (method, URI, query, headers, payload)
/// 2. Create string to sign (algorithm, timestamp, scope, request hash)
/// 3. Derive signing key (4-level HMAC chain)
/// 4. Calculate signature and build Authorization header
///
/// ## References
///
/// - [AWS Signature V4](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html)
/// - [Signing Process](https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html)
#[derive(Clone)]
struct AwsV4Signer {
    access_key: String,
    secret_key: String,
    region: String,
    service: String,
}

impl AwsV4Signer {
    /// Create new AWS Signature V4 signer
    ///
    /// # Arguments
    ///
    /// * `access_key` - AWS access key ID
    /// * `secret_key` - AWS secret access key
    /// * `region` - AWS region (e.g., "us-east-1")
    fn new(access_key: String, secret_key: String, region: String) -> Self {
        Self {
            access_key,
            secret_key,
            region,
            service: "sqs".to_string(),
        }
    }

    /// Sign an HTTP request with AWS Signature V4
    ///
    /// Returns a HashMap of headers to add to the request, including:
    /// - `Authorization`: AWS signature authorization header
    /// - `x-amz-date`: ISO8601 timestamp
    /// - `host`: Endpoint host
    ///
    /// # Arguments
    ///
    /// * `method` - HTTP method (GET, POST, etc.)
    /// * `host` - Endpoint host (e.g., "sqs.us-east-1.amazonaws.com")
    /// * `path` - Request path (e.g., "/")
    /// * `query_params` - Query parameters as key-value pairs
    /// * `body` - Request body (empty string for no body)
    /// * `timestamp` - Request timestamp
    fn sign_request(
        &self,
        method: &str,
        host: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
        timestamp: &DateTime<Utc>,
    ) -> HashMap<String, String> {
        let date_stamp = timestamp.format("%Y%m%d").to_string();
        let amz_date = timestamp.format("%Y%m%dT%H%M%SZ").to_string();

        // Task 1: Create canonical request
        let canonical_uri = path;

        // Sort query parameters for canonical request
        let mut canonical_query_string = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>();
        canonical_query_string.sort();
        let canonical_query_string = canonical_query_string.join("&");

        // Canonical headers (must be sorted)
        let canonical_headers = format!("host:{}\nx-amz-date:{}\n", host, amz_date);
        let signed_headers = "host;x-amz-date";

        // Payload hash
        let payload_hash = format!("{:x}", Sha256::digest(body.as_bytes()));

        // Build canonical request
        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            canonical_uri,
            canonical_query_string,
            canonical_headers,
            signed_headers,
            payload_hash
        );

        // Task 2: Create string to sign
        let algorithm = "AWS4-HMAC-SHA256";
        let credential_scope = format!(
            "{}/{}/{}/aws4_request",
            date_stamp, self.region, self.service
        );
        let canonical_request_hash = format!("{:x}", Sha256::digest(canonical_request.as_bytes()));

        let string_to_sign = format!(
            "{}\n{}\n{}\n{}",
            algorithm, amz_date, credential_scope, canonical_request_hash
        );

        // Task 3: Calculate signature
        let signature = self.calculate_signature(&string_to_sign, &date_stamp);

        // Task 4: Build authorization header
        let authorization_header = format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            algorithm, self.access_key, credential_scope, signed_headers, signature
        );

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), authorization_header);
        headers.insert("x-amz-date".to_string(), amz_date);
        headers.insert("host".to_string(), host.to_string());

        headers
    }

    /// Calculate AWS Signature V4 signature
    ///
    /// Uses 4-level HMAC-SHA256 chain to derive signing key:
    /// 1. kSecret = "AWS4" + secret_key
    /// 2. kDate = HMAC(kSecret, date)
    /// 3. kRegion = HMAC(kDate, region)
    /// 4. kService = HMAC(kRegion, service)
    /// 5. kSigning = HMAC(kService, "aws4_request")
    /// 6. signature = HMAC(kSigning, string_to_sign)
    fn calculate_signature(&self, string_to_sign: &str, date_stamp: &str) -> String {
        let k_secret = format!("AWS4{}", self.secret_key);
        let k_date = self.hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
        let k_region = self.hmac_sha256(&k_date, self.region.as_bytes());
        let k_service = self.hmac_sha256(&k_region, self.service.as_bytes());
        let k_signing = self.hmac_sha256(&k_service, b"aws4_request");
        let signature = self.hmac_sha256(&k_signing, string_to_sign.as_bytes());

        hex::encode(signature)
    }

    /// Compute HMAC-SHA256
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

// ============================================================================
// AWS Credential Provider
// ============================================================================

/// Temporary AWS credentials
#[derive(Debug, Clone)]
struct AwsCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    expiration: DateTime<Utc>,
}

impl AwsCredentials {
    /// Check if credentials are expired or will expire soon (within 5 minutes)
    fn is_expired(&self) -> bool {
        let now = Utc::now();
        let buffer = Duration::minutes(5);
        self.expiration - buffer <= now
    }
}

/// AWS credential provider that implements the credential chain
///
/// Attempts to load credentials in the following order:
/// 1. Explicit credentials from configuration
/// 2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
/// 3. EC2 instance metadata service (IMDSv2)
/// 4. ECS task metadata (via AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
///
/// Credentials are cached and automatically refreshed before expiration.
struct AwsCredentialProvider {
    http_client: HttpClient,
    cached_credentials: Arc<RwLock<Option<AwsCredentials>>>,
    explicit_config: Option<(String, String)>, // (access_key_id, secret_access_key)
}

impl AwsCredentialProvider {
    /// Create new credential provider
    fn new(
        http_client: HttpClient,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
    ) -> Self {
        let explicit_config = match (access_key_id, secret_access_key) {
            (Some(key_id), Some(secret)) => Some((key_id, secret)),
            _ => None,
        };

        Self {
            http_client,
            cached_credentials: Arc::new(RwLock::new(None)),
            explicit_config,
        }
    }

    /// Get credentials, refreshing if necessary
    async fn get_credentials(&self) -> Result<AwsCredentials, AwsError> {
        // Check cache first
        {
            let cache = self.cached_credentials.read().await;
            if let Some(creds) = cache.as_ref() {
                if !creds.is_expired() {
                    return Ok(creds.clone());
                }
            }
        }

        // Refresh credentials
        let creds = self.fetch_credentials().await?;

        // Update cache
        {
            let mut cache = self.cached_credentials.write().await;
            *cache = Some(creds.clone());
        }

        Ok(creds)
    }

    /// Fetch credentials from the credential chain
    async fn fetch_credentials(&self) -> Result<AwsCredentials, AwsError> {
        // 1. Try explicit configuration
        if let Some((key_id, secret)) = &self.explicit_config {
            return Ok(AwsCredentials {
                access_key_id: key_id.clone(),
                secret_access_key: secret.clone(),
                session_token: None,
                expiration: Utc::now() + Duration::days(365), // Static credentials don't expire
            });
        }

        // 2. Try environment variables
        if let Ok(creds) = self.fetch_from_environment() {
            return Ok(creds);
        }

        // 3. Try ECS task metadata
        if let Ok(creds) = self.fetch_from_ecs_metadata().await {
            return Ok(creds);
        }

        // 4. Try EC2 instance metadata
        if let Ok(creds) = self.fetch_from_ec2_metadata().await {
            return Ok(creds);
        }

        Err(AwsError::Authentication(
            "No credentials found in credential chain".to_string(),
        ))
    }

    /// Fetch credentials from environment variables
    fn fetch_from_environment(&self) -> Result<AwsCredentials, AwsError> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
            .map_err(|_| AwsError::Authentication("AWS_ACCESS_KEY_ID not set".to_string()))?;

        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
            .map_err(|_| AwsError::Authentication("AWS_SECRET_ACCESS_KEY not set".to_string()))?;

        let session_token = std::env::var("AWS_SESSION_TOKEN").ok();

        Ok(AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token,
            expiration: Utc::now() + Duration::days(365), // Environment creds don't expire
        })
    }

    /// Fetch credentials from ECS task metadata
    async fn fetch_from_ecs_metadata(&self) -> Result<AwsCredentials, AwsError> {
        let relative_uri =
            std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").map_err(|_| {
                AwsError::Authentication(
                    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI not set".to_string(),
                )
            })?;

        let endpoint = format!("http://169.254.170.2{}", relative_uri);

        let response = self
            .http_client
            .get(&endpoint)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .map_err(|e| {
                AwsError::Authentication(format!("Failed to fetch ECS credentials: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(AwsError::Authentication(format!(
                "ECS metadata returned error: {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| AwsError::Authentication(format!("Failed to read ECS metadata: {}", e)))?;

        self.parse_credentials_json(&body)
    }

    /// Fetch credentials from EC2 instance metadata (IMDSv2)
    async fn fetch_from_ec2_metadata(&self) -> Result<AwsCredentials, AwsError> {
        // Step 1: Get IMDSv2 token
        let token = self
            .http_client
            .put("http://169.254.169.254/latest/api/token")
            .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .map_err(|e| AwsError::Authentication(format!("Failed to get IMDSv2 token: {}", e)))?
            .text()
            .await
            .map_err(|e| AwsError::Authentication(format!("Failed to read IMDSv2 token: {}", e)))?;

        // Step 2: Get role name
        let role_name = self
            .http_client
            .get("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
            .header("X-aws-ec2-metadata-token", &token)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .map_err(|e| AwsError::Authentication(format!("Failed to fetch IAM role name: {}", e)))?
            .text()
            .await
            .map_err(|e| {
                AwsError::Authentication(format!("Failed to read IAM role name: {}", e))
            })?;

        // Step 3: Get credentials
        let credentials_url = format!(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/{}",
            role_name.trim()
        );

        let response = self
            .http_client
            .get(&credentials_url)
            .header("X-aws-ec2-metadata-token", &token)
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .map_err(|e| {
                AwsError::Authentication(format!("Failed to fetch EC2 credentials: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(AwsError::Authentication(format!(
                "EC2 metadata returned error: {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| AwsError::Authentication(format!("Failed to read EC2 metadata: {}", e)))?;

        self.parse_credentials_json(&body)
    }

    /// Parse credentials from JSON response
    fn parse_credentials_json(&self, json: &str) -> Result<AwsCredentials, AwsError> {
        // Parse JSON manually to avoid adding serde_json dependency
        let access_key_id = Self::extract_json_field(json, "AccessKeyId")?;
        let secret_access_key = Self::extract_json_field(json, "SecretAccessKey")?;
        let session_token = Self::extract_json_field(json, "Token").ok();
        let expiration_str = Self::extract_json_field(json, "Expiration")?;

        // Parse ISO 8601 timestamp
        let expiration = DateTime::parse_from_rfc3339(&expiration_str)
            .map_err(|e| AwsError::Authentication(format!("Invalid expiration timestamp: {}", e)))?
            .with_timezone(&Utc);

        Ok(AwsCredentials {
            access_key_id,
            secret_access_key,
            session_token,
            expiration,
        })
    }

    /// Extract a field value from JSON (simple parser, no dependencies)
    fn extract_json_field(json: &str, field: &str) -> Result<String, AwsError> {
        let pattern = format!("\"{}\": \"", field);
        let start = json.find(&pattern).ok_or_else(|| {
            AwsError::Authentication(format!("Field '{}' not found in JSON", field))
        })?;

        let value_start = start + pattern.len();
        let value_end = json[value_start..].find('"').ok_or_else(|| {
            AwsError::Authentication(format!("Malformed JSON for field '{}'", field))
        })? + value_start;

        Ok(json[value_start..value_end].to_string())
    }
}

// ============================================================================
// AWS SQS Provider
// ============================================================================

/// AWS SQS queue provider implementation
///
/// This provider implements the QueueProvider trait using AWS SQS.
/// It supports:
/// - Multiple authentication methods via AWS credential chain
/// - Standard queues for high throughput
/// - FIFO queues for ordered message processing
/// - Session emulation via FIFO message groups
/// - Queue URL caching for performance
/// - Dead letter queue integration
///
/// ## Thread Safety
///
/// The provider is thread-safe and can be shared across async tasks using `Arc`.
/// Internal state (queue URL cache) is protected by `RwLock`.
pub struct AwsSqsProvider {
    http_client: HttpClient,
    credential_provider: AwsCredentialProvider,
    config: AwsSqsConfig,
    endpoint: String,
    queue_url_cache: Arc<RwLock<HashMap<QueueName, String>>>,
}

impl AwsSqsProvider {
    /// Create new AWS SQS provider
    ///
    /// # Arguments
    ///
    /// * `config` - AWS SQS configuration with region and authentication details
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Configuration is invalid
    /// - Authentication fails
    /// - AWS SDK initialization fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// use queue_runtime::providers::AwsSqsProvider;
    /// use queue_runtime::AwsSqsConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = AwsSqsConfig {
    ///     region: "us-east-1".to_string(),
    ///     access_key_id: None,
    ///     secret_access_key: None,
    ///     use_fifo_queues: false,
    /// };
    ///
    /// let provider = AwsSqsProvider::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: AwsSqsConfig) -> Result<Self, AwsError> {
        // Validate configuration
        if config.region.is_empty() {
            return Err(AwsError::ConfigurationError(
                "Region cannot be empty".to_string(),
            ));
        }

        // Build endpoint URL
        let endpoint = format!("https://sqs.{}.amazonaws.com", config.region);

        // Create HTTP client with timeout
        let http_client = HttpClient::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| AwsError::NetworkError(format!("Failed to create HTTP client: {}", e)))?;

        // Create credential provider
        let credential_provider = AwsCredentialProvider::new(
            http_client.clone(),
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
        );

        Ok(Self {
            http_client,
            credential_provider,
            config,
            endpoint,
            queue_url_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Get queue URL for a queue name, with caching
    ///
    /// # Arguments
    ///
    /// * `queue_name` - The queue name to resolve
    ///
    /// # Errors
    ///
    /// Returns error if queue does not exist
    async fn get_queue_url(&self, queue_name: &QueueName) -> Result<String, AwsError> {
        // Check cache first
        {
            let cache = self.queue_url_cache.read().await;
            if let Some(url) = cache.get(queue_name) {
                return Ok(url.clone());
            }
        }

        // Build request parameters
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "GetQueueUrl".to_string());
        params.insert("QueueName".to_string(), queue_name.as_str().to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());

        // Make HTTP request
        let response = self.make_request("POST", "/", &params, "").await?;

        // Parse XML response
        let queue_url = self.parse_queue_url_response(&response)?;

        // Cache the URL
        let mut cache = self.queue_url_cache.write().await;
        cache.insert(queue_name.clone(), queue_url.clone());

        Ok(queue_url)
    }

    /// Make an HTTP request to AWS SQS with signature
    async fn make_request(
        &self,
        method: &str,
        path: &str,
        query_params: &HashMap<String, String>,
        body: &str,
    ) -> Result<String, AwsError> {
        // Get current credentials
        let credentials = self.credential_provider.get_credentials().await?;

        // Create signer with current credentials
        let signer = AwsV4Signer::new(
            credentials.access_key_id.clone(),
            credentials.secret_access_key.clone(),
            self.config.region.clone(),
        );

        // Parse host from endpoint
        let host = self
            .endpoint
            .strip_prefix("https://")
            .unwrap_or(&self.endpoint);

        // Get current timestamp
        let timestamp = Utc::now();

        // Sign request
        let mut auth_headers =
            signer.sign_request(method, host, path, query_params, body, &timestamp);

        // Add session token header if present (for temporary credentials)
        if let Some(session_token) = &credentials.session_token {
            auth_headers.insert("X-Amz-Security-Token".to_string(), session_token.clone());
        }

        // Build URL with query parameters
        let mut url = format!("{}{}", self.endpoint, path);
        if !query_params.is_empty() {
            let query_string = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            url = format!("{}?{}", url, query_string);
        }

        // Build HTTP request
        let mut request = self.http_client.request(
            method
                .parse()
                .map_err(|e| AwsError::ConfigurationError(format!("Invalid HTTP method: {}", e)))?,
            &url,
        );

        // Add auth headers
        for (key, value) in auth_headers {
            request = request.header(&key, value);
        }

        // Add body if present
        if !body.is_empty() {
            request = request.body(body.to_string());
        }

        // Send request
        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                AwsError::NetworkError(format!("Request timeout: {}", e))
            } else if e.is_connect() {
                AwsError::NetworkError(format!("Connection failed: {}", e))
            } else {
                AwsError::NetworkError(format!("HTTP request failed: {}", e))
            }
        })?;

        // Check status code
        let status = response.status();
        let response_body = response
            .text()
            .await
            .map_err(|e| AwsError::NetworkError(format!("Failed to read response body: {}", e)))?;

        if !status.is_success() {
            // Parse error from XML response
            return Err(self.parse_error_response(&response_body, status.as_u16()));
        }

        Ok(response_body)
    }

    /// Parse GetQueueUrl XML response
    fn parse_queue_url_response(&self, xml: &str) -> Result<String, AwsError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut in_queue_url = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"QueueUrl" => {
                    in_queue_url = true;
                }
                Ok(Event::Text(e)) if in_queue_url => {
                    return e.unescape().map(|s| s.into_owned()).map_err(|e| {
                        AwsError::SerializationError(format!("Failed to parse XML: {}", e))
                    });
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AwsError::SerializationError(format!(
                        "XML parsing error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Err(AwsError::SerializationError(
            "QueueUrl not found in response".to_string(),
        ))
    }

    /// Parse error response from XML
    fn parse_error_response(&self, xml: &str, status_code: u16) -> AwsError {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut error_code = None;
        let mut error_message = None;
        let mut in_error = false;
        let mut in_code = false;
        let mut in_message = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"Error" => in_error = true,
                    b"Code" if in_error => in_code = true,
                    b"Message" if in_error => in_message = true,
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if in_code {
                        error_code = e.unescape().ok().map(|s| s.into_owned());
                        in_code = false;
                    } else if in_message {
                        error_message = e.unescape().ok().map(|s| s.into_owned());
                        in_message = false;
                    }
                }
                Ok(Event::End(ref e)) if e.name().as_ref() == b"Error" => {
                    in_error = false;
                }
                Ok(Event::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
        }

        let code = error_code.unwrap_or_else(|| "Unknown".to_string());
        let message = error_message.unwrap_or_else(|| "Unknown error".to_string());

        // Map AWS error codes to our error types
        match code.as_str() {
            "AWS.SimpleQueueService.NonExistentQueue" | "QueueDoesNotExist" => {
                AwsError::QueueNotFound(message)
            }
            "InvalidClientTokenId" | "UnrecognizedClientException" | "SignatureDoesNotMatch" => {
                AwsError::Authentication(format!("{}: {}", code, message))
            }
            "InvalidReceiptHandle" | "ReceiptHandleIsInvalid" => AwsError::InvalidReceipt(message),
            _ if status_code == 401 || status_code == 403 => {
                AwsError::Authentication(format!("{}: {}", code, message))
            }
            _ if status_code >= 500 => AwsError::ServiceError(format!("{}: {}", code, message)),
            _ => AwsError::ServiceError(format!("{}: {}", code, message)),
        }
    }

    /// Parse SendMessage XML response
    fn parse_send_message_response(&self, xml: &str) -> Result<MessageId, AwsError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut in_message_id = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) if e.name().as_ref() == b"MessageId" => {
                    in_message_id = true;
                }
                Ok(Event::Text(e)) if in_message_id => {
                    let msg_id = e.unescape().map(|s| s.into_owned()).map_err(|e| {
                        AwsError::SerializationError(format!("Failed to parse XML: {}", e))
                    })?;

                    // Parse the message ID string
                    use std::str::FromStr;
                    let message_id =
                        MessageId::from_str(&msg_id).unwrap_or_else(|_| MessageId::new());
                    return Ok(message_id);
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AwsError::SerializationError(format!(
                        "XML parsing error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Err(AwsError::SerializationError(
            "MessageId not found in response".to_string(),
        ))
    }

    /// Parse ReceiveMessage XML response
    fn parse_receive_message_response(
        &self,
        xml: &str,
        queue: &QueueName,
    ) -> Result<Vec<ReceivedMessage>, AwsError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut messages = Vec::new();
        let mut in_message = false;
        let mut current_message_id: Option<String> = None;
        let mut current_receipt_handle: Option<String> = None;
        let mut current_body: Option<String> = None;
        let mut current_session_id: Option<String> = None;
        let mut current_delivery_count: u32 = 1;

        let mut in_message_id = false;
        let mut in_receipt_handle = false;
        let mut in_body = false;
        let mut in_attribute_name = false;
        let mut in_attribute_value = false;
        let mut current_attribute_name: Option<String> = None;

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"Message" => {
                        in_message = true;
                        // Reset current message fields
                        current_message_id = None;
                        current_receipt_handle = None;
                        current_body = None;
                        current_session_id = None;
                        current_delivery_count = 1;
                    }
                    b"MessageId" if in_message => in_message_id = true,
                    b"ReceiptHandle" if in_message => in_receipt_handle = true,
                    b"Body" if in_message => in_body = true,
                    b"Name" if in_message => in_attribute_name = true,
                    b"Value" if in_message => in_attribute_value = true,
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    let text = e.unescape().ok().map(|s| s.into_owned());
                    if in_message_id {
                        current_message_id = text;
                        in_message_id = false;
                    } else if in_receipt_handle {
                        current_receipt_handle = text;
                        in_receipt_handle = false;
                    } else if in_body {
                        current_body = text;
                        in_body = false;
                    } else if in_attribute_name {
                        current_attribute_name = text;
                        in_attribute_name = false;
                    } else if in_attribute_value {
                        if let Some(ref attr_name) = current_attribute_name {
                            match attr_name.as_str() {
                                "MessageGroupId" => current_session_id = text,
                                "ApproximateReceiveCount" => {
                                    if let Some(count_str) = text {
                                        current_delivery_count = count_str.parse().unwrap_or(1);
                                    }
                                }
                                _ => {}
                            }
                        }
                        in_attribute_value = false;
                        current_attribute_name = None;
                    }
                }
                Ok(Event::End(ref e)) if e.name().as_ref() == b"Message" => {
                    in_message = false;

                    // Build ReceivedMessage if we have required fields
                    if let (Some(body_base64), Some(receipt_handle)) =
                        (current_body.as_ref(), current_receipt_handle.as_ref())
                    {
                        // Decode base64 body
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        let body_bytes = STANDARD.decode(body_base64).map_err(|e| {
                            AwsError::SerializationError(format!("Base64 decode failed: {}", e))
                        })?;
                        let body = bytes::Bytes::from(body_bytes);

                        // Parse message ID
                        use std::str::FromStr;
                        let message_id = current_message_id
                            .as_ref()
                            .and_then(|id| MessageId::from_str(id).ok())
                            .unwrap_or_else(MessageId::new);

                        // Parse session ID
                        let session_id = current_session_id
                            .as_ref()
                            .and_then(|id| SessionId::new(id.clone()).ok());

                        // Create receipt handle with queue name encoded
                        // Format: "{queue_name}|{receipt_token}"
                        let handle_with_queue = format!("{}|{}", queue.as_str(), receipt_handle);
                        let expires_at = Timestamp::now();
                        let receipt =
                            ReceiptHandle::new(handle_with_queue, expires_at, ProviderType::AwsSqs);

                        // Create received message
                        let received_message = ReceivedMessage {
                            message_id,
                            body,
                            attributes: HashMap::new(),
                            session_id,
                            correlation_id: None,
                            receipt_handle: receipt,
                            delivery_count: current_delivery_count,
                            first_delivered_at: Timestamp::now(),
                            delivered_at: Timestamp::now(),
                        };

                        messages.push(received_message);
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AwsError::SerializationError(format!(
                        "XML parsing error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(messages)
    }

    /// Check if a queue is a FIFO queue
    fn is_fifo_queue(queue_name: &QueueName) -> bool {
        queue_name.as_str().ends_with(".fifo")
    }
}

impl fmt::Debug for AwsSqsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSqsProvider")
            .field("config", &self.config)
            .field("queue_url_cache_size", &"<redacted>")
            .finish()
    }
}

#[async_trait]
impl QueueProvider for AwsSqsProvider {
    async fn send_message(
        &self,
        queue: &QueueName,
        message: &Message,
    ) -> Result<MessageId, QueueError> {
        let queue_url = self
            .get_queue_url(queue)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Encode message body to base64 for AWS SQS
        use base64::{engine::general_purpose::STANDARD, Engine};
        let body_base64 = STANDARD.encode(&message.body);

        // Check message size (AWS SQS limit: 256KB)
        if body_base64.len() > 256 * 1024 {
            return Err(AwsError::MessageTooLarge {
                size: body_base64.len(),
                max_size: 256 * 1024,
            }
            .to_queue_error());
        }

        // Build request parameters
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "SendMessage".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url.clone());
        params.insert("MessageBody".to_string(), body_base64);

        // Add FIFO queue parameters if applicable
        if Self::is_fifo_queue(queue) {
            if let Some(ref session_id) = message.session_id {
                params.insert(
                    "MessageGroupId".to_string(),
                    session_id.as_str().to_string(),
                );
                // Use UUID for deduplication ID
                let dedup_id = uuid::Uuid::new_v4().to_string();
                params.insert("MessageDeduplicationId".to_string(), dedup_id);
            } else {
                // FIFO queues require message group ID
                return Err(QueueError::ValidationError(
                    crate::error::ValidationError::Required {
                        field: "session_id".to_string(),
                    },
                ));
            }
        }

        // Make HTTP request
        let response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // Parse XML response
        let message_id = self
            .parse_send_message_response(&response)
            .map_err(|e| e.to_queue_error())?;

        Ok(message_id)
    }

    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: &[Message],
    ) -> Result<Vec<MessageId>, QueueError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        // AWS SQS supports up to 10 messages per batch
        let max_batch = self.max_batch_size() as usize;
        let mut all_message_ids = Vec::new();

        // Process messages in chunks of 10
        for chunk in messages.chunks(max_batch) {
            let message_ids = self.send_messages_batch(queue, chunk).await?;
            all_message_ids.extend(message_ids);
        }

        Ok(all_message_ids)
    }

    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        let messages = self.receive_messages(queue, 1, timeout).await?;
        Ok(messages.into_iter().next())
    }

    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError> {
        let queue_url = self
            .get_queue_url(queue)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Convert timeout to seconds (AWS uses seconds for wait time)
        let wait_time_seconds = timeout.num_seconds().clamp(0, 20); // AWS max is 20 seconds

        // Build request parameters
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "ReceiveMessage".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert(
            "MaxNumberOfMessages".to_string(),
            max_messages.min(10).to_string(), // AWS max is 10
        );
        params.insert("WaitTimeSeconds".to_string(), wait_time_seconds.to_string());
        params.insert("AttributeName.1".to_string(), "All".to_string()); // Request all attributes

        // Make HTTP request
        let response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // Parse XML response
        let messages = self
            .parse_receive_message_response(&response, queue)
            .map_err(|e| e.to_queue_error())?;

        Ok(messages)
    }

    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Extract queue name from receipt handle (stored in provider type)
        // For AWS, we need to parse the queue URL from the receipt handle's extra data
        // Since we don't store that, we need to get the queue URL from the message
        // Actually, receipt handle in AWS is just the opaque token, so we need a different approach

        // Parse receipt handle to extract queue name and token
        // Format: "{queue_name}|{receipt_token}"
        let handle_str = receipt.handle();
        let parts: Vec<&str> = handle_str.split('|').collect();

        if parts.len() != 2 {
            return Err(QueueError::MessageNotFound {
                receipt: handle_str.to_string(),
            });
        }

        let queue_name =
            QueueName::new(parts[0].to_string()).map_err(|e| QueueError::ValidationError(e))?;
        let receipt_token = parts[1];

        // Get queue URL
        let queue_url = self
            .get_queue_url(&queue_name)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Build request parameters for DeleteMessage
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "DeleteMessage".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert("ReceiptHandle".to_string(), receipt_token.to_string());

        // Make HTTP request
        let _response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // DeleteMessage returns empty response on success
        Ok(())
    }

    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Parse receipt handle to extract queue name and token
        let handle_str = receipt.handle();
        let parts: Vec<&str> = handle_str.split('|').collect();

        if parts.len() != 2 {
            return Err(QueueError::MessageNotFound {
                receipt: handle_str.to_string(),
            });
        }

        let queue_name =
            QueueName::new(parts[0].to_string()).map_err(|e| QueueError::ValidationError(e))?;
        let receipt_token = parts[1];

        // Get queue URL
        let queue_url = self
            .get_queue_url(&queue_name)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Build request parameters for ChangeMessageVisibility
        // Setting visibility timeout to 0 makes the message immediately available
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "ChangeMessageVisibility".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert("ReceiptHandle".to_string(), receipt_token.to_string());
        params.insert("VisibilityTimeout".to_string(), "0".to_string());

        // Make HTTP request
        let _response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // ChangeMessageVisibility returns empty response on success
        Ok(())
    }

    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        _reason: &str,
    ) -> Result<(), QueueError> {
        // For AWS SQS, dead letter routing is automatic based on receive count
        // We delete the message, and AWS will route to DLQ if configured and max receives exceeded
        self.complete_message(receipt).await
    }

    async fn create_session_client(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionProvider>, QueueError> {
        // Check if queue supports sessions (FIFO only)
        if !Self::is_fifo_queue(queue) {
            return Err(AwsError::SessionsNotSupported.to_queue_error());
        }

        // Get queue URL
        let queue_url = self
            .get_queue_url(queue)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Session ID is required for FIFO queues
        let session_id = session_id.ok_or_else(|| {
            QueueError::ValidationError(crate::error::ValidationError::Required {
                field: "session_id".to_string(),
            })
        })?;

        Ok(Box::new(AwsSessionProvider::new(
            self.http_client.clone(),
            AwsCredentialProvider::new(
                self.http_client.clone(),
                self.config.access_key_id.clone(),
                self.config.secret_access_key.clone(),
            ),
            self.config.region.clone(),
            self.endpoint.clone(),
            queue_url,
            queue.clone(),
            session_id,
        )))
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::AwsSqs
    }

    fn supports_sessions(&self) -> SessionSupport {
        SessionSupport::Emulated
    }

    fn supports_batching(&self) -> bool {
        true
    }

    fn max_batch_size(&self) -> u32 {
        10 // AWS SQS max batch size
    }
}

// Private helper methods
impl AwsSqsProvider {
    /// Send a batch of up to 10 messages
    async fn send_messages_batch(
        &self,
        queue: &QueueName,
        messages: &[Message],
    ) -> Result<Vec<MessageId>, QueueError> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        // AWS SQS max batch size is 10
        if messages.len() > 10 {
            return Err(QueueError::ValidationError(
                crate::error::ValidationError::OutOfRange {
                    field: "messages".to_string(),
                    message: format!("Batch size {} exceeds AWS SQS limit of 10", messages.len()),
                },
            ));
        }

        let queue_url = self
            .get_queue_url(queue)
            .await
            .map_err(|e| e.to_queue_error())?;

        // Build request parameters for SendMessageBatch
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "SendMessageBatch".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url.clone());

        // Encode each message body to base64
        use base64::{engine::general_purpose::STANDARD, Engine};

        // Add each message to batch with index-based parameters
        for (idx, message) in messages.iter().enumerate() {
            let entry_id = format!("msg-{}", idx);
            let body_base64 = STANDARD.encode(&message.body);

            // Check message size (AWS SQS limit: 256KB per message)
            if body_base64.len() > 256 * 1024 {
                return Err(AwsError::MessageTooLarge {
                    size: body_base64.len(),
                    max_size: 256 * 1024,
                }
                .to_queue_error());
            }

            params.insert(
                format!("SendMessageBatchRequestEntry.{}.Id", idx + 1),
                entry_id,
            );
            params.insert(
                format!("SendMessageBatchRequestEntry.{}.MessageBody", idx + 1),
                body_base64,
            );

            // Add FIFO parameters if this is a FIFO queue
            if Self::is_fifo_queue(queue) {
                // Use session_id as MessageGroupId if available
                if let Some(ref session_id) = message.session_id {
                    params.insert(
                        format!("SendMessageBatchRequestEntry.{}.MessageGroupId", idx + 1),
                        session_id.as_str().to_string(),
                    );
                }

                // Generate MessageDeduplicationId from message content hash
                // This ensures idempotency for FIFO queues
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&message.body);
                if let Some(ref session_id) = message.session_id {
                    hasher.update(session_id.as_str().as_bytes());
                }
                let hash = format!("{:x}", hasher.finalize());
                params.insert(
                    format!(
                        "SendMessageBatchRequestEntry.{}.MessageDeduplicationId",
                        idx + 1
                    ),
                    hash,
                );
            }
        }

        // Make HTTP request
        let response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // Parse XML response
        self.parse_send_message_batch_response(&response)
            .map_err(|e| e.to_queue_error())
    }

    /// Parse SendMessageBatch XML response
    fn parse_send_message_batch_response(&self, xml: &str) -> Result<Vec<MessageId>, AwsError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut message_ids = Vec::new();
        let mut in_successful = false;
        let mut in_message_id = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"SendMessageBatchResultEntry" => in_successful = true,
                    b"MessageId" if in_successful => in_message_id = true,
                    _ => {}
                },
                Ok(Event::Text(e)) if in_message_id => {
                    let msg_id = e.unescape().map(|s| s.into_owned()).map_err(|e| {
                        AwsError::SerializationError(format!("Failed to parse XML: {}", e))
                    })?;

                    // Parse the message ID string
                    use std::str::FromStr;
                    let message_id =
                        MessageId::from_str(&msg_id).unwrap_or_else(|_| MessageId::new());
                    message_ids.push(message_id);
                    in_message_id = false;
                }
                Ok(Event::End(ref e)) if e.name().as_ref() == b"SendMessageBatchResultEntry" => {
                    in_successful = false;
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AwsError::SerializationError(format!(
                        "XML parsing error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(message_ids)
    }
}

// ============================================================================
// AWS Session Provider
// ============================================================================

/// AWS SQS session provider for ordered message processing via FIFO queues
///
/// This provider implements session-based operations using FIFO queue message groups.
/// The SessionId is mapped to MessageGroupId to ensure ordering within the session.
pub struct AwsSessionProvider {
    http_client: HttpClient,
    credential_provider: AwsCredentialProvider,
    region: String,
    endpoint: String,
    queue_url: String,
    queue_name: QueueName,
    session_id: SessionId,
}

impl AwsSessionProvider {
    /// Create new AWS session provider
    fn new(
        http_client: HttpClient,
        credential_provider: AwsCredentialProvider,
        region: String,
        endpoint: String,
        queue_url: String,
        queue_name: QueueName,
        session_id: SessionId,
    ) -> Self {
        Self {
            http_client,
            credential_provider,
            region,
            endpoint,
            queue_url,
            queue_name,
            session_id,
        }
    }

    /// Get the cached queue URL
    async fn get_queue_url(&self) -> Result<String, AwsError> {
        Ok(self.queue_url.clone())
    }

    /// Make an HTTP request to AWS SQS
    async fn make_request(
        &self,
        method: &str,
        path: &str,
        params: &HashMap<String, String>,
        body: &str,
    ) -> Result<String, AwsError> {
        use reqwest::header;

        // Get current credentials
        let credentials = self.credential_provider.get_credentials().await?;

        // Create signer with current credentials
        let signer = AwsV4Signer::new(
            credentials.access_key_id.clone(),
            credentials.secret_access_key.clone(),
            self.region.clone(),
        );

        // Build query string from parameters
        let query_string = if params.is_empty() {
            String::new()
        } else {
            let mut pairs: Vec<String> = params
                .iter()
                .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
                .collect();
            pairs.sort();
            pairs.join("&")
        };

        let url = if query_string.is_empty() {
            format!("{}{}", self.endpoint, path)
        } else {
            format!("{}{}?{}", self.endpoint, path, query_string)
        };

        // Build request
        let mut request_builder = self.http_client.request(
            method
                .parse()
                .map_err(|e| AwsError::NetworkError(format!("Invalid HTTP method: {}", e)))?,
            &url,
        );

        // Add signature
        let timestamp = Utc::now();
        let host = self
            .endpoint
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let mut signed_headers = signer.sign_request(method, host, path, params, body, &timestamp);

        // Add session token header if present (for temporary credentials)
        if let Some(session_token) = &credentials.session_token {
            signed_headers.insert("X-Amz-Security-Token".to_string(), session_token.clone());
        }

        for (key, value) in signed_headers {
            request_builder = request_builder.header(key, value);
        }

        // Add body if present
        if !body.is_empty() {
            request_builder = request_builder
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(body.to_string());
        }

        // Send request
        let response = request_builder
            .send()
            .await
            .map_err(|e| AwsError::NetworkError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();
        let response_text = response
            .text()
            .await
            .map_err(|e| AwsError::NetworkError(format!("Failed to read response: {}", e)))?;

        // Check for errors
        if !status.is_success() {
            return Err(self.parse_error_response(&response_text, status.as_u16()));
        }

        Ok(response_text)
    }

    /// Parse error response XML
    fn parse_error_response(&self, xml: &str, status_code: u16) -> AwsError {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut error_code = None;
        let mut error_message = None;
        let mut in_error = false;
        let mut in_code = false;
        let mut in_message = false;
        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"Error" => in_error = true,
                    b"Code" if in_error => in_code = true,
                    b"Message" if in_error => in_message = true,
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    if in_code {
                        error_code = e.unescape().ok().map(|s| s.into_owned());
                        in_code = false;
                    } else if in_message {
                        error_message = e.unescape().ok().map(|s| s.into_owned());
                        in_message = false;
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
        }

        // Map AWS error codes to our error types
        match error_code.as_deref() {
            Some("InvalidParameterValue") | Some("MissingParameter") => AwsError::ServiceError(
                error_message.unwrap_or_else(|| "Invalid parameter".to_string()),
            ),
            Some("AccessDenied") | Some("InvalidClientTokenId") | Some("SignatureDoesNotMatch") => {
                AwsError::Authentication(
                    error_message.unwrap_or_else(|| "Authentication failed".to_string()),
                )
            }
            Some("AWS.SimpleQueueService.NonExistentQueue") | Some("QueueDoesNotExist") => {
                AwsError::QueueNotFound(
                    error_message.unwrap_or_else(|| "Queue not found".to_string()),
                )
            }
            _ => {
                if status_code >= 500 {
                    AwsError::ServiceError(
                        error_message.unwrap_or_else(|| "Service error".to_string()),
                    )
                } else {
                    AwsError::ServiceError(
                        error_message.unwrap_or_else(|| format!("HTTP {}", status_code)),
                    )
                }
            }
        }
    }

    /// Parse ReceiveMessage XML response
    fn parse_receive_message_response(
        &self,
        xml: &str,
        queue: &QueueName,
    ) -> Result<Vec<ReceivedMessage>, AwsError> {
        use quick_xml::events::Event;
        use quick_xml::Reader;

        let mut reader = Reader::from_str(xml);
        reader.trim_text(true);

        let mut messages = Vec::new();
        let mut in_message = false;
        let mut current_message_id: Option<String> = None;
        let mut current_receipt_handle: Option<String> = None;
        let mut current_body: Option<String> = None;
        let mut current_session_id: Option<String> = None;
        let mut current_delivery_count: u32 = 1;

        let mut in_message_id = false;
        let mut in_receipt_handle = false;
        let mut in_body = false;
        let mut in_attribute_name = false;
        let mut in_attribute_value = false;
        let mut current_attribute_name: Option<String> = None;

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(ref e)) => match e.name().as_ref() {
                    b"Message" => {
                        in_message = true;
                        current_message_id = None;
                        current_receipt_handle = None;
                        current_body = None;
                        current_session_id = None;
                        current_delivery_count = 1;
                    }
                    b"MessageId" if in_message => in_message_id = true,
                    b"ReceiptHandle" if in_message => in_receipt_handle = true,
                    b"Body" if in_message => in_body = true,
                    b"Name" if in_message => in_attribute_name = true,
                    b"Value" if in_message => in_attribute_value = true,
                    _ => {}
                },
                Ok(Event::Text(e)) => {
                    let text = e.unescape().ok().map(|s| s.into_owned());
                    if in_message_id {
                        current_message_id = text;
                        in_message_id = false;
                    } else if in_receipt_handle {
                        current_receipt_handle = text;
                        in_receipt_handle = false;
                    } else if in_body {
                        current_body = text;
                        in_body = false;
                    } else if in_attribute_name {
                        current_attribute_name = text;
                        in_attribute_name = false;
                    } else if in_attribute_value {
                        if let Some(ref attr_name) = current_attribute_name {
                            match attr_name.as_str() {
                                "MessageGroupId" => current_session_id = text,
                                "ApproximateReceiveCount" => {
                                    if let Some(count_str) = text {
                                        current_delivery_count = count_str.parse().unwrap_or(1);
                                    }
                                }
                                _ => {}
                            }
                        }
                        in_attribute_value = false;
                        current_attribute_name = None;
                    }
                }
                Ok(Event::End(ref e)) if e.name().as_ref() == b"Message" => {
                    in_message = false;

                    if let (Some(body_base64), Some(receipt_handle)) =
                        (current_body.as_ref(), current_receipt_handle.as_ref())
                    {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        let body_bytes = STANDARD.decode(body_base64).map_err(|e| {
                            AwsError::SerializationError(format!("Base64 decode failed: {}", e))
                        })?;
                        let body = bytes::Bytes::from(body_bytes);

                        use std::str::FromStr;
                        let message_id = current_message_id
                            .as_ref()
                            .and_then(|id| MessageId::from_str(id).ok())
                            .unwrap_or_else(MessageId::new);

                        let session_id = current_session_id
                            .as_ref()
                            .and_then(|id| SessionId::new(id.clone()).ok());

                        let handle_with_queue = format!("{}|{}", queue.as_str(), receipt_handle);
                        let expires_at = Timestamp::now();
                        let receipt =
                            ReceiptHandle::new(handle_with_queue, expires_at, ProviderType::AwsSqs);

                        let received_message = ReceivedMessage {
                            message_id,
                            body,
                            attributes: HashMap::new(),
                            session_id,
                            correlation_id: None,
                            receipt_handle: receipt,
                            delivery_count: current_delivery_count,
                            first_delivered_at: Timestamp::now(),
                            delivered_at: Timestamp::now(),
                        };

                        messages.push(received_message);
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(AwsError::SerializationError(format!(
                        "XML parsing error: {}",
                        e
                    )))
                }
                _ => {}
            }
            buf.clear();
        }

        Ok(messages)
    }
}

impl fmt::Debug for AwsSessionProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSessionProvider")
            .field("queue_name", &self.queue_name)
            .field("session_id", &self.session_id)
            .finish()
    }
}

#[async_trait]
impl SessionProvider for AwsSessionProvider {
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        // For FIFO queues, receive with session filtering
        // AWS SQS handles session ordering via MessageGroupId
        let queue_url = self.get_queue_url().await.map_err(|e| e.to_queue_error())?;

        // Build request parameters for ReceiveMessage with session (MessageGroupId)
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "ReceiveMessage".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert("MaxNumberOfMessages".to_string(), "1".to_string());
        params.insert(
            "WaitTimeSeconds".to_string(),
            timeout.num_seconds().clamp(0, 20).to_string(),
        );
        params.insert("AttributeName.1".to_string(), "All".to_string());

        // Make HTTP request
        let response = self
            .make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        // Parse XML response
        let messages = self
            .parse_receive_message_response(&response, &self.queue_name)
            .map_err(|e| e.to_queue_error())?;

        // Filter by session ID (messages should already have matching session from MessageGroupId)
        Ok(messages
            .into_iter()
            .find(|msg| msg.session_id.as_ref() == Some(&self.session_id)))
    }

    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Parse receipt handle to extract queue name and token
        let handle_str = receipt.handle();
        let parts: Vec<&str> = handle_str.split('|').collect();

        if parts.len() != 2 {
            return Err(QueueError::MessageNotFound {
                receipt: handle_str.to_string(),
            });
        }

        let receipt_token = parts[1];
        let queue_url = self.get_queue_url().await.map_err(|e| e.to_queue_error())?;

        // Build request parameters for DeleteMessage
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "DeleteMessage".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert("ReceiptHandle".to_string(), receipt_token.to_string());

        // Make HTTP request
        self.make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        Ok(())
    }

    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Parse receipt handle to extract queue name and token
        let handle_str = receipt.handle();
        let parts: Vec<&str> = handle_str.split('|').collect();

        if parts.len() != 2 {
            return Err(QueueError::MessageNotFound {
                receipt: handle_str.to_string(),
            });
        }

        let receipt_token = parts[1];
        let queue_url = self.get_queue_url().await.map_err(|e| e.to_queue_error())?;

        // Build request parameters for ChangeMessageVisibility
        let mut params = HashMap::new();
        params.insert("Action".to_string(), "ChangeMessageVisibility".to_string());
        params.insert("Version".to_string(), "2012-11-05".to_string());
        params.insert("QueueUrl".to_string(), queue_url);
        params.insert("ReceiptHandle".to_string(), receipt_token.to_string());
        params.insert("VisibilityTimeout".to_string(), "0".to_string());

        // Make HTTP request
        self.make_request("POST", "/", &params, "")
            .await
            .map_err(|e| e.to_queue_error())?;

        Ok(())
    }

    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        _reason: &str,
    ) -> Result<(), QueueError> {
        // Delete the message - AWS will route to DLQ if configured
        self.complete_message(receipt).await
    }

    async fn renew_session_lock(&self) -> Result<(), QueueError> {
        // AWS SQS FIFO queues do not have explicit session locks
        Ok(())
    }

    async fn close_session(&self) -> Result<(), QueueError> {
        // AWS SQS FIFO queues do not require explicit session termination
        Ok(())
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn session_expires_at(&self) -> Timestamp {
        // AWS SQS FIFO queues do not have explicit session expiry times
        Timestamp::from_datetime(chrono::Utc::now() + chrono::Duration::days(365))
    }
}
