//! Provider types and configuration.

use chrono::Duration;
use serde::{Deserialize, Serialize};

/// Enumeration of supported queue providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderType {
    AzureServiceBus,
    AwsSqs,
    InMemory,
    /// RabbitMQ via AMQP 0-9-1
    RabbitMq,
    /// NATS with JetStream
    Nats,
}

impl ProviderType {
    /// Get session support level for provider
    pub fn supports_sessions(&self) -> SessionSupport {
        match self {
            Self::AzureServiceBus => SessionSupport::Native,
            Self::AwsSqs => SessionSupport::Emulated, // Via FIFO queues
            Self::InMemory => SessionSupport::Native,
            Self::RabbitMq => SessionSupport::Emulated, // Via routing keys and in-memory tracking
            Self::Nats => SessionSupport::Emulated, // Via JetStream consumer filter subjects
        }
    }

    /// Check if provider supports batch operations
    pub fn supports_batching(&self) -> bool {
        match self {
            Self::AzureServiceBus => true,
            Self::AwsSqs => true,
            Self::InMemory => true,
            Self::RabbitMq => true,
            Self::Nats => true,
        }
    }

    /// Get maximum message size for provider
    pub fn max_message_size(&self) -> usize {
        match self {
            Self::AzureServiceBus => 1024 * 1024,   // 1MB
            Self::AwsSqs => 256 * 1024,              // 256KB
            Self::InMemory => 10 * 1024 * 1024,      // 10MB
            Self::RabbitMq => 128 * 1024 * 1024,     // 128MB (configurable, practical limit)
            Self::Nats => 1024 * 1024,               // 1MB (default JetStream max)
        }
    }
}

/// Level of session support provided by different providers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSupport {
    /// Provider has built-in session support (Azure Service Bus)
    Native,
    /// Provider emulates sessions via other mechanisms (AWS SQS FIFO)
    Emulated,
    /// Provider cannot support session ordering
    Unsupported,
}

/// Configuration for queue client initialization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub provider: ProviderConfig,
    pub default_timeout: Duration,
    pub max_retry_attempts: u32,
    pub retry_base_delay: Duration,
    pub enable_dead_letter: bool,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            provider: ProviderConfig::InMemory(InMemoryConfig::default()),
            default_timeout: Duration::seconds(30),
            max_retry_attempts: 3,
            retry_base_delay: Duration::seconds(1),
            enable_dead_letter: true,
        }
    }
}

/// Provider-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderConfig {
    AzureServiceBus(AzureServiceBusConfig),
    AwsSqs(AwsSqsConfig),
    InMemory(InMemoryConfig),
    /// RabbitMQ via AMQP 0-9-1
    RabbitMq(RabbitMqConfig),
    /// NATS with JetStream
    Nats(NatsConfig),
}

/// Azure Service Bus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureServiceBusConfig {
    pub connection_string: Option<String>,
    pub namespace: Option<String>,
    #[serde(skip, default = "default_auth_method")]
    pub auth_method: crate::providers::AzureAuthMethod,
    pub use_sessions: bool,
    pub session_timeout: Duration,
}

fn default_auth_method() -> crate::providers::AzureAuthMethod {
    crate::providers::AzureAuthMethod::DefaultCredential
}

/// AWS SQS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsSqsConfig {
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub use_fifo_queues: bool,
}

/// In-memory provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryConfig {
    pub max_queue_size: usize,
    pub enable_persistence: bool,
    pub max_delivery_count: u32,
    pub default_message_ttl: Option<Duration>,
    pub enable_dead_letter_queue: bool,
    pub session_lock_duration: Duration,
}

impl Default for InMemoryConfig {
    fn default() -> Self {
        Self {
            max_queue_size: 10000,
            enable_persistence: false,
            max_delivery_count: 3,
            default_message_ttl: None,
            enable_dead_letter_queue: true,
            session_lock_duration: Duration::minutes(5),
        }
    }
}

/// RabbitMQ provider configuration using AMQP 0-9-1
///
/// # Examples
///
/// ```rust
/// use queue_runtime::RabbitMqConfig;
/// use chrono::Duration;
///
/// let config = RabbitMqConfig {
///     url: "amqp://guest:guest@localhost:5672".to_string(),
///     virtual_host: "/".to_string(),
///     prefetch_count: 10,
///     session_lock_duration: Duration::minutes(5),
///     message_ttl: None,
///     enable_dead_letter: true,
///     dead_letter_exchange: Some("dlx".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RabbitMqConfig {
    /// AMQP connection URL (e.g. `amqp://user:pass@host:port/vhost`)
    pub url: String,
    /// RabbitMQ virtual host (defaults to `/`)
    pub virtual_host: String,
    /// Number of messages to prefetch per channel (0 = unlimited)
    pub prefetch_count: u16,
    /// Duration to hold a session lock before expiry
    pub session_lock_duration: Duration,
    /// Default message time-to-live
    pub message_ttl: Option<Duration>,
    /// Whether to enable dead letter queue routing
    pub enable_dead_letter: bool,
    /// Name of the dead letter exchange (required when `enable_dead_letter` is true)
    pub dead_letter_exchange: Option<String>,
}

impl Default for RabbitMqConfig {
    fn default() -> Self {
        Self {
            url: "amqp://guest:guest@localhost:5672".to_string(),
            virtual_host: "/".to_string(),
            prefetch_count: 10,
            session_lock_duration: Duration::minutes(5),
            message_ttl: None,
            enable_dead_letter: true,
            dead_letter_exchange: Some("dlx".to_string()),
        }
    }
}

/// NATS provider configuration using JetStream
///
/// # Examples
///
/// ```rust
/// use queue_runtime::NatsConfig;
/// use chrono::Duration;
///
/// let config = NatsConfig {
///     url: "nats://localhost:4222".to_string(),
///     stream_prefix: "queue-runtime".to_string(),
///     max_deliver: Some(3),
///     ack_wait: Duration::seconds(30),
///     session_lock_duration: Duration::minutes(5),
///     enable_dead_letter: true,
///     dead_letter_subject_prefix: Some("dlq".to_string()),
///     credentials_path: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatsConfig {
    /// NATS server URL (e.g. `nats://localhost:4222` or `nats://user:pass@host:port`)
    pub url: String,
    /// Prefix for JetStream stream names (stream name = `{prefix}-{queue_name}`)
    pub stream_prefix: String,
    /// Maximum number of delivery attempts before giving up (None = unlimited)
    pub max_deliver: Option<i64>,
    /// Duration to wait for ack before re-delivering (visibility timeout analog)
    pub ack_wait: Duration,
    /// Duration to hold a session lock before expiry
    pub session_lock_duration: Duration,
    /// Whether to enable dead letter queue routing via a separate stream
    pub enable_dead_letter: bool,
    /// Subject prefix for dead letter messages (`{prefix}.{queue}`)
    pub dead_letter_subject_prefix: Option<String>,
    /// Path to NATS credentials file (`.creds` format)
    pub credentials_path: Option<String>,
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            url: "nats://localhost:4222".to_string(),
            stream_prefix: "queue-runtime".to_string(),
            max_deliver: Some(3),
            ack_wait: Duration::seconds(30),
            session_lock_duration: Duration::minutes(5),
            enable_dead_letter: true,
            dead_letter_subject_prefix: Some("dlq".to_string()),
            credentials_path: None,
        }
    }
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
