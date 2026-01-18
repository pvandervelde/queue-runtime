//! Provider types and configuration.

use chrono::Duration;
use serde::{Deserialize, Serialize};

/// Enumeration of supported queue providers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderType {
    AzureServiceBus,
    AwsSqs,
    InMemory,
}

impl ProviderType {
    /// Get session support level for provider
    pub fn supports_sessions(&self) -> SessionSupport {
        match self {
            Self::AzureServiceBus => SessionSupport::Native,
            Self::AwsSqs => SessionSupport::Emulated, // Via FIFO queues
            Self::InMemory => SessionSupport::Native,
        }
    }

    /// Check if provider supports batch operations
    pub fn supports_batching(&self) -> bool {
        match self {
            Self::AzureServiceBus => true,
            Self::AwsSqs => true,
            Self::InMemory => true,
        }
    }

    /// Get maximum message size for provider
    pub fn max_message_size(&self) -> usize {
        match self {
            Self::AzureServiceBus => 1024 * 1024, // 1MB
            Self::AwsSqs => 256 * 1024,           // 256KB
            Self::InMemory => 10 * 1024 * 1024,   // 10MB
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

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;
