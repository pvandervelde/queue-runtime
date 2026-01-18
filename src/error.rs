//! Error types for queue operations.

use crate::message::Timestamp;
use chrono::Duration;
use thiserror::Error;

/// Comprehensive error type for all queue operations
#[derive(Debug, Error)]
pub enum QueueError {
    #[error("Queue not found: {queue_name}")]
    QueueNotFound { queue_name: String },

    #[error("Message not found or receipt expired: {receipt}")]
    MessageNotFound { receipt: String },

    #[error("Session '{session_id}' is locked until {locked_until}")]
    SessionLocked {
        session_id: String,
        locked_until: Timestamp,
    },

    #[error("Session '{session_id}' not found or expired")]
    SessionNotFound { session_id: String },

    #[error("Operation timed out after {duration:?}")]
    Timeout { duration: Duration },

    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Authentication failed: {message}")]
    AuthenticationFailed { message: String },

    #[error("Permission denied for operation: {operation}")]
    PermissionDenied { operation: String },

    #[error("Message too large: {size} bytes (max: {max_size})")]
    MessageTooLarge { size: usize, max_size: usize },

    #[error("Batch size {size} exceeds maximum {max_size}")]
    BatchTooLarge { size: usize, max_size: usize },

    #[error("Provider error ({provider}): {code} - {message}")]
    ProviderError {
        provider: String,
        code: String,
        message: String,
    },

    #[error("Serialization failed: {0}")]
    SerializationError(#[from] SerializationError),

    #[error("Configuration error: {0}")]
    ConfigurationError(#[from] ConfigurationError),

    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),
}

impl QueueError {
    /// Check if error is transient and should be retried
    pub fn is_transient(&self) -> bool {
        match self {
            Self::QueueNotFound { .. } => false,
            Self::MessageNotFound { .. } => false,
            Self::SessionLocked { .. } => true,
            Self::SessionNotFound { .. } => false,
            Self::Timeout { .. } => true,
            Self::ConnectionFailed { .. } => true,
            Self::AuthenticationFailed { .. } => false,
            Self::PermissionDenied { .. } => false,
            Self::MessageTooLarge { .. } => false,
            Self::BatchTooLarge { .. } => false,
            Self::ProviderError { .. } => true, // Provider-specific errors are usually transient
            Self::SerializationError(_) => false,
            Self::ConfigurationError(_) => false,
            Self::ValidationError(_) => false,
        }
    }

    /// Check if error should be retried
    pub fn should_retry(&self) -> bool {
        self.is_transient()
    }

    /// Get suggested retry delay
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::SessionLocked { .. } => Some(Duration::seconds(5)),
            Self::Timeout { .. } => Some(Duration::seconds(1)),
            Self::ConnectionFailed { .. } => Some(Duration::seconds(5)),
            _ => None,
        }
    }
}

/// Errors during message serialization/deserialization
#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("JSON serialization failed: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Message body is not valid UTF-8")]
    InvalidUtf8,

    #[error("Message attribute '{key}' has invalid value")]
    InvalidAttribute { key: String },

    #[error("Message exceeds size limit: {size} bytes")]
    MessageTooLarge { size: usize },
}

/// Configuration errors
#[derive(Debug, Error)]
pub enum ConfigurationError {
    #[error("Invalid configuration: {message}")]
    Invalid { message: String },

    #[error("Missing required configuration: {key}")]
    Missing { key: String },

    #[error("Configuration parsing failed: {message}")]
    Parsing { message: String },

    #[error("Unsupported provider: {provider} - {message}")]
    UnsupportedProvider { provider: String, message: String },
}

/// Validation errors
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Required field missing: {field}")]
    Required { field: String },

    #[error("Invalid format for {field}: {message}")]
    InvalidFormat { field: String, message: String },

    #[error("Value out of range for {field}: {message}")]
    OutOfRange { field: String, message: String },
}

#[cfg(test)]
#[path = "error_tests.rs"]
mod tests;
