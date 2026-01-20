//! Message types for queue operations including core domain identifiers.

use crate::error::ValidationError;
use crate::provider::ProviderType;
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

// ============================================================================
// Core Domain Identifiers
// ============================================================================

/// Validated queue name with length and character restrictions
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueName(String);

impl QueueName {
    /// Create new queue name with validation
    pub fn new(name: String) -> Result<Self, ValidationError> {
        // Validate length
        if name.is_empty() || name.len() > 260 {
            return Err(ValidationError::OutOfRange {
                field: "queue_name".to_string(),
                message: "must be 1-260 characters".to_string(),
            });
        }

        // Validate characters (ASCII alphanumeric, hyphens, underscores)
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(ValidationError::InvalidFormat {
                field: "queue_name".to_string(),
                message: "only ASCII alphanumeric, hyphens, and underscores allowed".to_string(),
            });
        }

        // Validate no consecutive hyphens or leading/trailing hyphens
        if name.starts_with('-') || name.ends_with('-') || name.contains("--") {
            return Err(ValidationError::InvalidFormat {
                field: "queue_name".to_string(),
                message: "no leading/trailing hyphens or consecutive hyphens".to_string(),
            });
        }

        Ok(Self(name))
    }

    /// Create queue name with prefix
    pub fn with_prefix(prefix: &str, base_name: &str) -> Result<Self, ValidationError> {
        let full_name = format!("{}-{}", prefix, base_name);
        Self::new(full_name)
    }

    /// Get queue name as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for QueueName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for QueueName {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

/// Unique identifier for messages within the queue system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(String);

impl MessageId {
    /// Generate new random message ID
    pub fn new() -> Self {
        let id = uuid::Uuid::new_v4();
        Self(id.to_string())
    }

    /// Get message ID as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for MessageId {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ValidationError::Required {
                field: "message_id".to_string(),
            });
        }

        Ok(Self(s.to_string()))
    }
}

/// Identifier for grouping related messages for ordered processing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Create new session ID with validation
    pub fn new(id: String) -> Result<Self, ValidationError> {
        if id.is_empty() {
            return Err(ValidationError::Required {
                field: "session_id".to_string(),
            });
        }

        if id.len() > 128 {
            return Err(ValidationError::OutOfRange {
                field: "session_id".to_string(),
                message: "maximum 128 characters".to_string(),
            });
        }

        // Validate ASCII printable characters only
        if !id.chars().all(|c| c.is_ascii() && !c.is_ascii_control()) {
            return Err(ValidationError::InvalidFormat {
                field: "session_id".to_string(),
                message: "only ASCII printable characters allowed".to_string(),
            });
        }

        Ok(Self(id))
    }

    /// Create session ID from parts (for GitHub events)
    pub fn from_parts(owner: &str, repo: &str, entity_type: &str, entity_id: &str) -> Self {
        let id = format!("{}/{}/{}/{}", owner, repo, entity_type, entity_id);
        // Use unchecked creation since we control the format
        Self(id)
    }

    /// Get session ID as string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for SessionId {
    type Err = ValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

/// Timestamp wrapper for consistent time handling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(DateTime<Utc>);

impl Timestamp {
    /// Create timestamp for current time
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Create timestamp from DateTime
    pub fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    /// Get underlying DateTime
    pub fn as_datetime(&self) -> DateTime<Utc> {
        self.0
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%d %H:%M:%S UTC"))
    }
}

impl FromStr for Timestamp {
    type Err = chrono::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let dt = s.parse::<DateTime<Utc>>()?;
        Ok(Self::from_datetime(dt))
    }
}

// ============================================================================
// Message Types
// ============================================================================

/// A message to be sent through the queue system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(with = "bytes_serde")]
    pub body: Bytes,
    pub attributes: HashMap<String, String>,
    pub session_id: Option<SessionId>,
    pub correlation_id: Option<String>,
    pub time_to_live: Option<Duration>,
}

/// Custom serialization for Bytes
mod bytes_serde {
    use base64::{engine::general_purpose, Engine as _};
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = general_purpose::STANDARD.encode(bytes);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        Ok(Bytes::from(decoded))
    }
}

impl Message {
    /// Create new message with body
    pub fn new(body: Bytes) -> Self {
        Self {
            body,
            attributes: HashMap::new(),
            session_id: None,
            correlation_id: None,
            time_to_live: None,
        }
    }

    /// Add session ID for ordered processing
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Add message attribute
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }

    /// Add correlation ID for tracking
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Add time-to-live for message expiration
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.time_to_live = Some(ttl);
        self
    }
}

/// A message received from the queue with processing metadata
#[derive(Debug, Clone)]
pub struct ReceivedMessage {
    pub message_id: MessageId,
    pub body: Bytes,
    pub attributes: HashMap<String, String>,
    pub session_id: Option<SessionId>,
    pub correlation_id: Option<String>,
    pub receipt_handle: ReceiptHandle,
    pub delivery_count: u32,
    pub first_delivered_at: Timestamp,
    pub delivered_at: Timestamp,
}

impl ReceivedMessage {
    /// Convert back to Message (for forwarding/replaying)
    pub fn message(&self) -> Message {
        Message {
            body: self.body.clone(),
            attributes: self.attributes.clone(),
            session_id: self.session_id.clone(),
            correlation_id: self.correlation_id.clone(),
            time_to_live: None, // TTL is not preserved in received messages
        }
    }

    /// Check if message has exceeded maximum delivery count
    pub fn has_exceeded_max_delivery_count(&self, max_count: u32) -> bool {
        self.delivery_count > max_count
    }
}

/// Opaque token for acknowledging or rejecting received messages
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptHandle {
    handle: String,
    expires_at: Timestamp,
    provider_type: ProviderType,
}

impl ReceiptHandle {
    /// Create new receipt handle
    pub fn new(handle: String, expires_at: Timestamp, provider_type: ProviderType) -> Self {
        Self {
            handle,
            expires_at,
            provider_type,
        }
    }

    /// Get handle string
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// Check if receipt handle is expired
    pub fn is_expired(&self) -> bool {
        Timestamp::now() >= self.expires_at
    }

    /// Get time until expiry
    pub fn time_until_expiry(&self) -> Duration {
        let now = Timestamp::now();
        if now >= self.expires_at {
            Duration::zero()
        } else {
            self.expires_at.as_datetime() - now.as_datetime()
        }
    }

    /// Get provider type
    pub fn provider_type(&self) -> ProviderType {
        self.provider_type
    }
}

// ============================================================================
// Send and Receive Options
// ============================================================================

/// Configuration options for sending messages to queues
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Session ID for ordered processing workflows
    pub session_id: Option<SessionId>,
    /// Correlation ID for request/response and tracing patterns
    pub correlation_id: Option<String>,
    /// Scheduled delivery time for delayed message processing
    pub scheduled_enqueue_time: Option<Timestamp>,
    /// Time-to-live for automatic message expiration
    pub time_to_live: Option<Duration>,
    /// Custom properties for metadata and routing information
    pub properties: HashMap<String, String>,
    /// Content type override for specialized message formats
    pub content_type: Option<String>,
    /// Duplicate detection ID for exactly-once delivery guarantees
    pub duplicate_detection_id: Option<String>,
}

impl SendOptions {
    /// Create new send options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set session ID for ordered processing
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Set correlation ID for tracing
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Set scheduled delivery time
    pub fn with_scheduled_enqueue_time(mut self, time: Timestamp) -> Self {
        self.scheduled_enqueue_time = Some(time);
        self
    }

    /// Set scheduled delivery with a delay from now
    pub fn with_delay(mut self, delay: Duration) -> Self {
        let scheduled_time = Timestamp::from_datetime(Utc::now() + delay);
        self.scheduled_enqueue_time = Some(scheduled_time);
        self
    }

    /// Set time-to-live for message expiration
    pub fn with_time_to_live(mut self, ttl: Duration) -> Self {
        self.time_to_live = Some(ttl);
        self
    }

    /// Add a custom property
    pub fn with_property(mut self, key: String, value: String) -> Self {
        self.properties.insert(key, value);
        self
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Set duplicate detection ID
    pub fn with_duplicate_detection_id(mut self, id: String) -> Self {
        self.duplicate_detection_id = Some(id);
        self
    }
}

/// Configuration options for receiving messages from queues
#[derive(Debug, Clone)]
pub struct ReceiveOptions {
    /// Maximum number of messages to receive in a batch
    pub max_messages: u32,
    /// Timeout duration for receive operations
    pub timeout: Duration,
    /// Session ID for session-specific message consumption
    pub session_id: Option<SessionId>,
    /// Whether to accept any available session
    pub accept_any_session: bool,
    /// Message lock duration for processing time management
    pub lock_duration: Option<Duration>,
    /// Peek-only mode for message inspection without consumption
    pub peek_only: bool,
    /// Sequence number for replay and recovery scenarios
    pub from_sequence_number: Option<u64>,
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        Self {
            max_messages: 1,
            timeout: Duration::seconds(30),
            session_id: None,
            accept_any_session: false,
            lock_duration: None,
            peek_only: false,
            from_sequence_number: None,
        }
    }
}

impl ReceiveOptions {
    /// Create new receive options with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum number of messages to receive
    pub fn with_max_messages(mut self, max: u32) -> Self {
        self.max_messages = max;
        self
    }

    /// Set timeout duration
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set specific session ID to consume from
    pub fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = Some(session_id);
        self.accept_any_session = false;
        self
    }

    /// Accept messages from any available session
    pub fn accept_any_session(mut self) -> Self {
        self.accept_any_session = true;
        self.session_id = None;
        self
    }

    /// Set message lock duration
    pub fn with_lock_duration(mut self, duration: Duration) -> Self {
        self.lock_duration = Some(duration);
        self
    }

    /// Enable peek-only mode (inspect without consuming)
    pub fn peek_only(mut self) -> Self {
        self.peek_only = true;
        self
    }

    /// Set starting sequence number for replay
    pub fn from_sequence_number(mut self, sequence: u64) -> Self {
        self.from_sequence_number = Some(sequence);
        self
    }
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
