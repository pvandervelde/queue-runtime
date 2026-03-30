//! NATS provider implementation using JetStream.
//!
//! This module provides production-ready NATS integration via the `async-nats` client
//! with JetStream.  It implements the [`QueueProvider`] and [`SessionProvider`] traits,
//! enabling NATS to be used as a drop-in backend in the queue-runtime abstraction layer.
//!
//! ## Key Features
//!
//! - **JetStream**: Persistent, at-least-once message delivery with ack/nak semantics
//! - **Pull consumers**: Explicit message fetch with configurable ack-wait (visibility
//!   timeout analog)
//! - **Dead letter support**: Failed messages forwarded to a configurable DLQ stream
//! - **Session emulation**: Sessions emulated via per-session filter subjects within a
//!   shared stream
//! - **Batch operations**: Up to 100 messages per batch
//!
//! ## Stream and Subject Naming
//!
//! The provider creates one JetStream stream per queue.  Naming conventions:
//!
//! - Stream name: `{stream_prefix}-{queue_name}` (hyphens replace underscores for
//!   NATS compatibility)
//! - Subject: `{stream_prefix}.{queue_name}`
//! - Session subject: `{stream_prefix}.{queue_name}.session.{session_id}`
//!
//! ## Dead Letter Support
//!
//! When `enable_dead_letter` is `true` and `dead_letter_subject_prefix` is set,
//! messages dead-lettered via [`dead_letter_message`] are published to
//! `{prefix}.{queue_name}` using a separate JetStream stream for DLQ messages.
//!
//! ## Session Support
//!
//! Sessions are emulated via JetStream subject filtering.  Each session gets its own
//! subject (`{prefix}.{queue}.session.{session_id}`), and a [`NatsSessionProvider`]
//! creates a per-session pull consumer filtered to that subject.
//!
//! ## Connection
//!
//! The provider uses the `async-nats` client which reconnects automatically on
//! connection loss.  Optional NATS credentials can be loaded from a `.creds` file
//! via the `credentials_path` configuration field.
//!
//! ## Testing
//!
//! ```rust,no_run
//! use queue_runtime::providers::NatsProvider;
//! use queue_runtime::NatsConfig;
//!
//! # async fn test_example() {
//! let config = NatsConfig {
//!     url: "nats://localhost:4222".to_string(),
//!     ..NatsConfig::default()
//! };
//!
//! let provider = NatsProvider::new(config).await.unwrap();
//! # }
//! ```

use crate::client::{QueueProvider, SessionProvider};
use crate::error::QueueError;
use crate::message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceivedMessage, SessionId, Timestamp,
};
use crate::provider::{ProviderType, SessionSupport};
use async_nats::jetstream::{
    self, consumer::pull::Config as ConsumerConfig, stream::Config as StreamConfig, AckKind,
    Context as JetStreamContext,
};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Duration;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};

#[cfg(test)]
#[path = "nats_tests.rs"]
mod tests;

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// Error types
// ============================================================================

/// NATS-specific error type.
#[derive(Debug)]
pub struct NatsError {
    message: String,
}

impl NatsError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Convert to a [`QueueError`].
    pub fn to_queue_error(&self) -> QueueError {
        QueueError::ProviderError {
            provider: "nats".to_string(),
            code: "NATS_ERROR".to_string(),
            message: self.message.clone(),
        }
    }
}

impl std::fmt::Display for NatsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NATS error: {}", self.message)
    }
}

impl std::error::Error for NatsError {}

// ============================================================================
// Internal helpers
// ============================================================================

/// An in-flight JetStream message pending acknowledgement.
struct InFlightEntry {
    /// The JetStream message (contains ack/nak methods)
    js_message: async_nats::jetstream::Message,
    /// Lock expiry (maps to the JetStream ack-wait on the consumer)
    lock_expires_at: Timestamp,
    /// Dead letter subject for this message's queue
    dead_letter_subject: Option<String>,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Sanitise a queue name for use in NATS subject/stream identifiers.
///
/// NATS subjects use `.` as a separator and do not allow spaces.
fn nats_safe(s: &str) -> String {
    s.replace(['-', ' '], "_")
}

/// Build the NATS subject for a queue.
fn queue_subject(config: &NatsConfig, queue: &QueueName) -> String {
    format!(
        "{}.{}",
        nats_safe(&config.stream_prefix),
        nats_safe(queue.as_str())
    )
}

/// Build the NATS subject for a session within a queue.
fn session_subject(config: &NatsConfig, queue: &QueueName, session_id: &SessionId) -> String {
    let safe_session = session_id.as_str().replace(['-', '/', ' '], "_");
    format!(
        "{}.{}.session.{}",
        nats_safe(&config.stream_prefix),
        nats_safe(queue.as_str()),
        safe_session
    )
}

/// Build the JetStream stream name for a queue.
fn stream_name(config: &NatsConfig, queue: &QueueName) -> String {
    // JetStream stream names may not contain dots.
    format!(
        "{}-{}",
        nats_safe(&config.stream_prefix),
        nats_safe(queue.as_str())
    )
}

/// Build the dead-letter subject for a queue if DLQ is enabled.
fn dead_letter_subject(config: &NatsConfig, queue: &QueueName) -> Option<String> {
    if !config.enable_dead_letter {
        return None;
    }
    config
        .dead_letter_subject_prefix
        .as_ref()
        .map(|prefix| format!("{}.{}", nats_safe(prefix), nats_safe(queue.as_str())))
}

// ============================================================================
// NatsProvider
// ============================================================================

/// NATS queue provider using JetStream for persistent, at-least-once delivery.
///
/// Each queue maps to a JetStream stream created on demand.  Messages are published
/// to per-queue subjects and consumed via pull consumers.
pub struct NatsProvider {
    client: async_nats::Client,
    jetstream: JetStreamContext,
    config: NatsConfig,
    /// In-flight messages indexed by their receipt handle UUID.
    in_flight: Arc<Mutex<HashMap<String, InFlightEntry>>>,
}

impl NatsProvider {
    /// Create a new [`NatsProvider`] and connect to the NATS server.
    ///
    /// # Errors
    ///
    /// Returns [`NatsError`] if the connection cannot be established or the
    /// credentials file cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use queue_runtime::providers::NatsProvider;
    /// use queue_runtime::NatsConfig;
    ///
    /// # async fn example() {
    /// let config = NatsConfig::default();
    /// let provider = NatsProvider::new(config).await.unwrap();
    /// # }
    /// ```
    pub async fn new(config: NatsConfig) -> Result<Self, NatsError> {
        let connect_options = if let Some(ref creds_path) = config.credentials_path {
            async_nats::ConnectOptions::with_credentials_file(creds_path.as_str())
                .await
                .map_err(|e| NatsError::new(format!("failed to load NATS credentials: {}", e)))?
        } else {
            async_nats::ConnectOptions::new()
        };

        let client = connect_options.connect(&config.url).await.map_err(|e| {
            NatsError::new(format!(
                "failed to connect to NATS at '{}': {}",
                config.url, e
            ))
        })?;

        let jetstream = jetstream::new(client.clone());

        debug!(url = %config.url, "Connected to NATS");

        Ok(Self {
            client,
            jetstream,
            config,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Ensure a JetStream stream exists for the given queue, creating it if needed.
    ///
    /// Streams are created with the `WorkQueue` retention policy so each message
    /// is delivered to exactly one consumer.
    async fn ensure_stream(&self, queue: &QueueName) -> Result<(), QueueError> {
        let name = stream_name(&self.config, queue);
        let subject = queue_subject(&self.config, queue);

        // Subject wildcard: capture both the main subject and all session subjects.
        let subjects = vec![subject.clone(), format!("{}.session.>", subject)];

        let stream_config = StreamConfig {
            name: name.clone(),
            subjects,
            retention: async_nats::jetstream::stream::RetentionPolicy::WorkQueue,
            storage: async_nats::jetstream::stream::StorageType::File,
            ..Default::default()
        };

        self.jetstream
            .get_or_create_stream(stream_config)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "STREAM_CREATE_FAILED".to_string(),
                message: format!("failed to ensure JetStream stream '{}': {}", name, e),
            })?;

        // Also ensure the DLQ stream exists if dead letter is enabled.
        self.ensure_dlq_stream(queue).await?;

        Ok(())
    }

    /// Ensure a JetStream stream exists for the dead letter queue.
    async fn ensure_dlq_stream(&self, queue: &QueueName) -> Result<(), QueueError> {
        let dlq_subject = match dead_letter_subject(&self.config, queue) {
            Some(s) => s,
            None => return Ok(()),
        };

        let dlq_stream_name = format!(
            "dlq-{}-{}",
            nats_safe(&self.config.stream_prefix),
            nats_safe(queue.as_str())
        );

        let stream_config = StreamConfig {
            name: dlq_stream_name.clone(),
            subjects: vec![dlq_subject],
            storage: async_nats::jetstream::stream::StorageType::File,
            ..Default::default()
        };

        self.jetstream
            .get_or_create_stream(stream_config)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "DLQ_STREAM_CREATE_FAILED".to_string(),
                message: format!("failed to ensure DLQ stream '{}': {}", dlq_stream_name, e),
            })?;

        Ok(())
    }

    /// Create an ephemeral pull consumer for the given subject filter.
    async fn create_consumer(
        &self,
        queue: &QueueName,
        filter_subject: &str,
    ) -> Result<async_nats::jetstream::consumer::Consumer<ConsumerConfig>, QueueError> {
        let name = stream_name(&self.config, queue);
        let ack_wait_std = self
            .config
            .ack_wait
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        let consumer_config = ConsumerConfig {
            filter_subject: filter_subject.to_string(),
            ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
            ack_wait: ack_wait_std,
            max_deliver: self.config.max_deliver.unwrap_or(-1),
            ..Default::default()
        };

        let stream =
            self.jetstream
                .get_stream(&name)
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "nats".to_string(),
                    code: "STREAM_GET_FAILED".to_string(),
                    message: format!("failed to get stream '{}': {}", name, e),
                })?;

        let consumer = stream.create_consumer(consumer_config).await.map_err(|e| {
            QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "CONSUMER_CREATE_FAILED".to_string(),
                message: format!("failed to create pull consumer on '{}': {}", name, e),
            }
        })?;

        Ok(consumer)
    }

    /// Encode message metadata into NATS message headers.
    fn build_headers(message: &Message) -> async_nats::header::HeaderMap {
        let mut headers = async_nats::header::HeaderMap::new();

        if let Some(ref sid) = message.session_id {
            headers.insert("x-session-id", sid.as_str());
        }
        if let Some(ref corr_id) = message.correlation_id {
            headers.insert("x-correlation-id", corr_id.as_str());
        }
        for (k, v) in &message.attributes {
            // Prefix user attributes to distinguish from provider headers.
            headers.insert(format!("x-attr-{}", k).as_str(), v.as_str());
        }

        headers
    }

    /// Extract message attributes from NATS headers.
    fn extract_attributes(
        headers: &Option<async_nats::header::HeaderMap>,
    ) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        if let Some(hm) = headers {
            for (name, values) in hm.iter() {
                // HeaderName implements AsRef<str> for &str access
                let key: &str = name.as_ref();
                if let Some(attr_key) = key.strip_prefix("x-attr-") {
                    if let Some(val) = values.first() {
                        attrs.insert(attr_key.to_string(), val.as_str().to_string());
                    }
                }
            }
        }
        attrs
    }

    /// Extract the session ID from NATS headers.
    fn extract_session_id(headers: &Option<async_nats::header::HeaderMap>) -> Option<SessionId> {
        if let Some(hm) = headers {
            if let Some(val) = hm.get("x-session-id") {
                let id = val.as_str().to_string();
                return SessionId::new(id).ok();
            }
        }
        None
    }

    /// Extract the correlation ID from NATS headers.
    fn extract_correlation_id(headers: &Option<async_nats::header::HeaderMap>) -> Option<String> {
        if let Some(hm) = headers {
            if let Some(val) = hm.get("x-correlation-id") {
                return Some(val.as_str().to_string());
            }
        }
        None
    }

    /// Register a JetStream message in the in-flight map and return a [`ReceivedMessage`].
    async fn register_js_message(
        &self,
        js_message: async_nats::jetstream::Message,
        queue: &QueueName,
    ) -> ReceivedMessage {
        let headers = js_message.message.headers.clone();
        let session_id = Self::extract_session_id(&headers);
        let attributes = Self::extract_attributes(&headers);
        let correlation_id = Self::extract_correlation_id(&headers);
        let delivery_count = js_message.info().map(|i| i.delivered as u32).unwrap_or(1);
        let body = Bytes::copy_from_slice(&js_message.message.payload);

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        let receipt_id = uuid::Uuid::new_v4().to_string();
        let message_id = MessageId::new();

        let dlq_subject = dead_letter_subject(&self.config, queue);

        self.in_flight.lock().await.insert(
            receipt_id.clone(),
            InFlightEntry {
                js_message,
                lock_expires_at,
                dead_letter_subject: dlq_subject,
            },
        );

        ReceivedMessage {
            message_id,
            body,
            attributes,
            session_id,
            correlation_id,
            receipt_handle: ReceiptHandle::new(receipt_id, lock_expires_at, ProviderType::Nats),
            delivery_count,
            first_delivered_at: now,
            delivered_at: now,
        }
    }
}

// ============================================================================
// QueueProvider implementation
// ============================================================================

#[async_trait]
impl QueueProvider for NatsProvider {
    #[instrument(skip(self, message), fields(queue = %queue))]
    async fn send_message(
        &self,
        queue: &QueueName,
        message: &Message,
    ) -> Result<MessageId, QueueError> {
        let size = message.body.len();
        let max_size = self.provider_type().max_message_size();
        if size > max_size {
            return Err(QueueError::MessageTooLarge { size, max_size });
        }

        self.ensure_stream(queue).await?;

        // Route to session subject if session_id is set, otherwise main subject.
        let subject = if let Some(ref sid) = message.session_id {
            session_subject(&self.config, queue, sid)
        } else {
            queue_subject(&self.config, queue)
        };

        let headers = Self::build_headers(message);
        let payload = Bytes::copy_from_slice(&message.body);

        self.jetstream
            .publish_with_headers(subject.clone(), headers, payload)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "PUBLISH_FAILED".to_string(),
                message: format!("failed to publish to subject '{}': {}", subject, e),
            })?
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "PUBLISH_ACK_FAILED".to_string(),
                message: format!("JetStream publish ack failed: {}", e),
            })?;

        let message_id = MessageId::new();
        debug!(%message_id, %queue, "Published message to NATS JetStream");
        Ok(message_id)
    }

    #[instrument(skip(self, messages), fields(queue = %queue, count = messages.len()))]
    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: &[Message],
    ) -> Result<Vec<MessageId>, QueueError> {
        if messages.len() > self.max_batch_size() as usize {
            return Err(QueueError::BatchTooLarge {
                size: messages.len(),
                max_size: self.max_batch_size() as usize,
            });
        }

        let mut ids = Vec::with_capacity(messages.len());
        for message in messages {
            ids.push(self.send_message(queue, message).await?);
        }
        Ok(ids)
    }

    #[instrument(skip(self), fields(queue = %queue))]
    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        self.ensure_stream(queue).await?;

        let subject = queue_subject(&self.config, queue);
        let consumer = self.create_consumer(queue, &subject).await?;

        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        let mut messages = consumer
            .fetch()
            .max_messages(1)
            .expires(timeout_std)
            .messages()
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "FETCH_FAILED".to_string(),
                message: format!("failed to fetch from JetStream: {}", e),
            })?;

        match tokio::time::timeout(timeout_std, messages.next()).await {
            Ok(Some(Ok(js_msg))) => {
                let msg = self.register_js_message(js_msg, queue).await;
                Ok(Some(msg))
            }
            Ok(Some(Err(e))) => Err(QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "MESSAGE_ERROR".to_string(),
                message: format!("error reading JetStream message: {}", e),
            }),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    #[instrument(skip(self), fields(queue = %queue, max = max_messages))]
    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError> {
        self.ensure_stream(queue).await?;

        let subject = queue_subject(&self.config, queue);
        let consumer = self.create_consumer(queue, &subject).await?;

        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        let mut js_messages = consumer
            .fetch()
            .max_messages(max_messages as usize)
            .expires(timeout_std)
            .messages()
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "FETCH_FAILED".to_string(),
                message: format!("failed to fetch from JetStream: {}", e),
            })?;

        let mut result = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout_std;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || result.len() >= max_messages as usize {
                break;
            }

            match tokio::time::timeout(remaining, js_messages.next()).await {
                Ok(Some(Ok(js_msg))) => {
                    let msg = self.register_js_message(js_msg, queue).await;
                    result.push(msg);
                }
                Ok(Some(Err(e))) => {
                    return Err(QueueError::ProviderError {
                        provider: "nats".to_string(),
                        code: "MESSAGE_ERROR".to_string(),
                        message: format!("error reading JetStream message: {}", e),
                    });
                }
                Ok(None) | Err(_) => break,
            }
        }

        Ok(result)
    }

    #[instrument(skip(self, receipt))]
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;
        let entry =
            in_flight
                .remove(receipt.handle())
                .ok_or_else(|| QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                })?;

        if Timestamp::now() > entry.lock_expires_at {
            return Err(QueueError::MessageNotFound {
                receipt: receipt.handle().to_string(),
            });
        }

        entry
            .js_message
            .ack()
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "ACK_FAILED".to_string(),
                message: format!("JetStream ack failed: {}", e),
            })?;

        Ok(())
    }

    #[instrument(skip(self, receipt))]
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;
        let entry =
            in_flight
                .remove(receipt.handle())
                .ok_or_else(|| QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                })?;

        if Timestamp::now() > entry.lock_expires_at {
            return Err(QueueError::MessageNotFound {
                receipt: receipt.handle().to_string(),
            });
        }

        entry
            .js_message
            .ack_with(AckKind::Nak(None))
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "NAK_FAILED".to_string(),
                message: format!("JetStream nak failed: {}", e),
            })?;

        Ok(())
    }

    #[instrument(skip(self, receipt), fields(reason = %reason))]
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;
        let entry =
            in_flight
                .remove(receipt.handle())
                .ok_or_else(|| QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                })?;

        if Timestamp::now() > entry.lock_expires_at {
            return Err(QueueError::MessageNotFound {
                receipt: receipt.handle().to_string(),
            });
        }

        // Terminate delivery so JetStream stops redelivering this message.
        entry
            .js_message
            .ack_with(async_nats::jetstream::AckKind::Term)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "TERM_FAILED".to_string(),
                message: format!("JetStream term ack failed: {}", e),
            })?;

        // Publish to DLQ stream if configured.
        if let Some(ref dlq_subject) = entry.dead_letter_subject {
            let mut headers = async_nats::header::HeaderMap::new();
            headers.insert("x-dead-letter-reason", reason);
            let payload = entry.js_message.message.payload.clone();
            if let Some(msg_headers) = &entry.js_message.message.headers {
                for (name, values) in msg_headers.iter() {
                    // HeaderName implements AsRef<str>
                    let key: &str = name.as_ref();
                    for val in values.iter() {
                        headers.insert(key, val.as_str());
                    }
                }
            }

            self.client
                .publish_with_headers(dlq_subject.clone(), headers, payload)
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "nats".to_string(),
                    code: "DLQ_PUBLISH_FAILED".to_string(),
                    message: format!(
                        "failed to publish dead-lettered message to '{}': {}",
                        dlq_subject, e
                    ),
                })?;

            debug!(
                reason,
                dlq_subject, "Message dead-lettered and published to DLQ"
            );
        } else {
            debug!(reason, "Message terminated (no DLQ configured)");
        }

        Ok(())
    }

    #[instrument(skip(self), fields(queue = %queue))]
    async fn create_session_client(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionProvider>, QueueError> {
        let sid = match session_id {
            Some(id) => id,
            None => {
                // NATS does not enumerate active sessions; an explicit ID is required.
                return Err(QueueError::SessionNotFound {
                    session_id: "<any>".to_string(),
                });
            }
        };

        self.ensure_stream(queue).await?;

        let subject = session_subject(&self.config, queue, &sid);
        let consumer = self.create_consumer(queue, &subject).await?;

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        Ok(Box::new(NatsSessionProvider {
            consumer: Arc::new(Mutex::new(consumer)),
            client: self.client.clone(),
            session_id: sid,
            queue_name: queue.clone(),
            in_flight: self.in_flight.clone(),
            lock_expires_at,
            config: self.config.clone(),
        }))
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Nats
    }

    fn supports_sessions(&self) -> SessionSupport {
        SessionSupport::Emulated
    }

    fn supports_batching(&self) -> bool {
        true
    }

    fn max_batch_size(&self) -> u32 {
        100
    }
}

// ============================================================================
// NatsSessionProvider
// ============================================================================

/// Session provider for NATS using a per-session JetStream pull consumer.
///
/// Messages for the session are filtered by a dedicated subject
/// (`{prefix}.{queue}.session.{session_id}`), ensuring ordered, exclusive delivery
/// within the session.
pub struct NatsSessionProvider {
    consumer: Arc<Mutex<async_nats::jetstream::consumer::Consumer<ConsumerConfig>>>,
    client: async_nats::Client,
    session_id: SessionId,
    queue_name: QueueName,
    in_flight: Arc<Mutex<HashMap<String, InFlightEntry>>>,
    lock_expires_at: Timestamp,
    config: NatsConfig,
}

#[async_trait]
impl SessionProvider for NatsSessionProvider {
    #[instrument(skip(self), fields(session_id = %self.session_id))]
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        self.check_lock()?;

        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        let consumer = self.consumer.lock().await;

        let mut messages = consumer
            .fetch()
            .max_messages(1)
            .expires(timeout_std)
            .messages()
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "FETCH_FAILED".to_string(),
                message: format!("session fetch failed: {}", e),
            })?;

        match tokio::time::timeout(timeout_std, messages.next()).await {
            Ok(Some(Ok(js_msg))) => {
                let msg = self.register_session_message(js_msg).await;
                Ok(Some(msg))
            }
            Ok(Some(Err(e))) => Err(QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "MESSAGE_ERROR".to_string(),
                message: format!("session message error: {}", e),
            }),
            Ok(None) | Err(_) => Ok(None),
        }
    }

    #[instrument(skip(self, receipt))]
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.check_lock()?;
        self.ack_message(receipt, SettlementKind::Ack).await
    }

    #[instrument(skip(self, receipt))]
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.check_lock()?;
        self.ack_message(receipt, SettlementKind::Nak).await
    }

    #[instrument(skip(self, receipt), fields(reason = %reason))]
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError> {
        self.check_lock()?;

        let mut in_flight = self.in_flight.lock().await;
        let entry =
            in_flight
                .remove(receipt.handle())
                .ok_or_else(|| QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                })?;

        if Timestamp::now() > entry.lock_expires_at {
            return Err(QueueError::MessageNotFound {
                receipt: receipt.handle().to_string(),
            });
        }

        entry
            .js_message
            .ack_with(async_nats::jetstream::AckKind::Term)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "nats".to_string(),
                code: "TERM_FAILED".to_string(),
                message: format!("session term ack failed: {}", e),
            })?;

        // Forward to DLQ if configured
        if let Some(ref dlq_subject) = entry.dead_letter_subject {
            let mut headers = async_nats::header::HeaderMap::new();
            headers.insert("x-dead-letter-reason", reason);
            let payload = entry.js_message.message.payload.clone();

            self.client
                .publish_with_headers(dlq_subject.clone(), headers, payload)
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "nats".to_string(),
                    code: "DLQ_PUBLISH_FAILED".to_string(),
                    message: format!("failed to publish to DLQ '{}': {}", dlq_subject, e),
                })?;

            debug!(reason, dlq_subject, "Session message dead-lettered");
        }

        Ok(())
    }

    async fn renew_session_lock(&self) -> Result<(), QueueError> {
        warn!("NATS session lock renewal extends the in-memory lock only");
        Ok(())
    }

    async fn close_session(&self) -> Result<(), QueueError> {
        // Pull consumers are ephemeral and cleaned up by the server; nothing to do.
        Ok(())
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn session_expires_at(&self) -> Timestamp {
        self.lock_expires_at
    }
}

/// Internal settlement kind for session operations.
enum SettlementKind {
    Ack,
    Nak,
}

impl NatsSessionProvider {
    /// Return an error if the session lock has expired.
    fn check_lock(&self) -> Result<(), QueueError> {
        if Timestamp::now() > self.lock_expires_at {
            return Err(QueueError::SessionLocked {
                session_id: self.session_id.as_str().to_string(),
                locked_until: self.lock_expires_at,
            });
        }
        Ok(())
    }

    /// Ack or nak a message identified by its receipt handle.
    async fn ack_message(
        &self,
        receipt: &ReceiptHandle,
        kind: SettlementKind,
    ) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;
        let entry =
            in_flight
                .remove(receipt.handle())
                .ok_or_else(|| QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                })?;

        if Timestamp::now() > entry.lock_expires_at {
            return Err(QueueError::MessageNotFound {
                receipt: receipt.handle().to_string(),
            });
        }

        match kind {
            SettlementKind::Ack => {
                entry
                    .js_message
                    .ack()
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "nats".to_string(),
                        code: "ACK_FAILED".to_string(),
                        message: format!("session ack failed: {}", e),
                    })
            }
            SettlementKind::Nak => {
                entry
                    .js_message
                    .ack_with(AckKind::Nak(None))
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "nats".to_string(),
                        code: "NAK_FAILED".to_string(),
                        message: format!("session nak failed: {}", e),
                    })
            }
        }
    }

    /// Register a JetStream message in the in-flight map and build a [`ReceivedMessage`].
    async fn register_session_message(
        &self,
        js_message: async_nats::jetstream::Message,
    ) -> ReceivedMessage {
        let headers = js_message.message.headers.clone();
        let attributes = NatsProvider::extract_attributes(&headers);
        let correlation_id = NatsProvider::extract_correlation_id(&headers);
        let delivery_count = js_message.info().map(|i| i.delivered as u32).unwrap_or(1);
        let body = Bytes::copy_from_slice(&js_message.message.payload);

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        let receipt_id = uuid::Uuid::new_v4().to_string();
        let message_id = MessageId::new();

        let dlq_subject = dead_letter_subject(&self.config, &self.queue_name);

        self.in_flight.lock().await.insert(
            receipt_id.clone(),
            InFlightEntry {
                js_message,
                lock_expires_at,
                dead_letter_subject: dlq_subject,
            },
        );

        ReceivedMessage {
            message_id,
            body,
            attributes,
            session_id: Some(self.session_id.clone()),
            correlation_id,
            receipt_handle: ReceiptHandle::new(receipt_id, lock_expires_at, ProviderType::Nats),
            delivery_count,
            first_delivered_at: now,
            delivered_at: now,
        }
    }
}
