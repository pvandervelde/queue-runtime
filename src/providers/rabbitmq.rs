//! RabbitMQ provider implementation using AMQP 0-9-1.
//!
//! This module provides production-ready RabbitMQ integration via the `lapin` AMQP client.
//! It implements the [`QueueProvider`] and [`SessionProvider`] traits, enabling
//! RabbitMQ to be used as a drop-in backend within the queue-runtime abstraction layer.
//!
//! ## Key Features
//!
//! - **AMQP 0-9-1**: Full native protocol support via the `lapin` crate
//! - **Persistent queues**: Messages survive broker restarts (durable queues, persistent
//!   delivery mode)
//! - **Manual acknowledgement**: Messages remain unacked until explicitly completed,
//!   abandoned, or dead-lettered, giving visibility-timeout-like semantics
//! - **Dead letter exchange (DLX)**: Nacked messages are routed to a configured DLX,
//!   mirroring the DLQ behaviour of other providers
//! - **Session emulation**: Sessions are emulated via per-session sub-queues
//!   (`{queue}.session.{session_id}`) with exclusive consumers
//! - **Batch operations**: Up to 100 messages per batch
//!
//! ## Queue Naming
//!
//! Queues are declared as durable on first use.  The naming conventions are:
//!
//! - Main queue: `{queue_name}`
//! - Session queue: `{queue_name}.session.{session_id}`
//!
//! ## Dead Letter Routing
//!
//! When `enable_dead_letter` is `true` the provider automatically binds each
//! queue to the configured dead letter exchange.  Messages dead-lettered via
//! [`dead_letter_message`] are nacked without requeue, causing RabbitMQ to
//! forward them through the DLX to the dead letter queue.
//!
//! ## Session Support
//!
//! Sessions are emulated using per-session sub-queues.  Sending a message with a
//! `session_id` routes it to `{queue}.session.{session_id}`.  A
//! [`RabbitMqSessionProvider`] holds an exclusive consumer on that sub-queue for
//! the duration of the session.
//!
//! ## Testing
//!
//! ```rust,no_run
//! use queue_runtime::providers::RabbitMqProvider;
//! use queue_runtime::RabbitMqConfig;
//!
//! # async fn test_example() {
//! let config = RabbitMqConfig {
//!     url: "amqp://guest:guest@localhost:5672".to_string(),
//!     ..RabbitMqConfig::default()
//! };
//!
//! let provider = RabbitMqProvider::new(config).await.unwrap();
//! # }
//! ```

use crate::client::{QueueProvider, SessionProvider};
use crate::error::QueueError;
use crate::message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceivedMessage, SessionId, Timestamp,
};
use crate::provider::{ProviderType, SessionSupport};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Duration;
use futures::StreamExt;
use lapin::{
    options::{
        BasicAckOptions, BasicConsumeOptions, BasicGetOptions, BasicNackOptions,
        BasicPublishOptions, BasicQosOptions, QueueDeclareOptions,
    },
    types::{AMQPValue, FieldTable, LongString, ShortString},
    BasicProperties, Channel, Connection, ConnectionProperties,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, instrument, warn};

#[cfg(test)]
#[path = "rabbitmq_tests.rs"]
mod tests;

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// Error types
// ============================================================================

/// RabbitMQ-specific error type that wraps AMQP errors.
#[derive(Debug)]
pub struct RabbitMqError {
    message: String,
}

impl RabbitMqError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Convert to a [`QueueError`].
    pub fn to_queue_error(&self) -> QueueError {
        QueueError::ProviderError {
            provider: "rabbitmq".to_string(),
            code: "AMQP_ERROR".to_string(),
            message: self.message.clone(),
        }
    }
}

impl std::fmt::Display for RabbitMqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RabbitMQ error: {}", self.message)
    }
}

impl std::error::Error for RabbitMqError {}

// ============================================================================
// Internal helpers
// ============================================================================

/// An in-flight message awaiting acknowledgement.
struct InFlightEntry {
    /// The AMQP channel the message was received on
    channel: Channel,
    /// AMQP delivery tag used for ack/nack
    delivery_tag: u64,
    /// Lock expiry for best-effort visibility timeout
    lock_expires_at: Timestamp,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Redact any userinfo (username and password) from a URL, keeping host and path.
///
/// Used to prevent credential leakage in log fields and error messages when
/// connection URLs contain embedded credentials
/// (e.g. `amqp://user:pass@host:5672` → `amqp://***:***@host:5672`).
fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let has_credentials = !parsed.username().is_empty() || parsed.password().is_some();
            if has_credentials {
                // Errors here are non-fatal; fall through to return the redacted form.
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => "<invalid-url>".to_string(),
    }
}

/// Build the session sub-queue name from a queue name and session ID.
fn session_queue_name(queue: &QueueName, session_id: &SessionId) -> String {
    // Replace characters not valid in AMQP queue names.
    let safe = session_id.as_str().replace(['/', ' ', '\\'], "_");
    format!("{}.session.{}", queue.as_str(), safe)
}

// ============================================================================
// RabbitMqProvider
// ============================================================================

/// RabbitMQ queue provider using AMQP 0-9-1 via the `lapin` crate.
///
/// All queues are declared as durable on first use.  Messages are published with
/// `delivery_mode = 2` (persistent) so they survive broker restarts.
///
/// The provider emulates visibility timeouts by keeping in-flight messages in an
/// unacked state on the AMQP broker.  If the application crashes before calling
/// [`complete_message`] or [`abandon_message`], the AMQP broker will redeliver
/// the message once the connection is dropped.
pub struct RabbitMqProvider {
    connection: Arc<Connection>,
    config: RabbitMqConfig,
    /// In-flight messages indexed by their receipt handle UUID.
    in_flight: Arc<Mutex<HashMap<String, InFlightEntry>>>,
}

impl RabbitMqProvider {
    /// Create a new [`RabbitMqProvider`] and establish an AMQP connection.
    ///
    /// # Errors
    ///
    /// Returns [`RabbitMqError`] if the AMQP connection cannot be established or
    /// if the URL is malformed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use queue_runtime::providers::RabbitMqProvider;
    /// use queue_runtime::RabbitMqConfig;
    ///
    /// # async fn example() {
    /// let config = RabbitMqConfig::default();
    /// let provider = RabbitMqProvider::new(config).await.unwrap();
    /// # }
    /// ```
    pub async fn new(config: RabbitMqConfig) -> Result<Self, RabbitMqError> {
        let conn = Connection::connect(&config.url, ConnectionProperties::default())
            .await
            .map_err(|e| {
                RabbitMqError::new(format!(
                    "failed to connect to RabbitMQ at '{}': {}",
                    redact_url(&config.url),
                    e
                ))
            })?;

        debug!(url = %redact_url(&config.url), "Connected to RabbitMQ");

        Ok(Self {
            connection: Arc::new(conn),
            config,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Open a new AMQP channel, optionally configuring QoS prefetch.
    async fn open_channel(&self) -> Result<Channel, QueueError> {
        let channel =
            self.connection
                .create_channel()
                .await
                .map_err(|e| QueueError::ConnectionFailed {
                    message: format!("failed to create AMQP channel: {}", e),
                })?;

        if self.config.prefetch_count > 0 {
            channel
                .basic_qos(self.config.prefetch_count, BasicQosOptions::default())
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "rabbitmq".to_string(),
                    code: "QOS_FAILED".to_string(),
                    message: format!("failed to set QoS prefetch: {}", e),
                })?;
        }

        Ok(channel)
    }

    /// Declare a durable queue on the broker, optionally wiring up dead letter
    /// exchange and message TTL via queue arguments.
    async fn declare_queue(&self, channel: &Channel, queue: &QueueName) -> Result<(), QueueError> {
        let mut args = FieldTable::default();

        if self.config.enable_dead_letter {
            if let Some(ref dlx) = self.config.dead_letter_exchange {
                args.insert(
                    ShortString::from("x-dead-letter-exchange"),
                    AMQPValue::LongString(LongString::from(dlx.as_bytes())),
                );
            }
        }

        if let Some(ttl) = self.config.message_ttl {
            let ttl_ms = ttl.num_milliseconds();
            if ttl_ms > 0 {
                args.insert(
                    ShortString::from("x-message-ttl"),
                    AMQPValue::LongLongInt(ttl_ms),
                );
            }
        }

        let opts = QueueDeclareOptions {
            durable: true,
            ..Default::default()
        };

        channel
            .queue_declare(queue.as_str().into(), opts, args)
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "QUEUE_DECLARE_FAILED".to_string(),
                message: format!("failed to declare queue '{}': {}", queue.as_str(), e),
            })?;

        Ok(())
    }

    /// Declare a durable session sub-queue.
    ///
    /// Session queues are named `{queue}.session.{session_id}` and are bound to
    /// the default exchange automatically.
    async fn declare_session_queue(
        &self,
        channel: &Channel,
        queue: &QueueName,
        session_id: &SessionId,
    ) -> Result<String, QueueError> {
        let name = session_queue_name(queue, session_id);

        let opts = QueueDeclareOptions {
            durable: true,
            ..Default::default()
        };

        channel
            .queue_declare(name.as_str().into(), opts, FieldTable::default())
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "SESSION_QUEUE_DECLARE_FAILED".to_string(),
                message: format!("failed to declare session queue '{}': {}", name, e),
            })?;

        Ok(name)
    }

    /// Build AMQP [`BasicProperties`] from a [`Message`].
    fn build_properties(message: &Message) -> BasicProperties {
        let mut props = BasicProperties::default().with_delivery_mode(2); // persistent

        if let Some(ref corr_id) = message.correlation_id {
            props = props.with_correlation_id(ShortString::from(corr_id.as_str()));
        }

        if let Some(ttl) = message.time_to_live {
            let ttl_ms = ttl.num_milliseconds();
            if ttl_ms > 0 {
                props = props.with_expiration(ShortString::from(ttl_ms.to_string().as_str()));
            }
        }

        // Encode message attributes and session ID into AMQP headers.
        let mut headers = FieldTable::default();
        for (k, v) in &message.attributes {
            headers.insert(
                ShortString::from(k.as_str()),
                AMQPValue::LongString(LongString::from(v.as_bytes())),
            );
        }
        if let Some(ref sid) = message.session_id {
            headers.insert(
                ShortString::from("x-session-id"),
                AMQPValue::LongString(LongString::from(sid.as_str().as_bytes())),
            );
        }

        props.with_headers(headers)
    }

    /// Extract message attributes from AMQP headers, skipping all `x-`-prefixed headers.
    ///
    /// AMQP convention reserves the `x-` prefix for extension / broker-managed headers
    /// (e.g. `x-session-id`, `x-delivery-count`, `x-death`).  User attributes are stored
    /// without the `x-` prefix, so this filter is safe to apply broadly.
    fn extract_attributes(headers: &Option<FieldTable>) -> HashMap<String, String> {
        let mut attrs = HashMap::new();
        if let Some(ht) = headers {
            for (k, v) in ht.inner() {
                let key = k.as_str();
                // Skip AMQP extension headers (provider-managed and broker-managed).
                if key.starts_with("x-") {
                    continue;
                }
                if let AMQPValue::LongString(s) = v {
                    attrs.insert(
                        key.to_string(),
                        String::from_utf8_lossy(s.as_bytes()).to_string(),
                    );
                }
            }
        }
        attrs
    }

    /// Extract the session ID from AMQP headers.
    fn extract_session_id(headers: &Option<FieldTable>) -> Option<SessionId> {
        if let Some(ht) = headers {
            if let Some(AMQPValue::LongString(s)) = ht.inner().get("x-session-id") {
                let id = String::from_utf8_lossy(s.as_bytes()).to_string();
                return SessionId::new(id).ok();
            }
        }
        None
    }

    /// Extract the delivery count from AMQP `x-death` / `x-delivery-count` headers.
    fn extract_delivery_count(headers: &Option<FieldTable>) -> u32 {
        if let Some(ht) = headers {
            if let Some(AMQPValue::LongLongInt(n)) = ht.inner().get("x-delivery-count") {
                return (*n as u32).saturating_add(1);
            }
        }
        1
    }

    /// Register a delivery in the in-flight map and return its [`ReceivedMessage`].
    async fn register_delivery(
        &self,
        channel: &Channel,
        delivery_tag: u64,
        data: &[u8],
        headers: Option<FieldTable>,
        correlation_id: Option<String>,
    ) -> ReceivedMessage {
        let session_id = Self::extract_session_id(&headers);
        let attributes = Self::extract_attributes(&headers);
        let delivery_count = Self::extract_delivery_count(&headers);

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        let receipt_id = uuid::Uuid::new_v4().to_string();
        let message_id = MessageId::new();
        let body = Bytes::copy_from_slice(data);

        self.in_flight.lock().await.insert(
            receipt_id.clone(),
            InFlightEntry {
                channel: channel.clone(),
                delivery_tag,
                lock_expires_at,
            },
        );

        ReceivedMessage {
            message_id,
            body,
            attributes,
            session_id,
            correlation_id,
            receipt_handle: ReceiptHandle::new(receipt_id, lock_expires_at, ProviderType::RabbitMq),
            delivery_count,
            first_delivered_at: now,
            delivered_at: now,
        }
    }

    /// Ack, nack-requeue, or nack-discard a message identified by its receipt handle.
    async fn settle_message(
        &self,
        receipt: &ReceiptHandle,
        requeue: Option<bool>,
    ) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;

        // Check existence and lock expiry before removal so callers receive a
        // meaningful error: MessageNotFound for an unknown receipt, and a
        // separate expiry error for a receipt whose lock has lapsed.  Expired
        // entries are then pruned to prevent unbounded map growth.
        match in_flight.get(receipt.handle()) {
            None => {
                return Err(QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                });
            }
            Some(entry) if Timestamp::now() > entry.lock_expires_at => {
                // Remove the stale entry and surface a clear expiry error.
                in_flight.remove(receipt.handle());
                return Err(QueueError::MessageNotFound {
                    receipt: format!("{}(expired)", receipt.handle()),
                });
            }
            Some(_) => {}
        }

        let entry = in_flight
            .remove(receipt.handle())
            .expect("entry present after pre-check");

        match requeue {
            None => {
                // Complete (ack)
                entry
                    .channel
                    .basic_ack(entry.delivery_tag, BasicAckOptions::default())
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "rabbitmq".to_string(),
                        code: "BASIC_ACK_FAILED".to_string(),
                        message: format!("basic_ack failed: {}", e),
                    })?;
            }
            Some(requeue_flag) => {
                // Abandon (requeue=true) or dead-letter (requeue=false)
                entry
                    .channel
                    .basic_nack(
                        entry.delivery_tag,
                        BasicNackOptions {
                            requeue: requeue_flag,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "rabbitmq".to_string(),
                        code: "BASIC_NACK_FAILED".to_string(),
                        message: format!("basic_nack failed: {}", e),
                    })?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// QueueProvider implementation
// ============================================================================

#[async_trait]
impl QueueProvider for RabbitMqProvider {
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

        let channel = self.open_channel().await?;

        // Route session messages to their dedicated sub-queue; all others go to
        // the main queue via the default exchange.
        let routing_key = if let Some(ref sid) = message.session_id {
            self.declare_session_queue(&channel, queue, sid).await?
        } else {
            self.declare_queue(&channel, queue).await?;
            queue.as_str().to_string()
        };

        let props = Self::build_properties(message);

        channel
            .basic_publish(
                "".into(),
                routing_key.as_str().into(),
                BasicPublishOptions::default(),
                &message.body,
                props,
            )
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "PUBLISH_FAILED".to_string(),
                message: format!("failed to publish message to '{}': {}", routing_key, e),
            })?
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "PUBLISH_CONFIRM_FAILED".to_string(),
                message: format!("publish confirmation failed: {}", e),
            })?;

        let message_id = MessageId::new();
        debug!(%message_id, %queue, "Published message to RabbitMQ");
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

        // AMQP 0-9-1 has no native batch-publish command; messages are sent sequentially.
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
        let channel = self.open_channel().await?;
        self.declare_queue(&channel, queue).await?;

        let start = std::time::Instant::now();
        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        loop {
            let get = channel
                .basic_get(queue.as_str().into(), BasicGetOptions { no_ack: false })
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "rabbitmq".to_string(),
                    code: "BASIC_GET_FAILED".to_string(),
                    message: format!("basic_get on '{}' failed: {}", queue.as_str(), e),
                })?;

            if let Some(delivery) = get {
                let headers = delivery.delivery.properties.headers().clone();
                let correlation_id = delivery
                    .delivery
                    .properties
                    .correlation_id()
                    .as_ref()
                    .map(|s| s.to_string());
                let msg = self
                    .register_delivery(
                        &channel,
                        delivery.delivery.delivery_tag,
                        &delivery.delivery.data,
                        headers,
                        correlation_id,
                    )
                    .await;
                return Ok(Some(msg));
            }

            if start.elapsed() >= timeout_std {
                return Ok(None);
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    #[instrument(skip(self), fields(queue = %queue, max = max_messages))]
    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError> {
        let channel = self.open_channel().await?;
        self.declare_queue(&channel, queue).await?;

        let mut messages = Vec::new();
        let start = std::time::Instant::now();
        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        while messages.len() < max_messages as usize {
            if start.elapsed() >= timeout_std {
                break;
            }

            let get = channel
                .basic_get(queue.as_str().into(), BasicGetOptions { no_ack: false })
                .await
                .map_err(|e| QueueError::ProviderError {
                    provider: "rabbitmq".to_string(),
                    code: "BASIC_GET_FAILED".to_string(),
                    message: format!("basic_get on '{}' failed: {}", queue.as_str(), e),
                })?;

            match get {
                Some(delivery) => {
                    let headers = delivery.delivery.properties.headers().clone();
                    let correlation_id = delivery
                        .delivery
                        .properties
                        .correlation_id()
                        .as_ref()
                        .map(|s| s.to_string());
                    let msg = self
                        .register_delivery(
                            &channel,
                            delivery.delivery.delivery_tag,
                            &delivery.delivery.data,
                            headers,
                            correlation_id,
                        )
                        .await;
                    messages.push(msg);
                }
                // Queue is empty; poll with backoff until timeout, mirroring the
                // behaviour of `receive_message` rather than returning immediately.
                None => {
                    if start.elapsed() >= timeout_std {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }

        Ok(messages)
    }

    #[instrument(skip(self, receipt))]
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.settle_message(receipt, None).await
    }

    #[instrument(skip(self, receipt))]
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.settle_message(receipt, Some(true)).await
    }

    #[instrument(skip(self, receipt), fields(reason = %reason))]
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError> {
        debug!(reason, "Dead-lettering RabbitMQ message");
        // The `reason` argument is logged but cannot be forwarded to the DLX because the
        // AMQP `basic_nack` command carries no metadata payload.  Use the NATS provider
        // if dead-letter reason propagation is required.
        self.settle_message(receipt, Some(false)).await
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
                // RabbitMQ does not enumerate sessions; an explicit ID is required.
                return Err(QueueError::SessionNotFound {
                    session_id: "<any>".to_string(),
                });
            }
        };

        let channel = self.open_channel().await?;
        let session_queue = self.declare_session_queue(&channel, queue, &sid).await?;

        // Create an exclusive consumer on the session sub-queue so only one
        // active session client can process messages at a time.
        let consumer = channel
            .basic_consume(
                session_queue.as_str().into(),
                format!("session-{}", uuid::Uuid::new_v4()).as_str().into(),
                BasicConsumeOptions {
                    exclusive: true,
                    no_ack: false,
                    ..Default::default()
                },
                FieldTable::default(),
            )
            .await
            .map_err(|e| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "CONSUME_FAILED".to_string(),
                message: format!(
                    "failed to start exclusive consumer on '{}': {}",
                    session_queue, e
                ),
            })?;

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        // Spawn a background task that forwards deliveries over a channel so
        // we can use standard tokio async patterns without depending on
        // futures_lite directly in application code.
        let (tx, rx) = mpsc::unbounded_channel::<lapin::message::Delivery>();
        tokio::spawn(async move {
            let mut consumer = consumer;
            while let Some(result) = consumer.next().await {
                match result {
                    Ok(delivery) => {
                        if tx.send(delivery).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "RabbitMQ session consumer error");
                        break;
                    }
                }
            }
        });

        Ok(Box::new(RabbitMqSessionProvider {
            channel,
            deliveries: Arc::new(Mutex::new(rx)),
            session_id: sid,
            in_flight: self.in_flight.clone(),
            lock_expires_at: Arc::new(std::sync::Mutex::new(lock_expires_at)),
            config: self.config.clone(),
        }))
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::RabbitMq
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
// RabbitMqSessionProvider
// ============================================================================

/// Session provider for RabbitMQ backed by an exclusive per-session consumer.
///
/// An exclusive consumer on the session sub-queue ensures that only one active
/// [`RabbitMqSessionProvider`] processes messages for a given session at a time,
/// providing the ordering and exclusive-access semantics expected of sessions.
pub struct RabbitMqSessionProvider {
    channel: Channel,
    /// Tokio channel receiving deliveries forwarded from the AMQP consumer.
    deliveries: Arc<Mutex<mpsc::UnboundedReceiver<lapin::message::Delivery>>>,
    session_id: SessionId,
    in_flight: Arc<Mutex<HashMap<String, InFlightEntry>>>,
    /// Current session-lock expiry; shared so `renew_session_lock` can update it.
    lock_expires_at: Arc<std::sync::Mutex<Timestamp>>,
    config: RabbitMqConfig,
}

#[async_trait]
impl SessionProvider for RabbitMqSessionProvider {
    #[instrument(skip(self), fields(session_id = %self.session_id))]
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        self.check_lock()?;

        let timeout_std = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        let mut rx = self.deliveries.lock().await;
        match tokio::time::timeout(timeout_std, rx.recv()).await {
            Ok(Some(delivery)) => {
                let msg = self.register_session_delivery(delivery).await;
                Ok(Some(msg))
            }
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // timeout
        }
    }

    #[instrument(skip(self, receipt))]
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.check_lock()?;
        self.settle(receipt, None).await
    }

    #[instrument(skip(self, receipt))]
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        self.check_lock()?;
        self.settle(receipt, Some(true)).await
    }

    #[instrument(skip(self, receipt), fields(reason = %reason))]
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError> {
        self.check_lock()?;
        debug!(reason, "Dead-lettering session message");
        self.settle(receipt, Some(false)).await
    }

    async fn renew_session_lock(&self) -> Result<(), QueueError> {
        let new_expiry = Timestamp::from_datetime(
            Timestamp::now().as_datetime() + self.config.session_lock_duration,
        );
        *self
            .lock_expires_at
            .lock()
            .map_err(|_| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "INTERNAL_ERROR".to_string(),
                message: "session lock mutex poisoned".to_string(),
            })? = new_expiry;
        debug!(session_id = %self.session_id, "RabbitMQ session lock renewed");
        Ok(())
    }

    async fn close_session(&self) -> Result<(), QueueError> {
        if let Err(e) = self.channel.close(200, "session closed".into()).await {
            warn!(error = %e, "Failed to cleanly close RabbitMQ session channel");
        }
        Ok(())
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn session_expires_at(&self) -> Timestamp {
        // Recover from a poisoned lock by using the last known value.
        *self
            .lock_expires_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }
}

impl RabbitMqSessionProvider {
    /// Return an error if the session lock has expired.
    fn check_lock(&self) -> Result<(), QueueError> {
        let expires = *self
            .lock_expires_at
            .lock()
            .map_err(|_| QueueError::ProviderError {
                provider: "rabbitmq".to_string(),
                code: "INTERNAL_ERROR".to_string(),
                message: "session lock mutex poisoned".to_string(),
            })?;
        if Timestamp::now() > expires {
            return Err(QueueError::SessionLocked {
                session_id: self.session_id.as_str().to_string(),
                locked_until: expires,
            });
        }
        Ok(())
    }

    /// Register a delivery in the in-flight map and build a [`ReceivedMessage`].
    async fn register_session_delivery(
        &self,
        delivery: lapin::message::Delivery,
    ) -> ReceivedMessage {
        let delivery_tag = delivery.delivery_tag;
        let headers = delivery.properties.headers().clone();
        let attributes = RabbitMqProvider::extract_attributes(&headers);
        let delivery_count = RabbitMqProvider::extract_delivery_count(&headers);
        let correlation_id = delivery
            .properties
            .correlation_id()
            .as_ref()
            .map(|s| s.to_string());

        let now = Timestamp::now();
        let lock_expires_at =
            Timestamp::from_datetime(now.as_datetime() + self.config.session_lock_duration);

        let receipt_id = uuid::Uuid::new_v4().to_string();
        let message_id = MessageId::new();
        let body = Bytes::copy_from_slice(&delivery.data);

        self.in_flight.lock().await.insert(
            receipt_id.clone(),
            InFlightEntry {
                channel: self.channel.clone(),
                delivery_tag,
                lock_expires_at,
            },
        );

        ReceivedMessage {
            message_id,
            body,
            attributes,
            session_id: Some(self.session_id.clone()),
            correlation_id,
            receipt_handle: ReceiptHandle::new(receipt_id, lock_expires_at, ProviderType::RabbitMq),
            delivery_count,
            first_delivered_at: now,
            delivered_at: now,
        }
    }

    /// Ack, nack-requeue, or nack-discard a message identified by its receipt handle.
    async fn settle(
        &self,
        receipt: &ReceiptHandle,
        requeue: Option<bool>,
    ) -> Result<(), QueueError> {
        let mut in_flight = self.in_flight.lock().await;

        // Check existence and lock expiry before removal (mirrors settle_message).
        match in_flight.get(receipt.handle()) {
            None => {
                return Err(QueueError::MessageNotFound {
                    receipt: receipt.handle().to_string(),
                });
            }
            Some(entry) if Timestamp::now() > entry.lock_expires_at => {
                in_flight.remove(receipt.handle());
                return Err(QueueError::MessageNotFound {
                    receipt: format!("{}(expired)", receipt.handle()),
                });
            }
            Some(_) => {}
        }

        let entry = in_flight
            .remove(receipt.handle())
            .expect("entry present after pre-check");

        match requeue {
            None => {
                entry
                    .channel
                    .basic_ack(entry.delivery_tag, BasicAckOptions::default())
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "rabbitmq".to_string(),
                        code: "BASIC_ACK_FAILED".to_string(),
                        message: format!("basic_ack failed: {}", e),
                    })?;
            }
            Some(requeue_flag) => {
                entry
                    .channel
                    .basic_nack(
                        entry.delivery_tag,
                        BasicNackOptions {
                            requeue: requeue_flag,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|e| QueueError::ProviderError {
                        provider: "rabbitmq".to_string(),
                        code: "BASIC_NACK_FAILED".to_string(),
                        message: format!("basic_nack failed: {}", e),
                    })?;
            }
        }

        Ok(())
    }
}
