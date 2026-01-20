//! In-memory queue provider implementation for testing and development.
//!
//! This module provides a fully functional in-memory queue implementation that:
//! - Supports session-based ordered message processing
//! - Implements visibility timeouts and message TTL
//! - Simulates dead letter queue behavior
//! - Provides thread-safe concurrent access
//!
//! This provider is intended for:
//! - Unit testing of queue-runtime consumers
//! - Development and prototyping
//! - Reference implementation for cloud providers

use crate::client::{QueueProvider, SessionProvider};
use crate::error::QueueError;
use crate::message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceivedMessage, SessionId, Timestamp,
};
use crate::provider::{InMemoryConfig, ProviderType, SessionSupport};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Duration;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

#[cfg(test)]
#[path = "memory_tests.rs"]
mod tests;

// ============================================================================
// Internal Storage Structures
// ============================================================================

/// Thread-safe storage for all queues
struct QueueStorage {
    queues: HashMap<QueueName, InMemoryQueue>,
    config: InMemoryConfig,
}

impl QueueStorage {
    fn new(config: InMemoryConfig) -> Self {
        Self {
            queues: HashMap::new(),
            config,
        }
    }

    /// Get or create a queue
    fn get_or_create_queue(&mut self, queue_name: &QueueName) -> &mut InMemoryQueue {
        self.queues
            .entry(queue_name.clone())
            .or_insert_with(|| InMemoryQueue::new(self.config.clone()))
    }
}

/// Internal queue state for a single queue
struct InMemoryQueue {
    /// Main message queue (FIFO order)
    messages: VecDeque<StoredMessage>,
    /// Dead letter queue for failed messages
    dead_letter: VecDeque<StoredMessage>,
    /// In-flight messages being processed
    in_flight: HashMap<String, InFlightMessage>,
    /// Session state tracking
    sessions: HashMap<SessionId, SessionState>,
    /// Configuration
    config: InMemoryConfig,
}

impl InMemoryQueue {
    fn new(config: InMemoryConfig) -> Self {
        Self {
            messages: VecDeque::new(),
            dead_letter: VecDeque::new(),
            in_flight: HashMap::new(),
            sessions: HashMap::new(),
            config,
        }
    }
}

/// A message stored in the queue with metadata
#[derive(Clone)]
struct StoredMessage {
    message_id: MessageId,
    body: Bytes,
    attributes: HashMap<String, String>,
    session_id: Option<SessionId>,
    correlation_id: Option<String>,
    enqueued_at: Timestamp,
    delivery_count: u32,
    available_at: Timestamp,
    expires_at: Option<Timestamp>,
}

impl StoredMessage {
    fn from_message(message: &Message, message_id: MessageId, config: &InMemoryConfig) -> Self {
        let now = Timestamp::now();

        // Apply TTL: use message TTL if provided, otherwise use default from config
        let ttl = message.time_to_live.or(config.default_message_ttl);
        let expires_at = ttl.map(|ttl| Timestamp::from_datetime(now.as_datetime() + ttl));

        Self {
            message_id,
            body: message.body.clone(),
            attributes: message.attributes.clone(),
            session_id: message.session_id.clone(),
            correlation_id: message.correlation_id.clone(),
            enqueued_at: now,
            delivery_count: 0,
            available_at: now,
            expires_at,
        }
    }

    /// Check if message is expired based on TTL
    fn is_expired(&self) -> bool {
        if let Some(ref expires_at) = self.expires_at {
            Timestamp::now() >= *expires_at
        } else {
            false
        }
    }

    /// Check if message is available for receiving
    fn is_available(&self) -> bool {
        Timestamp::now() >= self.available_at
    }
}

/// A message currently being processed
#[allow(dead_code)]
struct InFlightMessage {
    message: StoredMessage,
    receipt_handle: String,
    lock_expires_at: Timestamp,
}

#[allow(dead_code)]
impl InFlightMessage {
    fn is_expired(&self) -> bool {
        Timestamp::now() >= self.lock_expires_at
    }
}

/// State tracking for a message session
struct SessionState {
    locked: bool,
    lock_expires_at: Option<Timestamp>,
    locked_by: Option<String>, // Session client ID
}

impl SessionState {
    fn new() -> Self {
        Self {
            locked: false,
            lock_expires_at: None,
            locked_by: None,
        }
    }

    fn is_locked(&self) -> bool {
        if !self.locked {
            return false;
        }

        // Check if lock has expired
        if let Some(ref expires_at) = self.lock_expires_at {
            if Timestamp::now() >= *expires_at {
                return false;
            }
        }

        true
    }
}

// ============================================================================
// InMemoryProvider
// ============================================================================

/// In-memory queue provider implementation
pub struct InMemoryProvider {
    storage: Arc<RwLock<QueueStorage>>,
}

impl InMemoryProvider {
    /// Create new in-memory provider with configuration
    pub fn new(config: InMemoryConfig) -> Self {
        Self {
            storage: Arc::new(RwLock::new(QueueStorage::new(config))),
        }
    }

    /// Helper method to accept a session and return a SessionClient.
    ///
    /// This is a convenience method for testing that wraps create_session_client.
    /// In production code, use QueueClient::accept_session() instead.
    pub async fn accept_session(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn crate::client::SessionClient>, QueueError> {
        use crate::client::SessionProvider;

        let provider = self.create_session_client(queue, session_id).await?;

        // Wrap in StandardSessionClient
        struct StandardSessionClient {
            provider: Box<dyn SessionProvider>,
        }

        #[async_trait]
        impl crate::client::SessionClient for StandardSessionClient {
            async fn receive_message(
                &self,
                timeout: Duration,
            ) -> Result<Option<ReceivedMessage>, QueueError> {
                self.provider.receive_message(timeout).await
            }

            async fn complete_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError> {
                self.provider.complete_message(&receipt).await
            }

            async fn abandon_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError> {
                self.provider.abandon_message(&receipt).await
            }

            async fn dead_letter_message(
                &self,
                receipt: ReceiptHandle,
                reason: String,
            ) -> Result<(), QueueError> {
                self.provider.dead_letter_message(&receipt, &reason).await
            }

            async fn renew_session_lock(&self) -> Result<(), QueueError> {
                self.provider.renew_session_lock().await
            }

            async fn close_session(&self) -> Result<(), QueueError> {
                self.provider.close_session().await
            }

            fn session_id(&self) -> &SessionId {
                self.provider.session_id()
            }

            fn session_expires_at(&self) -> Timestamp {
                self.provider.session_expires_at()
            }
        }

        Ok(Box::new(StandardSessionClient { provider }))
    }

    /// Return expired in-flight messages back to the queue
    fn return_expired_messages(queue: &mut InMemoryQueue) {
        let now = Timestamp::now();
        let mut expired_handles = Vec::new();

        // Find expired messages
        for (handle, inflight) in &queue.in_flight {
            if now >= inflight.lock_expires_at {
                expired_handles.push(handle.clone());
            }
        }

        // Return them to the queue
        for handle in expired_handles {
            if let Some(inflight) = queue.in_flight.remove(&handle) {
                let mut message = inflight.message;
                // Make immediately available
                message.available_at = now;
                queue.messages.push_back(message);
            }
        }
    }

    /// Clean up expired messages (based on TTL)
    fn clean_expired_messages(queue: &mut InMemoryQueue) {
        let mut i = 0;
        while i < queue.messages.len() {
            if queue.messages[i].is_expired() {
                // Remove expired message
                if let Some(expired_msg) = queue.messages.remove(i) {
                    // Move to DLQ if enabled, otherwise just discard
                    if queue.config.enable_dead_letter_queue {
                        queue.dead_letter.push_back(expired_msg);
                    }
                }
                // Don't increment i since we removed an element
            } else {
                i += 1;
            }
        }
    }

    /// Check if a session is locked
    fn is_session_locked(queue: &InMemoryQueue, session_id: &Option<SessionId>) -> bool {
        if let Some(ref sid) = session_id {
            if let Some(session_state) = queue.sessions.get(sid) {
                return session_state.is_locked();
            }
        }
        false
    }
}

impl Default for InMemoryProvider {
    fn default() -> Self {
        Self::new(InMemoryConfig::default())
    }
}

#[async_trait]
impl QueueProvider for InMemoryProvider {
    async fn send_message(
        &self,
        queue: &QueueName,
        message: &Message,
    ) -> Result<MessageId, QueueError> {
        // Validate message size (10MB for in-memory provider)
        let message_size = message.body.len();
        let max_size = self.provider_type().max_message_size();
        if message_size > max_size {
            return Err(QueueError::MessageTooLarge {
                size: message_size,
                max_size,
            });
        }

        // Generate message ID
        let message_id = MessageId::new();

        // Store message with config for default TTL
        let mut storage = self.storage.write().unwrap();
        let queue_state = storage.get_or_create_queue(queue);
        let stored_message =
            StoredMessage::from_message(message, message_id.clone(), &queue_state.config);
        queue_state.messages.push_back(stored_message);

        Ok(message_id)
    }

    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: &[Message],
    ) -> Result<Vec<MessageId>, QueueError> {
        // Validate batch size
        if messages.len() > self.max_batch_size() as usize {
            return Err(QueueError::BatchTooLarge {
                size: messages.len(),
                max_size: self.max_batch_size() as usize,
            });
        }

        // Validate individual message sizes and send all
        let mut message_ids = Vec::with_capacity(messages.len());
        for message in messages {
            let message_id = self.send_message(queue, message).await?;
            message_ids.push(message_id);
        }

        Ok(message_ids)
    }

    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        let start_time = std::time::Instant::now();
        let timeout_duration = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        loop {
            // Try to receive a message
            let received_message = {
                let mut storage = self.storage.write().unwrap();
                let queue_state = storage.get_or_create_queue(queue);

                // First, return any expired in-flight messages back to the queue
                Self::return_expired_messages(queue_state);

                // Clean up expired messages (move to DLQ or discard)
                Self::clean_expired_messages(queue_state);

                // Find first available message (not expired, visibility timeout passed, not in a locked session)
                let now = Timestamp::now();
                let message_index = queue_state.messages.iter().position(|msg| {
                    !msg.is_expired()
                        && msg.is_available()
                        && !Self::is_session_locked(queue_state, &msg.session_id)
                });

                if let Some(index) = message_index {
                    // Remove message from queue
                    let mut stored_message = queue_state.messages.remove(index).unwrap();

                    // Check if message should go to DLQ before delivery
                    if queue_state.config.enable_dead_letter_queue
                        && stored_message.delivery_count >= queue_state.config.max_delivery_count
                    {
                        // Move to DLQ instead of delivering
                        queue_state.dead_letter.push_back(stored_message);
                        None
                    } else {
                        // Increment delivery count
                        stored_message.delivery_count += 1;

                        // Create receipt handle
                        let receipt_handle_str = uuid::Uuid::new_v4().to_string();
                        let lock_expires_at =
                            Timestamp::from_datetime(now.as_datetime() + Duration::seconds(30));
                        let receipt_handle = ReceiptHandle::new(
                            receipt_handle_str.clone(),
                            lock_expires_at,
                            ProviderType::InMemory,
                        );

                        // Create received message
                        let received_message = ReceivedMessage {
                            message_id: stored_message.message_id.clone(),
                            body: stored_message.body.clone(),
                            attributes: stored_message.attributes.clone(),
                            session_id: stored_message.session_id.clone(),
                            correlation_id: stored_message.correlation_id.clone(),
                            receipt_handle: receipt_handle.clone(),
                            delivery_count: stored_message.delivery_count,
                            first_delivered_at: stored_message.enqueued_at,
                            delivered_at: now,
                        };

                        // Move to in-flight
                        let inflight = InFlightMessage {
                            message: stored_message,
                            receipt_handle: receipt_handle_str.clone(),
                            lock_expires_at,
                        };
                        queue_state.in_flight.insert(receipt_handle_str, inflight);

                        Some(received_message)
                    }
                } else {
                    None
                }
            }; // Lock is released here

            if let Some(msg) = received_message {
                return Ok(Some(msg));
            }

            // No message available - check timeout
            if start_time.elapsed() >= timeout_duration {
                return Ok(None);
            }

            // Small sleep before retry
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError> {
        let mut messages = Vec::new();
        let start_time = std::time::Instant::now();
        let timeout_duration = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        while messages.len() < max_messages as usize {
            let remaining_timeout = timeout_duration
                .checked_sub(start_time.elapsed())
                .unwrap_or(std::time::Duration::ZERO);

            if remaining_timeout.is_zero() {
                break;
            }

            let remaining_duration =
                Duration::from_std(remaining_timeout).unwrap_or(Duration::zero());
            let received = self.receive_message(queue, remaining_duration).await?;

            match received {
                Some(msg) => messages.push(msg),
                None => break,
            }
        }

        Ok(messages)
    }

    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        let mut storage = self.storage.write().unwrap();
        let now = Timestamp::now();

        // Find the queue containing this receipt
        for queue in storage.queues.values_mut() {
            if let Some(inflight) = queue.in_flight.get(receipt.handle()) {
                // Check if receipt is expired
                if inflight.lock_expires_at <= now {
                    queue.in_flight.remove(receipt.handle());
                    return Err(QueueError::MessageNotFound {
                        receipt: receipt.handle().to_string(),
                    });
                }

                // Remove from in-flight (permanently deletes the message)
                queue.in_flight.remove(receipt.handle());
                return Ok(());
            }
        }

        // Receipt not found in any queue
        Err(QueueError::MessageNotFound {
            receipt: receipt.handle().to_string(),
        })
    }

    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        let mut storage = self.storage.write().unwrap();
        let now = Timestamp::now();

        // Find the queue containing this receipt
        for queue in storage.queues.values_mut() {
            if let Some(inflight) = queue.in_flight.remove(receipt.handle()) {
                // Check if receipt is expired
                if inflight.lock_expires_at <= now {
                    return Err(QueueError::MessageNotFound {
                        receipt: receipt.handle().to_string(),
                    });
                }

                // Return message to queue with immediate availability
                let mut returned_message = inflight.message;
                returned_message.available_at = now;

                // Add back to queue (front for sessions to maintain ordering, back for others)
                if returned_message.session_id.is_some() {
                    queue.messages.push_front(returned_message);
                } else {
                    queue.messages.push_back(returned_message);
                }

                return Ok(());
            }
        }

        // Receipt not found in any queue
        Err(QueueError::MessageNotFound {
            receipt: receipt.handle().to_string(),
        })
    }

    async fn dead_letter_message(
        &self,
        _receipt: &ReceiptHandle,
        _reason: &str,
    ) -> Result<(), QueueError> {
        // TODO: Implement in subtask 10.4
        unimplemented!("dead_letter_message will be implemented in subtask 10.4")
    }

    async fn create_session_client(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionProvider>, QueueError> {
        // Determine which session to use
        let target_session_id = if let Some(sid) = session_id {
            sid
        } else {
            // Find first available session (one with messages but not locked)
            let storage = self.storage.read().unwrap();
            let queue_state =
                storage
                    .queues
                    .get(queue)
                    .ok_or_else(|| QueueError::QueueNotFound {
                        queue_name: queue.as_str().to_string(),
                    })?;

            // Find first session with available messages
            let mut sessions_with_messages = std::collections::HashSet::new();
            for msg in &queue_state.messages {
                if let Some(ref sid) = msg.session_id {
                    sessions_with_messages.insert(sid.clone());
                }
            }

            // Check which sessions are not locked
            let mut found_session = None;
            for sid in sessions_with_messages {
                let session_state = queue_state.sessions.get(&sid);
                if session_state.map(|s| !s.is_locked()).unwrap_or(true) {
                    // Session has messages and is not locked
                    found_session = Some(sid);
                    break;
                }
            }

            found_session.ok_or_else(|| QueueError::SessionNotFound {
                session_id: "<any>".to_string(),
            })?
        };

        // Try to acquire lock on the session
        let mut storage = self.storage.write().unwrap();
        let queue_state = storage.get_or_create_queue(queue);
        let config = queue_state.config.clone();

        // Check if session is already locked
        let session_state = queue_state
            .sessions
            .entry(target_session_id.clone())
            .or_insert_with(SessionState::new);

        if session_state.is_locked() {
            let locked_until = session_state.lock_expires_at.unwrap_or_else(Timestamp::now);
            return Err(QueueError::SessionLocked {
                session_id: target_session_id.as_str().to_string(),
                locked_until,
            });
        }

        // Acquire lock
        let lock_duration = config.session_lock_duration;
        let now = Timestamp::now();
        let lock_expires_at = Timestamp::from_datetime(now.as_datetime() + lock_duration);
        let client_id = uuid::Uuid::new_v4().to_string();

        session_state.locked = true;
        session_state.lock_expires_at = Some(lock_expires_at);
        session_state.locked_by = Some(client_id.clone());

        // Create session provider
        Ok(Box::new(InMemorySessionProvider::new(
            self.storage.clone(),
            queue.clone(),
            target_session_id,
            client_id,
            lock_expires_at,
        )))
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::InMemory
    }

    fn supports_sessions(&self) -> SessionSupport {
        SessionSupport::Native
    }

    fn supports_batching(&self) -> bool {
        true
    }

    fn max_batch_size(&self) -> u32 {
        100
    }
}

// ============================================================================
// InMemorySessionProvider
// ============================================================================

/// In-memory session provider implementation
pub struct InMemorySessionProvider {
    storage: Arc<RwLock<QueueStorage>>,
    queue_name: QueueName,
    session_id: SessionId,
    client_id: String,
    lock_expires_at: Timestamp,
}

impl InMemorySessionProvider {
    fn new(
        storage: Arc<RwLock<QueueStorage>>,
        queue_name: QueueName,
        session_id: SessionId,
        client_id: String,
        lock_expires_at: Timestamp,
    ) -> Self {
        Self {
            storage,
            queue_name,
            session_id,
            client_id,
            lock_expires_at,
        }
    }
}

#[async_trait]
impl SessionProvider for InMemorySessionProvider {
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        // Check if we still hold the lock
        {
            let storage = self.storage.read().unwrap();
            if let Some(queue_state) = storage.queues.get(&self.queue_name) {
                if let Some(session_state) = queue_state.sessions.get(&self.session_id) {
                    if !session_state.is_locked()
                        || session_state.locked_by.as_ref() != Some(&self.client_id)
                    {
                        return Err(QueueError::SessionLocked {
                            session_id: self.session_id.as_str().to_string(),
                            locked_until: session_state
                                .lock_expires_at
                                .unwrap_or_else(Timestamp::now),
                        });
                    }
                }
            }
        }

        // Use a similar approach to regular receive, but filtered for this session
        let start_time = std::time::Instant::now();
        let timeout_duration = timeout
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(30));

        loop {
            // Try to receive a message for this session
            let received_message = {
                let mut storage = self.storage.write().unwrap();
                if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
                    // Clean up expired messages
                    InMemoryProvider::clean_expired_messages(queue_state);

                    // Find first available message for this session
                    let now = Timestamp::now();
                    let message_index = queue_state.messages.iter().position(|msg| {
                        !msg.is_expired()
                            && msg.is_available()
                            && msg.session_id.as_ref() == Some(&self.session_id)
                    });

                    if let Some(index) = message_index {
                        // Remove message from queue
                        let mut message = queue_state.messages.remove(index).unwrap();

                        // Generate receipt handle
                        let receipt = uuid::Uuid::new_v4().to_string();

                        // Calculate visibility timeout
                        let visibility_timeout = Duration::seconds(30);
                        let lock_expires_at =
                            Timestamp::from_datetime(now.as_datetime() + visibility_timeout);

                        // Track delivery
                        message.delivery_count += 1;
                        let first_delivered_at = if message.delivery_count == 1 {
                            now
                        } else {
                            message.enqueued_at
                        };

                        // Add to in-flight
                        queue_state.in_flight.insert(
                            receipt.clone(),
                            InFlightMessage {
                                message: message.clone(),
                                receipt_handle: receipt.clone(),
                                lock_expires_at,
                            },
                        );

                        // Build received message
                        Some(ReceivedMessage {
                            message_id: message.message_id.clone(),
                            body: message.body.clone(),
                            attributes: message.attributes.clone(),
                            receipt_handle: ReceiptHandle::new(
                                receipt,
                                lock_expires_at,
                                ProviderType::InMemory,
                            ),
                            session_id: message.session_id.clone(),
                            correlation_id: message.correlation_id.clone(),
                            delivery_count: message.delivery_count,
                            first_delivered_at,
                            delivered_at: now,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(msg) = received_message {
                return Ok(Some(msg));
            }

            // Check timeout
            if start_time.elapsed() >= timeout_duration {
                return Ok(None);
            }

            // Brief sleep before retry
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Verify we still hold the session lock
        {
            let storage = self.storage.read().unwrap();
            if let Some(queue_state) = storage.queues.get(&self.queue_name) {
                if let Some(session_state) = queue_state.sessions.get(&self.session_id) {
                    if !session_state.is_locked()
                        || session_state.locked_by.as_ref() != Some(&self.client_id)
                    {
                        return Err(QueueError::SessionLocked {
                            session_id: self.session_id.as_str().to_string(),
                            locked_until: session_state
                                .lock_expires_at
                                .unwrap_or_else(Timestamp::now),
                        });
                    }
                }
            }
        }

        // Delegate to storage to remove message
        let mut storage = self.storage.write().unwrap();
        if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
            if queue_state.in_flight.remove(receipt.handle()).is_some() {
                return Ok(());
            }
        }

        Err(QueueError::MessageNotFound {
            receipt: receipt.handle().to_string(),
        })
    }

    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError> {
        // Verify we still hold the session lock
        {
            let storage = self.storage.read().unwrap();
            if let Some(queue_state) = storage.queues.get(&self.queue_name) {
                if let Some(session_state) = queue_state.sessions.get(&self.session_id) {
                    if !session_state.is_locked()
                        || session_state.locked_by.as_ref() != Some(&self.client_id)
                    {
                        return Err(QueueError::SessionLocked {
                            session_id: self.session_id.as_str().to_string(),
                            locked_until: session_state
                                .lock_expires_at
                                .unwrap_or_else(Timestamp::now),
                        });
                    }
                }
            }
        }

        // Return message to queue
        let mut storage = self.storage.write().unwrap();
        if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
            if let Some(inflight) = queue_state.in_flight.remove(receipt.handle()) {
                let mut message = inflight.message;

                // Check if max delivery count reached
                if message.delivery_count >= queue_state.config.max_delivery_count {
                    // Move to DLQ if enabled
                    if queue_state.config.enable_dead_letter_queue {
                        queue_state.dead_letter.push_back(message);
                        return Ok(());
                    }
                }

                // Make immediately available and add back to front for session ordering
                message.available_at = Timestamp::now();
                queue_state.messages.push_front(message);
                return Ok(());
            }
        }

        Err(QueueError::MessageNotFound {
            receipt: receipt.handle().to_string(),
        })
    }

    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        _reason: &str,
    ) -> Result<(), QueueError> {
        // Verify we still hold the session lock
        {
            let storage = self.storage.read().unwrap();
            if let Some(queue_state) = storage.queues.get(&self.queue_name) {
                if let Some(session_state) = queue_state.sessions.get(&self.session_id) {
                    if !session_state.is_locked()
                        || session_state.locked_by.as_ref() != Some(&self.client_id)
                    {
                        return Err(QueueError::SessionLocked {
                            session_id: self.session_id.as_str().to_string(),
                            locked_until: session_state
                                .lock_expires_at
                                .unwrap_or_else(Timestamp::now),
                        });
                    }
                }
            }
        }

        // Move message to DLQ
        let mut storage = self.storage.write().unwrap();
        if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
            if let Some(inflight) = queue_state.in_flight.remove(receipt.handle()) {
                queue_state.dead_letter.push_back(inflight.message);
                return Ok(());
            }
        }

        Err(QueueError::MessageNotFound {
            receipt: receipt.handle().to_string(),
        })
    }

    async fn renew_session_lock(&self) -> Result<(), QueueError> {
        let mut storage = self.storage.write().unwrap();
        if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
            if let Some(session_state) = queue_state.sessions.get_mut(&self.session_id) {
                // Verify we hold the lock
                if session_state.locked_by.as_ref() != Some(&self.client_id) {
                    return Err(QueueError::SessionLocked {
                        session_id: self.session_id.as_str().to_string(),
                        locked_until: session_state.lock_expires_at.unwrap_or_else(Timestamp::now),
                    });
                }

                // Renew lock
                let lock_duration = queue_state.config.session_lock_duration;
                let new_expires_at =
                    Timestamp::from_datetime(Timestamp::now().as_datetime() + lock_duration);
                session_state.lock_expires_at = Some(new_expires_at);

                return Ok(());
            }
        }

        Err(QueueError::SessionNotFound {
            session_id: self.session_id.as_str().to_string(),
        })
    }

    async fn close_session(&self) -> Result<(), QueueError> {
        let mut storage = self.storage.write().unwrap();
        if let Some(queue_state) = storage.queues.get_mut(&self.queue_name) {
            if let Some(session_state) = queue_state.sessions.get_mut(&self.session_id) {
                // Release lock
                session_state.locked = false;
                session_state.lock_expires_at = None;
                session_state.locked_by = None;
                return Ok(());
            }
        }

        Ok(()) // Session already released or doesn't exist - that's fine
    }

    fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    fn session_expires_at(&self) -> Timestamp {
        self.lock_expires_at
    }
}
