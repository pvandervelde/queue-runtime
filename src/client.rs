//! Client traits and implementations for queue operations.

use crate::error::QueueError;
use crate::message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceivedMessage, SessionId, Timestamp,
};
use crate::provider::{InMemoryConfig, ProviderConfig, ProviderType, QueueConfig, SessionSupport};
use crate::providers::InMemoryProvider;
use async_trait::async_trait;
use chrono::Duration;

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

/// Main interface for queue operations across all providers
#[async_trait]
pub trait QueueClient: Send + Sync {
    /// Send single message to queue
    async fn send_message(
        &self,
        queue: &QueueName,
        message: Message,
    ) -> Result<MessageId, QueueError>;

    /// Send multiple messages in batch (if supported)
    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: Vec<Message>,
    ) -> Result<Vec<MessageId>, QueueError>;

    /// Receive single message from queue
    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError>;

    /// Receive multiple messages from queue
    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError>;

    /// Mark message as successfully processed
    async fn complete_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

    /// Return message to queue for retry
    async fn abandon_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

    /// Send message to dead letter queue
    async fn dead_letter_message(
        &self,
        receipt: ReceiptHandle,
        reason: String,
    ) -> Result<(), QueueError>;

    /// Accept session for ordered processing
    async fn accept_session(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionClient>, QueueError>;

    /// Get provider type
    fn provider_type(&self) -> ProviderType;

    /// Check if provider supports sessions
    fn supports_sessions(&self) -> bool;

    /// Check if provider supports batch operations
    fn supports_batching(&self) -> bool;
}

/// Interface for session-based ordered message processing
#[async_trait]
pub trait SessionClient: Send + Sync {
    /// Receive message from session (maintains order)
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError>;

    /// Complete message in session
    async fn complete_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

    /// Abandon message in session
    async fn abandon_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

    /// Send message to dead letter queue
    async fn dead_letter_message(
        &self,
        receipt: ReceiptHandle,
        reason: String,
    ) -> Result<(), QueueError>;

    /// Renew session lock to prevent timeout
    async fn renew_session_lock(&self) -> Result<(), QueueError>;

    /// Close session and release lock
    async fn close_session(&self) -> Result<(), QueueError>;

    /// Get session ID
    fn session_id(&self) -> &SessionId;

    /// Get session expiry time
    fn session_expires_at(&self) -> Timestamp;
}

/// Interface implemented by specific queue providers (Azure, AWS, etc.)
#[async_trait]
pub trait QueueProvider: Send + Sync {
    /// Send single message
    async fn send_message(
        &self,
        queue: &QueueName,
        message: &Message,
    ) -> Result<MessageId, QueueError>;

    /// Send multiple messages
    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: &[Message],
    ) -> Result<Vec<MessageId>, QueueError>;

    /// Receive single message
    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError>;

    /// Receive multiple messages
    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError>;

    /// Complete message processing
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError>;

    /// Abandon message for retry
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError>;

    /// Send to dead letter queue
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError>;

    /// Create session client
    async fn create_session_client(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionProvider>, QueueError>;

    /// Get provider type
    fn provider_type(&self) -> ProviderType;

    /// Get session support level
    fn supports_sessions(&self) -> SessionSupport;

    /// Check batch operation support
    fn supports_batching(&self) -> bool;

    /// Get maximum batch size
    fn max_batch_size(&self) -> u32;
}

/// Interface implemented by provider-specific session implementations
#[async_trait]
pub trait SessionProvider: Send + Sync {
    /// Receive message from session
    async fn receive_message(
        &self,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError>;

    /// Complete message
    async fn complete_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError>;

    /// Abandon message
    async fn abandon_message(&self, receipt: &ReceiptHandle) -> Result<(), QueueError>;

    /// Send to dead letter queue
    async fn dead_letter_message(
        &self,
        receipt: &ReceiptHandle,
        reason: &str,
    ) -> Result<(), QueueError>;

    /// Renew session lock
    async fn renew_session_lock(&self) -> Result<(), QueueError>;

    /// Close session
    async fn close_session(&self) -> Result<(), QueueError>;

    /// Get session ID
    fn session_id(&self) -> &SessionId;

    /// Get session expiry time
    fn session_expires_at(&self) -> Timestamp;
}

/// Factory for creating queue clients with appropriate providers
pub struct QueueClientFactory;

impl QueueClientFactory {
    /// Create queue client from configuration
    pub async fn create_client(config: QueueConfig) -> Result<Box<dyn QueueClient>, QueueError> {
        // Clone config for client since we need to move parts for provider
        let client_config = config.clone();

        // Create provider based on configuration
        let provider: Box<dyn QueueProvider> = match config.provider {
            ProviderConfig::InMemory(in_memory_config) => {
                Box::new(InMemoryProvider::new(in_memory_config))
            }
            ProviderConfig::AzureServiceBus(azure_config) => {
                let azure_provider = crate::providers::AzureServiceBusProvider::new(azure_config)
                    .await
                    .map_err(|e| e.to_queue_error())?;
                Box::new(azure_provider)
            }
            ProviderConfig::AwsSqs(aws_config) => {
                let aws_provider = crate::providers::AwsSqsProvider::new(aws_config)
                    .await
                    .map_err(|e| e.to_queue_error())?;
                Box::new(aws_provider)
            }
        };

        // Wrap provider in StandardQueueClient
        Ok(Box::new(StandardQueueClient::new(provider, client_config)))
    }

    /// Create test client with in-memory provider
    pub fn create_test_client() -> Box<dyn QueueClient> {
        let provider = InMemoryProvider::new(InMemoryConfig::default());
        let config = QueueConfig::default();
        Box::new(StandardQueueClient::new(Box::new(provider), config))
    }
}

/// Standard queue client implementation
pub struct StandardQueueClient {
    provider: Box<dyn QueueProvider>,
    #[allow(dead_code)] // Will be used for retry logic and timeouts in future
    config: QueueConfig,
}

impl StandardQueueClient {
    /// Create new standard queue client with provider
    pub fn new(provider: Box<dyn QueueProvider>, config: QueueConfig) -> Self {
        Self { provider, config }
    }
}

#[async_trait]
impl QueueClient for StandardQueueClient {
    async fn send_message(
        &self,
        queue: &QueueName,
        message: Message,
    ) -> Result<MessageId, QueueError> {
        self.provider.send_message(queue, &message).await
    }

    async fn send_messages(
        &self,
        queue: &QueueName,
        messages: Vec<Message>,
    ) -> Result<Vec<MessageId>, QueueError> {
        // Pass slice of messages to provider
        self.provider.send_messages(queue, &messages).await
    }

    async fn receive_message(
        &self,
        queue: &QueueName,
        timeout: Duration,
    ) -> Result<Option<ReceivedMessage>, QueueError> {
        self.provider.receive_message(queue, timeout).await
    }

    async fn receive_messages(
        &self,
        queue: &QueueName,
        max_messages: u32,
        timeout: Duration,
    ) -> Result<Vec<ReceivedMessage>, QueueError> {
        self.provider
            .receive_messages(queue, max_messages, timeout)
            .await
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

    async fn accept_session(
        &self,
        queue: &QueueName,
        session_id: Option<SessionId>,
    ) -> Result<Box<dyn SessionClient>, QueueError> {
        let session_provider = self
            .provider
            .create_session_client(queue, session_id)
            .await?;
        Ok(Box::new(StandardSessionClient::new(session_provider)))
    }

    fn provider_type(&self) -> ProviderType {
        self.provider.provider_type()
    }

    fn supports_sessions(&self) -> bool {
        matches!(
            self.provider.supports_sessions(),
            SessionSupport::Native | SessionSupport::Emulated
        )
    }

    fn supports_batching(&self) -> bool {
        self.provider.supports_batching()
    }
}

/// Standard session client implementation
struct StandardSessionClient {
    provider: Box<dyn SessionProvider>,
}

impl StandardSessionClient {
    fn new(provider: Box<dyn SessionProvider>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl SessionClient for StandardSessionClient {
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
