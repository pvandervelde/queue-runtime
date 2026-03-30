//! # Queue Runtime
//!
//! Multi-provider queue runtime for reliable message processing with support for
//! Azure Service Bus, AWS SQS, RabbitMQ, NATS, and in-memory implementations.
//!
//! This library provides:
//! - Provider-agnostic queue operations
//! - Session-based ordered message processing
//! - Dead letter queue support
//! - Retry policies with exponential backoff
//! - Batch operations where supported
//!
//! ## Module Organization
//!
//! - [`error`] - Error types for all queue operations
//! - [`message`] - Message structures and receipt handles
//! - [`provider`] - Provider types and configuration
//! - [`client`] - Client traits and implementations
//!
//! See specs/interfaces/queue-client.md for complete specification.

// Module declarations
pub mod client;
pub mod error;
pub mod message;
pub mod provider;
pub mod providers;
pub mod sessions;

// Re-export commonly used types at crate root for convenience
pub use client::{
    QueueClient, QueueClientFactory, QueueProvider, SessionClient, SessionProvider,
    StandardQueueClient,
};
pub use error::{ConfigurationError, QueueError, SerializationError, ValidationError};
pub use message::{
    Message, MessageId, QueueName, ReceiptHandle, ReceiveOptions, ReceivedMessage, SendOptions,
    SessionId, Timestamp,
};
pub use provider::{
    AwsSqsConfig, AzureServiceBusConfig, InMemoryConfig, NatsConfig, ProviderConfig, ProviderType,
    QueueConfig, RabbitMqConfig, SessionSupport,
};
pub use providers::{
    AzureAuthMethod, AzureServiceBusProvider, AzureSessionProvider, InMemoryProvider,
    InMemorySessionProvider, NatsError, NatsProvider, NatsSessionProvider, RabbitMqError,
    RabbitMqProvider, RabbitMqSessionProvider,
};
pub use sessions::{
    CompositeKeyStrategy, FallbackStrategy, NoOrderingStrategy, SessionAffinity,
    SessionAffinityTracker, SessionInfo, SessionKeyExtractor, SessionKeyGenerator,
    SessionLifecycleConfig, SessionLifecycleManager, SessionLock, SessionLockManager,
    SingleFieldStrategy,
};
