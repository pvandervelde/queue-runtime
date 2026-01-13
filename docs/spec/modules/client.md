# Queue Client Module

The queue client module provides the core traits and factory for queue operations, defining provider-agnostic interfaces that work consistently across Azure Service Bus, AWS SQS, and in-memory implementations.

## Overview

This module establishes a three-tier trait hierarchy:

1. **QueueClient**: High-level interface for applications
2. **SessionClient**: High-level interface for session-based processing
3. **QueueProvider**: Low-level interface implemented by provider adapters

Applications interact with `QueueClient` and `SessionClient` traits, which are implemented by `StandardQueueClient` and `StandardSessionClient` that wrap provider implementations.

## Core Traits

### QueueClient

The main interface for queue operations across all providers. Applications should depend on this trait, not concrete implementations.

**Trait Requirements**:

- `async_trait` for async methods
- `Send + Sync` for thread-safe sharing across async tasks
- All operations return `Result<T, QueueError>` for consistent error handling

**Message Operations**:

```rust
/// Send single message to queue
async fn send_message(
    &self,
    queue: &QueueName,
    message: Message,
) -> Result<MessageId, QueueError>;

/// Send multiple messages in batch (if provider supports batching)
async fn send_messages(
    &self,
    queue: &QueueName,
    messages: Vec<Message>,
) -> Result<Vec<MessageId>, QueueError>;

/// Receive single message from queue with timeout
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
```

**Message Lifecycle Operations**:

```rust
/// Mark message as successfully processed (removes from queue)
async fn complete_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

/// Return message to queue for retry (makes visible again)
async fn abandon_message(&self, receipt: ReceiptHandle) -> Result<(), QueueError>;

/// Send message to dead letter queue (permanent failure)
async fn dead_letter_message(
    &self,
    receipt: ReceiptHandle,
    reason: String,
) -> Result<(), QueueError>;
```

**Session Operations**:

```rust
/// Accept session for ordered processing
///
/// - If session_id is Some, attempts to accept that specific session
/// - If session_id is None, accepts next available session
/// - Returns SessionClient for processing messages in order
async fn accept_session(
    &self,
    queue: &QueueName,
    session_id: Option<SessionId>,
) -> Result<Box<dyn SessionClient>, QueueError>;
```

**Provider Capability Queries**:

```rust
/// Get provider type (Azure, Aws, InMemory)
fn provider_type(&self) -> ProviderType;

/// Check if provider supports sessions
fn supports_sessions(&self) -> bool;

/// Check if provider supports batch operations
fn supports_batching(&self) -> bool;
```

### SessionClient

Interface for session-based ordered message processing. Messages within a session are guaranteed to be delivered in FIFO order.

**Trait Requirements**:

- `async_trait` for async methods
- `Send + Sync` for thread-safe sharing across async tasks
- Session lock is held until `close_session()` is called or session expires

**Session Message Operations**:

```rust
/// Receive message from session (maintains FIFO order)
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
```

**Session Management**:

```rust
/// Renew session lock to prevent timeout
///
/// Must be called periodically during long-running processing
/// to maintain exclusive access to the session
async fn renew_session_lock(&self) -> Result<(), QueueError>;

/// Close session and release lock
///
/// Allows other consumers to accept this session
async fn close_session(&self) -> Result<(), QueueError>;

/// Get session ID
fn session_id(&self) -> &SessionId;

/// Get session expiry time
fn session_expires_at(&self) -> Timestamp;
```

### QueueProvider

Low-level trait implemented by provider adapters (Azure, AWS, InMemory). Applications should NOT depend on this trait directly - use `QueueClient` instead.

**Trait Requirements**:

- `async_trait` for async methods
- `Send + Sync` for thread-safe sharing
- Takes references to parameters (unlike QueueClient which takes ownership)

**Provider Operations**:

```rust
/// Send single message
async fn send_message(
    &self,
    queue: &QueueName,
    message: &Message,
) -> Result<MessageId, QueueError>;

/// Send multiple messages (batch)
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

/// Create session client for ordered processing
async fn create_session_client(
    &self,
    queue: &QueueName,
    session_id: Option<SessionId>,
) -> Result<Box<dyn SessionProvider>, QueueError>;
```

**Provider Capability Reporting**:

```rust
/// Get provider type
fn provider_type(&self) -> ProviderType;

/// Report session support capability
fn supports_sessions(&self) -> SessionSupport;

/// Check if batch operations are supported
fn supports_batching(&self) -> bool;

/// Get maximum batch size
fn max_batch_size(&self) -> u32;
```

### SessionProvider

Low-level trait for session-based operations, implemented by provider adapters. Applications should NOT depend on this trait directly - use `SessionClient` instead.

**Trait Requirements**:

- `async_trait` for async methods
- `Send + Sync` for thread-safe sharing
- Takes references to parameters

**Session Provider Operations**:

```rust
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

/// Get session expiry timestamp
fn session_expires_at(&self) -> Timestamp;
```

## StandardQueueClient

Concrete implementation of `QueueClient` trait that wraps a `QueueProvider` implementation.

**Responsibilities**:

- Adapt `QueueProvider` low-level interface to `QueueClient` high-level interface
- Handle ownership conversions (QueueClient takes ownership, QueueProvider takes references)
- Wrap `SessionProvider` in `StandardSessionClient` for consistency

**Construction**:

```rust
impl StandardQueueClient {
    /// Create new client wrapping a provider
    pub fn new(provider: Arc<dyn QueueProvider>) -> Self;
}
```

**Design Notes**:

- Holds `Arc<dyn QueueProvider>` for shared ownership
- Implements `Clone` to enable sharing across async tasks
- All trait methods delegate to underlying provider

## StandardSessionClient

Concrete implementation of `SessionClient` trait that wraps a `SessionProvider` implementation.

**Responsibilities**:

- Adapt `SessionProvider` low-level interface to `SessionClient` high-level interface
- Handle ownership conversions
- Maintain session metadata (ID, expiry timestamp)

**Construction**:

```rust
impl StandardSessionClient {
    /// Create new session client wrapping a provider
    pub fn new(provider: Box<dyn SessionProvider>) -> Self;
}
```

**Design Notes**:

- Holds `Box<dyn SessionProvider>` for owned provider instance
- NOT clonable (session ownership is exclusive)
- All trait methods delegate to underlying provider

## QueueClientFactory

Factory for creating `QueueClient` instances from configuration.

**Responsibilities**:

- Parse `QueueConfig` to determine provider type
- Instantiate appropriate provider (Azure, AWS, InMemory)
- Wrap provider in `StandardQueueClient`
- Validate configuration before creating provider

**Factory Method**:

```rust
impl QueueClientFactory {
    /// Create queue client from configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Queue configuration specifying provider and settings
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Configuration is invalid
    /// - Provider initialization fails
    /// - Authentication fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = QueueConfig {
    ///     provider: ProviderConfig::InMemory(Default::default()),
    ///     retry_policy: Default::default(),
    ///     timeout: Default::default(),
    /// };
    ///
    /// let client = QueueClientFactory::create_client(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create_client(config: QueueConfig) -> Result<Arc<dyn QueueClient>, QueueError>;
}
```

## Usage Patterns

### Basic Send/Receive

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, QueueName, Message};
use bytes::Bytes;
use chrono::Duration;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// Create client from configuration
let config = QueueConfig::default();
let client = QueueClientFactory::create_client(config).await?;

// Send a message
let queue = QueueName::new("my-queue".to_string())?;
let message = Message::new(Bytes::from("Hello, World!"));
let message_id = client.send_message(&queue, message).await?;

// Receive a message
let received = client.receive_message(&queue, Duration::seconds(30)).await?;

if let Some(msg) = received {
    // Process the message
    println!("Received: {:?}", msg.body);

    // Mark as complete
    client.complete_message(msg.receipt_handle).await?;
}
# Ok(())
# }
```

### Session-Based Processing

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, QueueName};
use chrono::Duration;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = QueueConfig::default();
let client = QueueClientFactory::create_client(config).await?;
let queue = QueueName::new("my-queue".to_string())?;

// Accept next available session
let session = client.accept_session(&queue, None).await?;

// Process messages in order
while let Some(msg) = session.receive_message(Duration::seconds(30)).await? {
    // Messages arrive in FIFO order
    println!("Processing: {:?}", msg.body);

    // Complete message
    session.complete_message(msg.receipt_handle).await?;
}

// Close session
session.close_session().await?;
# Ok(())
# }
```

### Batch Operations

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, QueueName, Message};
use bytes::Bytes;
use chrono::Duration;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = QueueConfig::default();
let client = QueueClientFactory::create_client(config).await?;
let queue = QueueName::new("my-queue".to_string())?;

// Send batch (if provider supports batching)
if client.supports_batching() {
    let messages = vec![
        Message::new(Bytes::from("Message 1")),
        Message::new(Bytes::from("Message 2")),
        Message::new(Bytes::from("Message 3")),
    ];

    let message_ids = client.send_messages(&queue, messages).await?;
    println!("Sent {} messages", message_ids.len());
}

// Receive batch
let messages = client.receive_messages(&queue, 10, Duration::seconds(30)).await?;
for msg in messages {
    // Process each message
    client.complete_message(msg.receipt_handle).await?;
}
# Ok(())
# }
```

### Error Handling

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, QueueName, Message, QueueError};
use bytes::Bytes;
use chrono::Duration;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let config = QueueConfig::default();
let client = QueueClientFactory::create_client(config).await?;
let queue = QueueName::new("my-queue".to_string())?;

let message = Message::new(Bytes::from("data"));

match client.send_message(&queue, message).await {
    Ok(message_id) => {
        println!("Sent: {}", message_id);
    }
    Err(QueueError::Timeout) => {
        // Retry with exponential backoff
        eprintln!("Timeout, will retry");
    }
    Err(QueueError::Authentication(msg)) => {
        // Fatal error, don't retry
        eprintln!("Auth failed: {}", msg);
        return Err(msg.into());
    }
    Err(e) => {
        // Handle other errors
        eprintln!("Error: {}", e);
    }
}
# Ok(())
# }
```

## Behavioral Assertions

### QueueClient Assertions

1. **send_message must generate unique MessageId**: Each message sent returns a unique identifier
2. **receive_message with no messages returns None**: Empty queue returns None after timeout
3. **complete_message must remove message from queue**: Completed messages are not redelivered
4. **abandon_message must make message visible again**: Abandoned messages can be received by other consumers
5. **dead_letter_message must move message to DLQ**: Message removed from main queue and sent to dead letter queue
6. **accept_session with Some(id) must accept specific session**: Targets specific session for processing
7. **accept_session with None must accept next available session**: Accepts any session with messages

### SessionClient Assertions

1. **receive_message must return messages in FIFO order**: Messages within session processed in send order
2. **session_id must return accepted session ID**: Returns the session identifier for this client
3. **session_expires_at must return valid timestamp**: Returns future timestamp indicating session lock expiry
4. **renew_session_lock must extend expiry time**: Session lock extended to prevent timeout
5. **close_session must release session lock**: Other consumers can accept session after close

### Provider Capability Assertions

1. **supports_sessions must match provider capability**: Returns true only for providers with session support
2. **supports_batching must match provider capability**: Returns true only for providers with batch operations
3. **provider_type must return correct enum variant**: Identifies provider (Azure, Aws, InMemory)

## Testing Strategy

### Unit Testing

- Mock `QueueProvider` implementations for testing `StandardQueueClient`
- Mock `SessionProvider` implementations for testing `StandardSessionClient`
- Test factory with in-memory configuration for fast tests
- Verify error handling and retry logic

### Integration Testing

- Test against real Azure Service Bus (requires Azure credentials)
- Test against real AWS SQS (requires AWS credentials)
- Test against LocalStack for AWS integration without real AWS account
- Verify session ordering across provider implementations

### Contract Testing

- All providers must pass same test suite
- Verify behavioral assertions against each provider
- Test edge cases (empty queues, session timeouts, lock expiry)
- Test error scenarios (network failures, authentication errors)
