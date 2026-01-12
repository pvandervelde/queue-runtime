# Message Types Module

The message types module defines the domain identifiers, message structures, and serialization patterns used throughout the queue runtime library.

## Overview

This module provides **domain-agnostic** message types that work with any content. Unlike many queue libraries that assume specific message formats (JSON, Protobuf, etc.), this library treats message bodies as opaque bytes, allowing applications to use any serialization format.

## Core Domain Identifiers

### QueueName

Validated queue name with length and character restrictions enforced at construction time.

**Type Definition**:

```rust
pub struct QueueName(String);
```

**Validation Rules**:

- Length: 1-260 characters
- Characters: ASCII alphanumeric, hyphens, underscores only
- No leading/trailing hyphens
- No consecutive hyphens

**Construction**:

```rust
/// Create new queue name with validation
pub fn new(name: String) -> Result<Self, ValidationError>;

/// Create queue name with prefix
pub fn with_prefix(prefix: &str, base_name: &str) -> Result<Self, ValidationError>;

/// Get queue name as string
pub fn as_str(&self) -> &str;
```

**Usage**:

```rust
use queue_runtime::message::QueueName;

// Valid queue names
let queue1 = QueueName::new("my-queue".to_string())?;
let queue2 = QueueName::new("customer_orders_v2".to_string())?;
let queue3 = QueueName::with_prefix("prod", "events")?; // "prod-events"

// Invalid queue names
assert!(QueueName::new("".to_string()).is_err());           // Empty
assert!(QueueName::new("-queue".to_string()).is_err());     // Leading hyphen
assert!(QueueName::new("queue--name".to_string()).is_err()); // Consecutive hyphens
assert!(QueueName::new("queue.name".to_string()).is_err()); // Invalid character
```

### MessageId

Unique identifier for messages within the queue system. Generated automatically or parsed from provider-specific message IDs.

**Type Definition**:

```rust
pub struct MessageId(String);
```

**Construction**:

```rust
/// Generate new random message ID (UUID v4)
pub fn new() -> Self;

/// Get message ID as string
pub fn as_str(&self) -> &str;
```

**Usage**:

```rust
use queue_runtime::message::MessageId;
use std::str::FromStr;

// Generate new ID
let msg_id = MessageId::new();

// Parse from string (for provider IDs)
let msg_id = MessageId::from_str("provider-message-id-12345")?;
```

### SessionId

Identifier for grouping related messages for ordered processing. Session IDs enable FIFO delivery of related messages.

**Type Definition**:

```rust
pub struct SessionId(String);
```

**Validation Rules**:

- Required (non-empty)
- Maximum 128 characters
- ASCII printable characters only (no control characters)

**Construction**:

```rust
/// Create new session ID with validation
pub fn new(id: String) -> Result<Self, ValidationError>;

/// Create session ID from parts (convenience for GitHub events)
pub fn from_parts(owner: &str, repo: &str, entity_type: &str, entity_id: &str) -> Self;

/// Get session ID as string
pub fn as_str(&self) -> &str;
```

**Usage**:

```rust
use queue_runtime::message::SessionId;

// Domain-specific session IDs
let session1 = SessionId::new("order-12345".to_string())?;
let session2 = SessionId::new("user-alice-cart".to_string())?;
let session3 = SessionId::new("tenant-123-resource-456".to_string())?;

// GitHub event session ID (convenience method)
let session4 = SessionId::from_parts("owner", "repo", "pr", "42");
// Produces: "owner/repo/pr/42"
```

### ReceiptHandle

Opaque token for acknowledging or rejecting received messages. Contains provider-specific data and expiration tracking.

**Type Definition**:

```rust
pub struct ReceiptHandle {
    handle: String,
    expires_at: Timestamp,
    provider_type: ProviderType,
}
```

**Construction**:

```rust
/// Create new receipt handle
pub fn new(handle: String, expires_at: Timestamp, provider_type: ProviderType) -> Self;

/// Get handle string
pub fn handle(&self) -> &str;

/// Check if receipt handle is expired
pub fn is_expired(&self) -> bool;

/// Get provider type
pub fn provider_type(&self) -> ProviderType;
```

**Usage**:

```rust
use queue_runtime::message::ReceiptHandle;

// Receipt handles are created by providers when receiving messages
// Applications use them for acknowledgment operations
let receipt = /* received from provider */;

if receipt.is_expired() {
    eprintln!("Receipt handle expired, message may be redelivered");
}

// Use receipt to complete, abandon, or dead-letter message
client.complete_message(receipt).await?;
```

### Timestamp

Wrapper for consistent time handling across the library. Uses UTC timezone for all timestamps.

**Type Definition**:

```rust
pub struct Timestamp(DateTime<Utc>);
```

**Construction**:

```rust
/// Create timestamp for current time
pub fn now() -> Self;

/// Create timestamp from DateTime
pub fn from_datetime(dt: DateTime<Utc>) -> Self;

/// Get underlying DateTime
pub fn as_datetime(&self) -> DateTime<Utc>;
```

**Usage**:

```rust
use queue_runtime::message::Timestamp;
use chrono::Utc;

let now = Timestamp::now();
let future = Timestamp::from_datetime(Utc::now() + Duration::hours(2));

// Timestamps are comparable
assert!(now < future);
```

## Message Types

### Message

A message to be sent through the queue system. Messages are domain-agnostic - the body is opaque bytes, allowing any serialization format.

**Type Definition**:

```rust
pub struct Message {
    pub body: Bytes,
    pub attributes: HashMap<String, String>,
    pub session_id: Option<SessionId>,
    pub correlation_id: Option<String>,
    pub time_to_live: Option<Duration>,
}
```

**Fields**:

- **body**: Message payload as bytes (any format: JSON, Protobuf, binary, etc.)
- **attributes**: Key-value metadata for routing, filtering, tracing
- **session_id**: Optional session ID for ordered processing
- **correlation_id**: Optional ID for request/response patterns and distributed tracing
- **time_to_live**: Optional TTL for automatic message expiration

**Construction**:

```rust
/// Create new message with body
pub fn new(body: Bytes) -> Self;

/// Add session ID for ordered processing
pub fn with_session_id(mut self, session_id: SessionId) -> Self;

/// Add message attribute
pub fn with_attribute(mut self, key: String, value: String) -> Self;

/// Add correlation ID for tracking
pub fn with_correlation_id(mut self, correlation_id: String) -> Self;

/// Add time-to-live for message expiration
pub fn with_ttl(mut self, ttl: Duration) -> Self;
```

**Usage**:

```rust
use queue_runtime::message::{Message, SessionId};
use bytes::Bytes;
use chrono::Duration;

// Simple message
let msg1 = Message::new(Bytes::from("Hello, World!"));

// Message with session for ordered processing
let session = SessionId::new("order-123".to_string())?;
let msg2 = Message::new(Bytes::from(b"order data".to_vec()))
    .with_session_id(session)
    .with_correlation_id("request-456".to_string())
    .with_attribute("priority".to_string(), "high".to_string())
    .with_ttl(Duration::hours(24));

// Serialize your domain objects to bytes
use serde_json;
let order = /* your domain struct */;
let json_bytes = Bytes::from(serde_json::to_vec(&order)?);
let msg3 = Message::new(json_bytes);
```

**Serialization**:

```rust
// Message implements Serialize/Deserialize for storage/transmission
// Body bytes are base64-encoded in JSON serialization
let json = serde_json::to_string(&message)?;
let message: Message = serde_json::from_str(&json)?;
```

### ReceivedMessage

A message received from the queue with processing metadata. Contains all original message data plus delivery tracking information.

**Type Definition**:

```rust
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
```

**Fields**:

- **message_id**: Unique identifier assigned by provider
- **body**: Message payload bytes
- **attributes**: Message metadata
- **session_id**: Session ID if message is part of ordered session
- **correlation_id**: Correlation ID for tracing
- **receipt_handle**: Token for acknowledgment operations
- **delivery_count**: Number of times message has been delivered (for retry logic)
- **first_delivered_at**: When message was first delivered to any consumer
- **delivered_at**: When message was delivered to this consumer

**Operations**:

```rust
/// Convert back to Message (for forwarding/replaying)
pub fn message(&self) -> Message;

/// Check if message has exceeded maximum delivery count
pub fn has_exceeded_max_delivery_count(&self, max_count: u32) -> bool;
```

**Usage**:

```rust
use queue_runtime::message::ReceivedMessage;

// Receive message from queue
let received = client.receive_message(&queue, timeout).await?;

if let Some(msg) = received {
    println!("Message ID: {}", msg.message_id);
    println!("Delivery count: {}", msg.delivery_count);

    // Check for poison messages (too many retries)
    if msg.has_exceeded_max_delivery_count(5) {
        // Send to dead letter queue
        client.dead_letter_message(
            msg.receipt_handle,
            format!("Max delivery count exceeded: {}", msg.delivery_count)
        ).await?;
    } else {
        // Process message
        process(&msg.body)?;

        // Mark as complete
        client.complete_message(msg.receipt_handle).await?;
    }
}
```

**Forwarding/Replaying Messages**:

```rust
// Convert received message back to sendable message
let new_message = received.message()
    .with_attribute("replayed".to_string(), "true".to_string());

// Send to different queue
client.send_message(&other_queue, new_message).await?;
```

## Serialization Support

### Message Serialization

Messages implement `Serialize` and `Deserialize` for persistence and transmission.

**Body Encoding**:

- Message bodies (bytes) are base64-encoded in JSON format
- Prevents JSON escaping issues with binary data
- Ensures safe transmission over text-based protocols

**Example**:

```rust
use queue_runtime::message::Message;
use bytes::Bytes;
use serde_json;

let message = Message::new(Bytes::from(vec![0x01, 0x02, 0x03, 0xFF]));

// Serialize to JSON
let json = serde_json::to_string(&message)?;
// Body is base64-encoded: {"body":"AQIDBP//","attributes":{},...}

// Deserialize from JSON
let message: Message = serde_json::from_str(&json)?;
assert_eq!(message.body, Bytes::from(vec![0x01, 0x02, 0x03, 0xFF]));
```

### Domain Object Serialization

Applications serialize domain objects before creating messages:

```rust
use serde::{Serialize, Deserialize};
use bytes::Bytes;

#[derive(Serialize, Deserialize)]
struct OrderEvent {
    order_id: String,
    customer_id: String,
    total: f64,
}

// Serialize domain object to bytes
let event = OrderEvent {
    order_id: "order-123".to_string(),
    customer_id: "customer-456".to_string(),
    total: 99.99,
};

let json_bytes = Bytes::from(serde_json::to_vec(&event)?);
let message = Message::new(json_bytes);

// Send message
client.send_message(&queue, message).await?;

// Receive and deserialize
let received = client.receive_message(&queue, timeout).await?;
if let Some(msg) = received {
    let event: OrderEvent = serde_json::from_slice(&msg.body)?;
    println!("Order: {} for customer {}", event.order_id, event.customer_id);
}
```

## Message Validation

### Validation Errors

The module defines validation errors for invalid identifiers:

```rust
pub enum ValidationError {
    Required { field: String },
    OutOfRange { field: String, message: String },
    InvalidFormat { field: String, message: String },
}
```

**Validation Rules**:

- **QueueName**: 1-260 characters, ASCII alphanumeric/hyphens/underscores, no leading/trailing hyphens
- **MessageId**: Non-empty string
- **SessionId**: Non-empty, max 128 characters, ASCII printable only

**Usage**:

```rust
use queue_runtime::message::{QueueName, ValidationError};

match QueueName::new("invalid..name".to_string()) {
    Ok(queue) => { /* use queue */ }
    Err(ValidationError::InvalidFormat { field, message }) => {
        eprintln!("Invalid {}: {}", field, message);
    }
    Err(e) => {
        eprintln!("Validation error: {:?}", e);
    }
}
```

## Design Principles

### Domain-Agnostic Design

This module is intentionally **not specific** to GitHub events or any particular domain:

- **Body is Bytes**: Applications choose their own serialization (JSON, Protobuf, CBOR, etc.)
- **No Envelope Assumptions**: No assumed structure beyond basic queue message fields
- **Generic Attributes**: Key-value attributes work for any metadata
- **Flexible Session IDs**: Session IDs can be structured for any domain

### Type Safety

- **Branded Types**: QueueName, MessageId, SessionId are distinct types (not just strings)
- **Validation at Construction**: Invalid values rejected immediately
- **No Runtime Surprises**: Validation errors at construction time, not during queue operations

### Provider Compatibility

- **ReceiptHandle**: Encapsulates provider-specific data while providing common interface
- **Timestamp**: Consistent UTC time handling across providers
- **Expiration Tracking**: Built-in support for message and receipt handle expiration

## Behavioral Assertions

### QueueName Assertions

1. **Valid names must be 1-260 characters**: Empty or too-long names rejected
2. **Only alphanumeric, hyphens, underscores allowed**: Special characters rejected
3. **No leading/trailing hyphens**: Hyphen placement validated
4. **No consecutive hyphens**: Double-hyphens rejected

### SessionId Assertions

1. **Non-empty session IDs required**: Empty strings rejected
2. **Maximum 128 characters**: Longer session IDs rejected
3. **ASCII printable only**: Control characters and non-ASCII rejected

### Message Assertions

1. **Body preserved exactly**: Bytes sent == bytes received (no encoding corruption)
2. **Attributes preserved**: Key-value metadata transmitted unchanged
3. **Session ID preserved**: Session grouping maintained through queue

### ReceivedMessage Assertions

1. **delivery_count >= 1**: Message delivered at least once
2. **delivered_at >= first_delivered_at**: Current delivery after or equal to first
3. **receipt_handle not expired initially**: Receipt valid when message received
4. **message() preserves body**: Converted message has same body as received

## Testing Strategy

### Unit Testing

- Test validation rules for all domain identifiers
- Test message construction with builder pattern
- Test serialization round-trips (Message -> JSON -> Message)
- Test receipt handle expiration logic

### Property-Based Testing

- QueueName validation with property tests (generate random strings)
- SessionId character restrictions with property tests
- Message serialization with arbitrary bytes

### Integration Testing

- Test message transmission through real queue providers
- Verify body preservation across providers
- Test attribute handling across providers
- Verify session ID propagation
