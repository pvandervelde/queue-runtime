# Queue Client Module

The queue client module provides the core abstraction layer for queue operations, defining the main traits and interfaces that enable provider-agnostic queue handling.

## Overview

The queue client module establishes a unified API that abstracts the differences between Azure Service Bus and AWS SQS, providing consistent interfaces for message operations while preserving provider-specific capabilities like sessions and FIFO ordering.

## Core Traits

### QueueClient Design Requirements

**Core Interface Design**:

- Async trait with Send + Sync + Clone bounds for multi-threaded usage
- Generic over Message, Receipt, and Error types for provider flexibility
- Consistent method signatures across Azure Service Bus and AWS SQS implementations

**Message Operations**:

- Send individual messages with configurable options (session, TTL, scheduling)
- Batch send operations for improved throughput and reduced API calls
- Receive with timeout, batch size, and session filtering support
- Acknowledge, reject, and requeue operations with receipt-based tracking

**Queue Management**:

- Queue information retrieval (depth, statistics, configuration)
- Queue provisioning with definition-based configuration
- Queue deletion with safety considerations

**Error Handling**:

- Provider-specific error types implementing common error interface
- Categorized errors (network, authentication, quota, transient vs permanent)

### QueueMessage

Trait for messages that can be sent to queues:

```rust
pub trait QueueMessage: Send + Sync + Clone + Debug {
    /// Unique identifier for the message
    fn message_id(&self) -> &str;

    /// Session ID for ordered processing (if applicable)
    fn session_id(&self) -> Option<&str>;

    /// Correlation ID for request/response patterns
    fn correlation_id(&self) -> Option<&str>;

    /// Content type of the message body
    fn content_type(&self) -> &str;

    /// Raw message body as bytes
    fn body(&self) -> &[u8];

    /// Custom properties/headers for the message
    fn properties(&self) -> &HashMap<String, String>;

    /// Time-to-live for the message
    fn ttl(&self) -> Option<Duration>;

    /// Scheduled enqueue time for delayed delivery
    fn scheduled_enqueue_time(&self) -> Option<DateTime<Utc>>;
}
```

### MessageReceipt

Trait for message receipts used in acknowledgment operations:

```rust
pub trait MessageReceipt: Send + Sync + Clone + Debug {
    /// Unique receipt identifier
    fn receipt_id(&self) -> &str;

    /// Original message ID this receipt corresponds to
    fn message_id(&self) -> &str;

    /// Queue name where the message was received from
    fn queue_name(&self) -> &str;

    /// Number of times this message has been delivered
    fn delivery_count(&self) -> u32;

    /// When the message was originally enqueued
    fn enqueued_at(&self) -> DateTime<Utc>;

    /// When the message was received by this consumer
    fn received_at(&self) -> DateTime<Utc>;

    /// Session ID if the message is part of a session
    fn session_id(&self) -> Option<&str>;
}
```

## Core Types

### ReceivedMessage

**Message Container Requirements**:

- Generic message type supporting any QueueMessage implementation
- Associated receipt type for message acknowledgment operations
- Delivery count tracking for retry logic and dead letter handling
- Timestamp tracking for message age and processing time analysis
- Message lock expiration tracking for distributed processing coordination

**Lock Management Requirements**:

- Lock expiration detection for processing timeout scenarios
- Remaining lock time calculation for processing scheduling
- Automatic lock extension support for long-running operations
- Graceful handling of expired locks with appropriate error responses

### SendOptions

**Message Send Configuration Requirements**:

- Session ID specification for ordered processing workflows
- Correlation ID for request/response and tracing patterns
- Scheduled delivery time support for delayed message processing
- Time-to-live configuration for automatic message expiration
- Custom properties for metadata and routing information
- Content type override for specialized message formats
- Duplicate detection ID for exactly-once delivery guarantees

**Builder Pattern Requirements**:

- Fluent builder methods for ergonomic configuration
- Method chaining support for concise option specification
- Delay configuration with automatic timestamp calculation
- Property attachment with key-value pairs

### ReceiveOptions

**Message Receive Configuration Requirements**:

- Maximum message batch size control for throughput optimization
- Configurable timeout duration for receive operations
- Session-specific message consumption for ordered processing
- Session acceptance flexibility for load balancing scenarios
- Message lock duration control for processing time management
- Peek-only mode for message inspection without consumption
- Sequence number positioning for replay and recovery scenarios

**Receive Behavior Configuration**:

- Batch size optimization for different processing patterns
- Timeout configuration for responsive vs. efficient polling
- Session targeting for specific workflow requirements
- Lock duration matching processing time expectations

### QueueInfo

**Queue Statistics Requirements**:

- Queue name and unique identification
- Message count tracking (total, active, dead letter, scheduled)
- Queue size monitoring in bytes for capacity planning
- Creation and last update timestamps for audit trails
- Current operational status for health monitoring
- Configuration snapshot for compliance verification

**Queue Status Classifications**:

- **Active**: Normal operational state accepting and delivering messages
- **Creating**: Queue initialization in progress
- **Deleting**: Queue removal operation in progress
- **Disabled**: Temporarily suspended operations (send and receive blocked)
- **ReceiveDisabled**: Send-only mode (receive operations blocked)
- **SendDisabled**: Receive-only mode (send operations blocked)
- **Unknown**: Status cannot be determined or provider-specific state

**Queue Configuration Tracking**:

- Maximum delivery attempt count before dead lettering
- Message time-to-live settings for automatic cleanup
- Message lock duration for processing coordination
- Session enablement for ordered processing workflows
- Dead letter queue configuration for failure handling
- Duplicate detection settings for exactly-once delivery
- Maximum queue size limits for capacity management

### QueueDefinition

**Queue Configuration Template Requirements**:

- Unique queue name for identification and routing
- Maximum delivery attempt count before dead letter processing
- Message time-to-live for automatic message expiration
- Message lock duration for processing timeout control
- Session enablement for ordered message processing
- Dead letter queue activation for failure handling
- Duplicate detection configuration for exactly-once delivery
- Duplicate detection time window for deduplication scope
- Maximum queue size limits for storage management
- Auto-delete configuration for unused queue cleanup
- Batch operation support for performance optimization
- Express messaging for low-latency scenarios
- Queue partitioning for horizontal scaling

**Default Configuration Strategy**:

- Conservative delivery count (3 attempts) for reliability
- 24-hour message TTL for reasonable retention
- 60-second lock duration for typical processing time
- Sessions enabled by default for GitHub event ordering
- Dead lettering enabled for debugging failed messages
- Duplicate detection enabled for idempotency
- 10-minute deduplication window for webhook retries
- 1GB queue size limit for resource management
- Batch operations enabled for throughput optimization

**Queue Definition Builder Requirements**:

- Fluent builder methods for configuration customization
- Delivery count configuration for retry behavior
- TTL configuration for message lifecycle management
- Lock duration tuning for processing time requirements

## Error Types

### QueueError

**Error Classification Requirements**:

- Base error trait for consistent error handling across providers
- Transient error identification for automatic retry logic
- Permanent error classification to avoid futile retries
- Provider-specific error codes for detailed troubleshooting
- Retry delay hints for intelligent backoff strategies

**Error Categories**:

- **ConnectionFailed**: Network connectivity and connection establishment errors
- **AuthenticationFailed**: Credential and authorization failures
- **QueueNotFound**: Invalid queue name or missing queue references
- **MessageNotFound**: Message ID references for non-existent messages
- **SessionNotFound**: Invalid session ID for session-based operations
- **LockExpired**: Message processing timeout violations
- **OperationTimeout**: Client-side operation timeout conditions
    Timeout { timeout: Duration },

- **RateLimitExceeded**: Provider rate limiting and throttling responses
- **MessageTooLarge**: Message size validation against provider limits
- **InvalidMessage**: Message format and content validation failures
- **ServiceUnavailable**: Provider service outages and maintenance windows
- **Configuration**: Configuration validation and setup errors
- **Serialization**: Message serialization and deserialization failures

**Error Trait Implementation Requirements**:

- Transient error classification for retry eligibility (ConnectionFailed, Timeout, RateLimitExceeded, ServiceUnavailable)
- Permanent error identification to prevent infinite retries
- Error code mapping for provider-specific troubleshooting and monitoring
- Retry delay recommendations for intelligent backoff strategies

## Client Factory

### QueueClientFactory

**Factory Design Requirements**:

- Provider-agnostic client creation based on configuration
- Support for Azure Service Bus, AWS SQS, and In-Memory providers
- Configuration-driven provider selection and instantiation
- Consistent error handling across provider implementations
- Provider-specific factory methods for direct client creation
- Dynamic client instantiation based on runtime configuration

## Usage Examples

**Client Usage Requirements**:

- Environment-based configuration loading
- Factory-based client instantiation
- Queue creation and configuration management
- Message sending with delivery options (session ID, correlation ID)
- Message receiving with configurable timeouts and batch sizes
- Receipt-based message lifecycle management (acknowledge, reject, requeue)
- Delivery count tracking and exponential backoff retry strategies
- Dead letter queue handling for poison messages

**Batch Processing Requirements**:

- Batch message sending for high-throughput scenarios
- Individual result tracking for batch operations
- Session-based batch processing for ordered workflows
- Error handling and partial failure management in batch operations

**Session Processing Requirements**:

- Session-based message ordering and sequential processing
- Session timeout configuration and session lifecycle management
- Session completion detection and graceful termination
- Error handling with session processing interruption on failures
- Message acknowledgment within session boundaries

## Testing Support

**Mock Implementation Requirements**:

- In-memory mock client for unit testing
- Message storage and retrieval simulation
- Receipt lifecycle simulation and verification
- Queue state management and inspection capabilities
- Configurable error injection for failure scenario testing
- Thread-safe implementations for concurrent test scenarios

## Performance Expectations

**Latency Requirements**:

- **Send Operations**: ~2-5ms per message, ~10-20ms for batch of 10
- **Receive Operations**: ~5-15ms with long polling, ~1-3ms without polling
- **Acknowledgment**: ~1-3ms per receipt

**Throughput Requirements**:

- **Send Rate**: 1000+ messages per second per client
- **Receive Rate**: 500+ messages per second per client
- **Batch Processing**: 10,000+ messages per batch operation
- **Concurrent Clients**: Support 100+ concurrent client connections per provider

## Performance Characteristics

- **Send Operations**: ~2-5ms per message, ~10-20ms for batch of 10
- **Receive Operations**: ~10-50ms depending on message availability
- **Acknowledgment**: ~1-3ms per receipt
- **Session Processing**: Adds ~5-10ms overhead for session management
- **Connection Overhead**: ~100-500ms for initial connection establishment
- **Memory Usage**: ~1KB per message in flight, ~100KB base client overhead
