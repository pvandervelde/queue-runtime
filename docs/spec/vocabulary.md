# Queue Runtime Domain Vocabulary

This document defines the core concepts and terminology used throughout the queue-runtime system to ensure consistent understanding across all provider implementations and bot integrations.

## Core Queue Concepts

### Queue

A message delivery mechanism that provides reliable, asynchronous communication between services.

- **Purpose**: Decouples message producers from consumers
- **Providers**: Azure Service Bus, AWS SQS, or in-memory implementations
- **Guarantees**: At-least-once delivery with optional ordering
- **Configuration**: TTL, retry limits, dead letter settings, session enablement
- **Naming**: Follows provider-specific conventions with environment prefixes

### Message

A discrete unit of data sent through a queue system.

- **Content**: Binary payload with metadata properties
- **Identity**: Unique message ID for deduplication and tracking
- **Properties**: Key-value metadata for routing and processing hints
- **TTL**: Time-to-live for automatic expiration
- **Correlation**: Optional correlation ID for request-response patterns

### Receipt

A proof-of-delivery token that enables message lifecycle management.

- **Purpose**: Enables acknowledgment, rejection, or requeuing of received messages
- **Scope**: Valid only for specific message and consumer
- **Expiration**: Tied to message lock duration
- **Operations**: Acknowledge (complete), reject (dead letter), requeue (retry)
- **Security**: Prevents unauthorized message operations

### Session

A logical grouping mechanism that ensures related messages are processed in order.

- **Session ID**: String identifier that groups related messages
- **Ordering**: Messages within a session processed sequentially (FIFO)
- **Exclusivity**: Only one consumer can process a session at a time
- **Timeout**: Automatic session release if consumer becomes unresponsive
- **Lock**: Session lock prevents concurrent processing by multiple consumers

### Provider

An implementation of the queue abstraction for a specific cloud platform.

- **Azure Service Bus**: Primary provider with native session support
- **AWS SQS**: Secondary provider using FIFO queues for ordering
- **In-Memory**: Testing provider for local development and unit tests
- **Interface**: Common QueueClient trait across all providers
- **Features**: Provider-specific capabilities exposed through common API

## Message Processing Concepts

### Delivery Count

The number of times a message has been delivered to consumers.

- **Increment**: Increased each time message is delivered
- **Retry Logic**: Used to determine if message should be retried
- **Dead Letter**: Messages exceeding max delivery count moved to DLQ
- **Reset**: Some providers reset count on successful processing

### Lock Duration

The time period during which a consumer has exclusive access to a message.

- **Purpose**: Prevents duplicate processing by multiple consumers
- **Extension**: Can be renewed if processing takes longer than expected
- **Expiration**: Message becomes available to other consumers when lock expires
- **Configuration**: Balanced between processing time and recovery speed

### Dead Letter Queue (DLQ)

A special queue for messages that cannot be processed successfully.

- **Purpose**: Preserves failed messages for investigation and replay
- **Triggers**: Max delivery count exceeded, message TTL expired, explicit rejection
- **Content**: Original message plus failure metadata and error details
- **Recovery**: Messages can be moved back to main queue after issue resolution

### Batch Processing

The ability to send or receive multiple messages in a single operation.

- **Efficiency**: Reduces network round trips and improves throughput
- **Atomicity**: All messages in batch succeed or fail together
- **Size Limits**: Provider-specific limits on batch size and total payload
- **Session Batching**: Batches can be session-aware for ordered processing

## Session Management Concepts

### Session Strategy

The algorithm used to determine session IDs for messages.

- **Entity-Based**: Group messages by GitHub entity (PR, issue, branch)
- **Repository-Based**: Group all messages for a repository
- **Time-Based**: Group messages by time windows (hourly, daily)
- **Custom**: User-defined strategy based on message content

### Session Acceptance

The process by which a consumer claims exclusive access to a session.

- **Automatic**: Consumer automatically accepts next available session
- **Explicit**: Consumer specifies which session to accept
- **Timeout**: Session acceptance has timeout to prevent indefinite waiting
- **Fairness**: Sessions distributed fairly among available consumers

### Session Completion

The process of finishing work on a session and releasing it for other consumers.

- **Success**: All messages in session processed successfully
- **Failure**: Session abandoned due to processing errors
- **Timeout**: Session automatically released after inactivity timeout
- **Explicit**: Consumer explicitly completes or abandons session

## Error Handling Concepts

### Transient Error

A temporary failure condition that may succeed if retried.

- **Examples**: Network timeouts, service throttling, temporary unavailability
- **Response**: Automatic retry with exponential backoff
- **Duration**: Failures expected to resolve within minutes or hours
- **Circuit Breaker**: May trigger protection if failures persist

### Permanent Error

A failure condition that will not succeed regardless of retries.

- **Examples**: Invalid message format, authorization failures, configuration errors
- **Response**: Immediate failure without retry
- **Dead Letter**: Message moved to DLQ for investigation
- **Fix Required**: Manual intervention needed to resolve issue

### Retry Policy

Configuration that determines how failed operations are retried.

- **Max Attempts**: Maximum number of retry attempts before giving up
- **Backoff Strategy**: Exponential, linear, or custom delay between attempts
- **Jitter**: Random variation to prevent thundering herd effects
- **Circuit Breaker**: Protection mechanism for cascading failures

### Circuit Breaker

A protection mechanism that prevents cascade failures to unhealthy services.

- **States**: Closed (normal), Open (failing), Half-Open (testing recovery)
- **Failure Threshold**: Number of failures that trigger circuit opening
- **Success Threshold**: Number of successes needed to close circuit
- **Timeout**: How long circuit stays open before testing recovery

## Provider-Specific Concepts

### Azure Service Bus

#### Namespace

A container for queues and topics within Azure Service Bus.

- **Scope**: Regional deployment with global unique name
- **Authentication**: Managed Identity or connection string access
- **Pricing Tier**: Basic, Standard, or Premium with different feature sets
- **Quotas**: Message size, queue count, and throughput limits

#### Duplicate Detection

Azure Service Bus feature that prevents duplicate message processing.

- **Detection Window**: Configurable time period for duplicate detection
- **Message ID**: Uses message ID or custom property for duplicate detection
- **Automatic**: Automatic discard of duplicate messages
- **Limitations**: Only works within detection window

### AWS SQS

#### FIFO Queue

AWS SQS queue type that guarantees message ordering and exactly-once processing.

- **Message Group ID**: Equivalent to session ID for ordering
- **Deduplication**: Automatic duplicate detection using content hash
- **Throughput**: Limited to 300 transactions per second
- **Ordering**: Strict FIFO within message groups

#### Visibility Timeout

AWS SQS concept for message lock duration.

- **Purpose**: Prevents other consumers from receiving the message
- **Duration**: Configurable timeout period (default 30 seconds)
- **Extension**: Can be modified while message is being processed
- **Expiration**: Message becomes visible again after timeout

## Configuration Concepts

### Queue Definition

Template that describes how a queue should be configured.

- **Name**: Unique identifier for the queue
- **TTL**: Message time-to-live configuration
- **Sessions**: Whether session-based ordering is enabled
- **Dead Letter**: Dead letter queue configuration
- **Size Limits**: Maximum queue size and message size limits

### Connection Configuration

Settings required to connect to a queue provider.

- **Endpoints**: Service URLs and connection strings
- **Authentication**: Credentials, tokens, or managed identity configuration
- **Timeouts**: Connection and operation timeout settings
- **Retry**: Connection retry and circuit breaker configuration
- **TLS**: Security and certificate validation settings

## Observability Concepts

### Metrics

Quantitative measurements of queue operations and performance.

- **Counters**: Messages sent, received, acknowledged, failed
- **Gauges**: Queue depth, active sessions, connection count
- **Histograms**: Processing latency, message size, session duration
- **Labels**: Provider, queue name, operation type for filtering

### Tracing

Distributed tracing that follows messages across system boundaries.

- **Trace Context**: W3C standard trace headers propagated with messages
- **Spans**: Individual operations (send, receive, acknowledge) as spans
- **Correlation**: Links queue operations with upstream and downstream processing
- **Sampling**: Configurable sampling rate to control overhead

### Health Checks

Monitoring endpoints that report system and dependency health.

- **Provider Health**: Connectivity and authentication status for queue providers
- **Queue Health**: Individual queue accessibility and configuration
- **Circuit Breaker Status**: Current state of circuit breakers
- **Resource Usage**: Memory, CPU, and connection pool utilization

This vocabulary establishes the shared language for queue-runtime architecture and implementation, ensuring consistent terminology across all provider implementations and bot integrations.
