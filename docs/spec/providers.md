# Provider Implementation Differences

This document outlines the key differences between Azure Service Bus and AWS SQS implementations in the queue-runtime, helping developers understand provider-specific behavior and choose the appropriate provider for their use case.

## Overview

The queue-runtime provides a unified abstraction over different cloud message queue providers. While the API remains consistent, each provider has unique characteristics, capabilities, and limitations that affect implementation decisions.

## Provider Comparison Matrix

| Feature | Azure Service Bus | AWS SQS | In-Memory |
|---------|------------------|----------|-----------|
| **Ordered Processing** | Native Sessions | FIFO Queues | Simple Ordering |
| **Dead Letter Queues** | Built-in | Built-in | Simulated |
| **Message Deduplication** | Native Support | Content-based | Hash-based |
| **Batch Operations** | Send/Receive Batches | Send/Receive Batches | Full Batching |
| **Message Size Limit** | 1MB (Premium) | 256KB | Memory Limited |
| **Session Support** | First-class | Via Message Groups | Thread-based |
| **Transactional Operations** | Limited | No | Yes |
| **Peek Operations** | Supported | No | Yes |
| **Authentication** | Azure AD/Managed Identity | IAM Roles | N/A |

## Azure Service Bus Implementation

### Session Management

**Native Session Support**:

- Sessions provide strict FIFO ordering within session boundaries
- Session acceptance locks session for exclusive processing
- Session timeout and renewal mechanisms
- Session state storage for stateful processing

**Implementation Characteristics**:

- Session ID directly maps to Service Bus session ID
- Session acceptance provides exclusive lock until completion or timeout
- Messages without session ID go to default session queue
- Session completion releases lock for next consumer

### Message Features

**Advanced Message Properties**:

- Rich message properties and headers
- Custom message annotations
- Message scheduling and deferred delivery
- Message peeking without consumption

**Error Handling**:

- Native dead letter queue with detailed failure reason
- Message abandonment returns message to queue
- Delivery count tracking with automatic DLQ transfer
- Error description and exception details preserved

### Connection Management

**Connection Efficiency**:

- Connection pooling and multiplexing
- Long-lived connections with automatic renewal
- Exponential backoff for connection failures
- Circuit breaker patterns for fault tolerance

```rust
// Azure Service Bus specific configuration
pub struct AzureServiceBusConfig {
    pub connection_string: Option<String>,
    pub namespace: String,
    pub shared_access_key_name: Option<String>,
    pub shared_access_key: Option<String>,
    pub managed_identity_client_id: Option<String>,
    pub max_concurrent_calls: u32,
    pub prefetch_count: u32,
    pub max_auto_lock_renewal_duration: Duration,
    pub transport_type: TransportType,
}

#[derive(Debug, Clone)]
pub enum TransportType {
    Amqp,
    AmqpWebSockets,
}
```

## AWS SQS Implementation

### FIFO Queue Behavior

**Message Group Ordering**:

- FIFO queues ensure ordering within message groups
- Message group ID determines processing order
- Deduplication based on message content or deduplication ID
- Higher throughput with multiple message groups

**Implementation Mapping**:

- Session ID maps to SQS message group ID
- Content-based deduplication for message uniqueness
- Receive request deduplication for exactly-once delivery
- FIFO queue naming convention with `.fifo` suffix

### Performance Characteristics

**Throughput and Scaling**:

- Standard queues: Unlimited throughput, at-least-once delivery
- FIFO queues: 3000 messages/second with batching
- Visibility timeout for message processing windows
- Long polling for efficient message retrieval

**Batch Operations**:

- Send up to 10 messages per batch request
- Receive up to 10 messages per request
- Delete multiple messages in single request
- Batch operations reduce API calls and improve performance

### AWS-Specific Features

**Extended Message Support**:

- S3 payload storage for large messages
- Automatic message offloading and retrieval
- Cost optimization for infrequent access patterns

**Dead Letter Queue Configuration**:

- Redrive policy with source queue configuration
- Message retention and replay capabilities
- Cross-account DLQ access patterns

```rust
// AWS SQS specific configuration
pub struct AwsSqsConfig {
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub session_token: Option<String>,
    pub role_arn: Option<String>,
    pub queue_url: String,
    pub max_number_of_messages: i32,
    pub visibility_timeout: Option<Duration>,
    pub wait_time_seconds: Option<Duration>,
    pub message_retention_period: Duration,
}
```

## In-Memory Implementation

### Development and Testing

**Simplified Behavior**:

- Thread-safe in-memory queue storage
- Simulated session behavior with thread affinity
- Configurable delivery delays and failures
- Full message lifecycle simulation

**Testing Capabilities**:

- Message inspection and verification
- Controlled failure injection
- Deterministic ordering and timing
- Reset and cleanup operations

```rust
// In-Memory specific configuration
pub struct InMemoryConfig {
    pub max_queue_size: usize,
    pub enable_persistence: bool,
    pub persistence_path: Option<PathBuf>,
    pub simulate_delays: bool,
    pub default_visibility_timeout: Duration,
    pub failure_rate: f64, // For chaos testing
}
```

## Provider Selection Guidance

### Use Azure Service Bus When

1. **Rich Session Management**: Need complex session state and lifecycle management
2. **Enterprise Integration**: Existing Azure ecosystem and managed identity integration
3. **Advanced Messaging**: Require message scheduling, peeking, and rich metadata
4. **Strict Ordering**: Need guaranteed FIFO with session affinity
5. **Large Messages**: Messages approaching 1MB size limit

### Use AWS SQS When

1. **High Throughput**: Standard queues with unlimited throughput requirements
2. **Cost Optimization**: Pay-per-use pricing model preferred
3. **AWS Ecosystem**: Existing AWS infrastructure and IAM integration
4. **Simple Ordering**: FIFO requirements with multiple processing groups
5. **Global Scale**: Multi-region deployment with consistent behavior

### Use In-Memory When

1. **Local Development**: Fast local development and testing cycles
2. **Unit Testing**: Predictable behavior and message inspection
3. **Integration Testing**: Controlled message flow and failure scenarios
4. **Prototyping**: Rapid prototyping without cloud dependencies

## Configuration Patterns

### Environment-Based Selection

```rust
use queue_runtime::*;

pub fn create_queue_client() -> Result<Box<dyn QueueClient>, Box<dyn std::error::Error>> {
    let provider = std::env::var("QUEUE_PROVIDER").unwrap_or_default();

    match provider.as_str() {
        "azure" => {
            let config = AzureServiceBusConfig {
                namespace: std::env::var("SERVICE_BUS_NAMESPACE")?,
                managed_identity_client_id: std::env::var("AZURE_CLIENT_ID").ok(),
                max_concurrent_calls: 16,
                prefetch_count: 10,
                max_auto_lock_renewal_duration: Duration::from_minutes(5),
                transport_type: TransportType::Amqp,
                ..Default::default()
            };
            Ok(Box::new(AzureServiceBusClient::new(config).await?))
        },

        "aws" => {
            let config = AwsSqsConfig {
                region: std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
                queue_url: std::env::var("SQS_QUEUE_URL")?,
                max_number_of_messages: 10,
                wait_time_seconds: Some(Duration::from_secs(20)),
                visibility_timeout: Some(Duration::from_secs(30)),
                message_retention_period: Duration::from_days(14),
                ..Default::default()
            };
            Ok(Box::new(AwsSqsClient::new(config).await?))
        },

        "memory" | _ => {
            let config = InMemoryConfig {
                max_queue_size: 1000,
                enable_persistence: false,
                simulate_delays: false,
                default_visibility_timeout: Duration::from_secs(30),
                failure_rate: 0.0,
                ..Default::default()
            };
            Ok(Box::new(InMemoryClient::new(config).await?))
        }
    }
}
```

### Feature-Based Selection

```rust
pub struct ProviderRequirements {
    pub strict_ordering: bool,
    pub high_throughput: bool,
    pub large_messages: bool,
    pub session_state: bool,
    pub cost_optimization: bool,
    pub existing_ecosystem: CloudProvider,
}

pub enum CloudProvider {
    Azure,
    Aws,
    MultiCloud,
    OnPremises,
}

pub fn recommend_provider(requirements: &ProviderRequirements) -> QueueProvider {
    match requirements {
        // Azure Service Bus preferred
        ProviderRequirements {
            session_state: true,
            large_messages: true,
            existing_ecosystem: CloudProvider::Azure,
            ..
        } => QueueProvider::AzureServiceBus,

        // AWS SQS preferred
        ProviderRequirements {
            high_throughput: true,
            cost_optimization: true,
            existing_ecosystem: CloudProvider::Aws,
            ..
        } => QueueProvider::AwsSqs,

        // Default to in-memory for development
        _ => QueueProvider::InMemory,
    }
}
```

## Migration Considerations

### Azure to AWS Migration

**Configuration Mapping**:

- Service Bus sessions → SQS message groups
- Message properties → Message attributes
- Connection strings → Queue URLs and IAM roles
- Session state → External state store (DynamoDB, Redis)

**Behavioral Changes**:

- Session exclusive locking → Message group ordering
- Message peeking → Additional SQS operations
- Rich message metadata → Simplified attributes
- Transaction support → Application-level compensation

### AWS to Azure Migration

**Configuration Mapping**:

- Message groups → Service Bus sessions
- Queue URLs → Connection strings and queue names
- IAM roles → Managed identity and RBAC
- Visibility timeout → Lock duration

**Feature Enhancements**:

- Message group ordering → Session exclusive processing
- Simple attributes → Rich message properties
- Redrive policies → Native dead letter handling
- Long polling → Prefetch and concurrent processing

## Performance Optimization

### Provider-Specific Tuning

**Azure Service Bus**:

- Increase prefetch count for high-throughput scenarios
- Use Premium tier for consistent performance
- Configure appropriate max concurrent calls
- Enable connection pooling and multiplexing

**AWS SQS**:

- Use batch operations to reduce API calls
- Tune visibility timeout for processing patterns
- Enable long polling to reduce empty receives
- Consider FIFO vs Standard queues based on requirements

**In-Memory**:

- Configure appropriate queue sizes for memory usage
- Enable persistence for durable local testing
- Use controlled delays for realistic testing scenarios

### Cross-Provider Patterns

```rust
pub trait QueueOptimization {
    fn configure_for_throughput(&mut self) -> Result<(), ConfigError>;
    fn configure_for_latency(&mut self) -> Result<(), ConfigError>;
    fn configure_for_cost(&mut self) -> Result<(), ConfigError>;
}

impl QueueOptimization for AzureServiceBusConfig {
    fn configure_for_throughput(&mut self) -> Result<(), ConfigError> {
        self.prefetch_count = 50;
        self.max_concurrent_calls = 32;
        self.transport_type = TransportType::Amqp;
        Ok(())
    }

    fn configure_for_latency(&mut self) -> Result<(), ConfigError> {
        self.prefetch_count = 1;
        self.max_concurrent_calls = 1;
        self.transport_type = TransportType::AmqpWebSockets;
        Ok(())
    }
}

impl QueueOptimization for AwsSqsConfig {
    fn configure_for_throughput(&mut self) -> Result<(), ConfigError> {
        self.max_number_of_messages = 10;
        self.wait_time_seconds = Some(Duration::from_secs(20));
        self.visibility_timeout = Some(Duration::from_secs(60));
        Ok(())
    }

    fn configure_for_cost(&mut self) -> Result<(), ConfigError> {
        self.wait_time_seconds = Some(Duration::from_secs(20)); // Long polling
        self.message_retention_period = Duration::from_days(1); // Shorter retention
        Ok(())
    }
}
```

## Behavioral Assertions

The following assertions define expected provider-specific behaviors:

### Azure Service Bus Assertions

1. **Session Exclusivity**: Only one consumer can process messages from a session at a time
2. **Session Ordering**: Messages within a session MUST be processed in FIFO order
3. **Lock Renewal**: Session locks MUST be renewable before expiration
4. **Message Scheduling**: Scheduled messages MUST not be visible until scheduled time
5. **Peek Operations**: Peek MUST not affect message visibility or lock state

### AWS SQS Assertions

6. **Message Group Ordering**: Messages in the same group MUST be processed in order
7. **FIFO Deduplication**: Duplicate messages MUST be rejected within deduplication window
8. **Visibility Timeout**: Messages MUST be invisible during processing window
9. **Long Polling**: Empty receives MUST wait for configured duration
10. **Batch Efficiency**: Batch operations MUST be more efficient than individual operations

### Cross-Provider Assertions

11. **API Consistency**: All providers MUST implement the same QueueClient trait
12. **Error Mapping**: Provider-specific errors MUST map to consistent error types
13. **Configuration Validation**: Invalid configurations MUST be rejected at startup
14. **Graceful Degradation**: Provider failures MUST not cause application crashes
15. **Resource Cleanup**: All providers MUST properly cleanup connections and resources
