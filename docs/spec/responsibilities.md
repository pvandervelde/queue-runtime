# Queue Runtime Component Responsibilities

This document defines the responsibilities and collaboration patterns for queue-runtime components using Responsibility-Driven Design (RDD) principles to create a provider-agnostic queue abstraction.

## QueueClient (Trait)

**Responsibilities:**

- **Knows**: Queue operation contracts, provider-agnostic interfaces, async operation patterns
- **Does**: Defines standard queue operations (send, receive, acknowledge, reject), specifies error handling contracts, establishes session management interfaces

**Collaborators:**

- **Concrete Providers**: Implemented by AzureServiceBusClient, AwsSqsClient, InMemoryClient
- **Message Types**: Works with any type implementing QueueMessage trait
- **Receipt Types**: Manages provider-specific receipt implementations
- **Error Types**: Returns standardized QueueError variants

**Roles:**

- **Abstraction Layer**: Hides provider-specific implementation details
- **Contract Definer**: Establishes behavior expectations for all providers
- **Type Safety Guardian**: Ensures compile-time correctness across providers

**Boundaries:**

- **In**: Provider-agnostic queue operations and configuration
- **Out**: Standardized results and error types across all providers
- **Not Responsible For**: Provider-specific implementation details, connection management, credential handling

---

## AzureServiceBusClient

**Responsibilities:**

- **Knows**: Azure Service Bus APIs, session management, AMQP protocol, authentication patterns
- **Does**: Implements QueueClient trait for Azure Service Bus, manages connection pools, handles session-based message delivery

**Collaborators:**

- **Azure Service Bus**: Native Azure messaging service with session support
- **SessionManager**: Coordinates session-based message ordering
- **ConnectionPool**: Manages AMQP connections for efficiency
- **RetryPolicy**: Handles transient Azure service failures

**Roles:**

- **Azure Adapter**: Translates generic queue operations to Azure Service Bus calls
- **Session Coordinator**: Implements ordered processing using Azure sessions
- **Connection Manager**: Maintains efficient connections to Azure services

**Boundaries:**

- **In**: Generic queue operations and Azure-specific configuration
- **Out**: Azure Service Bus API calls and Azure-specific error conditions
- **Not Responsible For**: Other cloud providers, in-memory implementations, business logic

---

## AwsSqsClient

**Responsibilities:**

- **Knows**: AWS SQS APIs, FIFO queue management, visibility timeouts, IAM authentication
- **Does**: Implements QueueClient trait for AWS SQS, manages FIFO queues for ordering, handles visibility timeout extensions

**Collaborators:**

- **AWS SQS**: Amazon Simple Queue Service with FIFO capabilities
- **FifoManager**: Coordinates message group IDs for ordering
- **VisibilityManager**: Handles message lock duration and extensions
- **CredentialProvider**: Manages AWS authentication and authorization

**Roles:**

- **AWS Adapter**: Translates generic queue operations to AWS SQS calls
- **FIFO Coordinator**: Implements ordered processing using SQS message groups
- **Visibility Manager**: Controls message availability and processing timeouts

**Boundaries:**

- **In**: Generic queue operations and AWS-specific configuration
- **Out**: AWS SQS API calls and AWS-specific error conditions
- **Not Responsible For**: Other cloud providers, Azure-specific features, session concepts

---

## InMemoryClient

**Responsibilities:**

- **Knows**: Thread-safe data structures, message ordering, timeout simulation
- **Does**: Implements QueueClient trait for testing, provides deterministic behavior, simulates provider characteristics

**Collaborators:**

- **MessageStore**: Thread-safe storage for in-memory messages
- **TimeoutSimulator**: Mimics real provider timeout behaviors
- **OrderingManager**: Implements session-based ordering without external dependencies

**Roles:**

- **Testing Double**: Provides fast, deterministic queue operations for tests
- **Development Tool**: Enables local development without cloud dependencies
- **Behavior Simulator**: Replicates provider-specific characteristics for testing

**Boundaries:**

- **In**: Generic queue operations and testing configuration
- **Out**: Predictable, fast responses for development and testing
- **Not Responsible For**: Production usage, real networking, external service integration

---

## SessionManager

**Responsibilities:**

- **Knows**: Session ID generation strategies, session timeout management, ordering requirements
- **Does**: Generates session IDs from message content, manages session lifecycle, coordinates ordered processing

**Collaborators:**

- **SessionStrategy**: Pluggable strategy for session ID generation
- **QueueProviders**: Coordinates with providers for session-based delivery
- **TimeoutManager**: Handles session timeout and cleanup

**Roles:**

- **Session Coordinator**: Ensures related messages are processed in order
- **ID Generator**: Creates consistent session identifiers across restarts
- **Ordering Enforcer**: Prevents concurrent processing of related messages

**Boundaries:**

- **In**: Messages requiring session-based ordering
- **Out**: Session IDs and session management commands
- **Not Responsible For**: Message content processing, provider-specific session implementations

---

## RetryPolicyEngine

**Responsibilities:**

- **Knows**: Retry strategies, backoff algorithms, failure classification, circuit breaker patterns
- **Does**: Classifies errors as transient vs permanent, applies exponential backoff with jitter, manages circuit breaker state

**Collaborators:**

- **ErrorClassifier**: Determines if errors are worth retrying
- **BackoffCalculator**: Computes delay between retry attempts
- **CircuitBreaker**: Protects against cascading failures
- **MetricsCollector**: Tracks retry patterns and success rates

**Roles:**

- **Reliability Guardian**: Implements patterns that improve system reliability
- **Failure Classifier**: Distinguishes between recoverable and permanent failures
- **Protection Provider**: Prevents cascading failures through circuit breaking

**Boundaries:**

- **In**: Failed operations and retry configuration
- **Out**: Retry decisions and delay calculations
- **Not Responsible For**: Business logic, message content, provider-specific error codes

---

## MessageSerializer

**Responsibilities:**

- **Knows**: JSON serialization, binary encoding, schema validation, performance optimization
- **Does**: Serializes EventEnvelope to bytes, deserializes bytes to EventEnvelope, validates message structure

**Collaborators:**

- **JsonSerializer**: Handles JSON encoding/decoding with serde
- **SchemaValidator**: Ensures message structure correctness
- **CompressionEngine**: Optional compression for large messages

**Roles:**

- **Data Transformer**: Converts between Rust types and wire format
- **Schema Guardian**: Ensures data structure integrity
- **Performance Optimizer**: Minimizes serialization overhead

**Boundaries:**

- **In**: Rust data structures and serialization configuration
- **Out**: Byte arrays suitable for queue transmission
- **Not Responsible For**: Message routing, business logic, provider-specific formats

---

## DeadLetterQueueManager

**Responsibilities:**

- **Knows**: Dead letter policies, failure metadata, replay procedures
- **Does**: Routes failed messages to DLQ, preserves failure context, enables message replay

**Collaborators:**

- **QueueProviders**: Sends messages to dead letter queues
- **FailureMetadataBuilder**: Constructs failure context information
- **ReplayCoordinator**: Handles moving messages back to main queues

**Roles:**

- **Failure Handler**: Manages messages that cannot be processed
- **Context Preserver**: Maintains debugging information for failed messages
- **Recovery Enabler**: Provides mechanisms for message replay and recovery

**Boundaries:**

- **In**: Failed messages and failure metadata
- **Out**: Dead letter queue operations and replay requests
- **Not Responsible For**: Determining what constitutes failure, business logic recovery

---

## Component Collaboration Patterns

### Message Send Flow

```
Application → QueueClient → Provider → Queue Service
                  ↓              ↓
            SessionManager → MessageSerializer
                  ↓              ↓
            RetryPolicy ← ErrorClassifier
```

**Collaboration Rules:**

1. **Provider Selection**: QueueClient trait allows runtime provider selection
2. **Session Coordination**: SessionManager generates IDs before provider send
3. **Serialization**: Messages serialized before provider-specific transmission
4. **Error Handling**: All errors flow through retry policy classification

### Message Receive Flow

```
Queue Service → Provider → QueueClient → Application
      ↓              ↓           ↓
MessageSerializer ← Receipt → SessionCoordinator
      ↓                           ↓
Application Processing → RetryPolicy → DeadLetterManager
```

**Collaboration Rules:**

1. **Deserialization**: Messages deserialized before application delivery
2. **Receipt Management**: Providers issue receipts for message lifecycle tracking
3. **Session Ordering**: Session coordination prevents concurrent processing
4. **Failure Handling**: Processing failures trigger retry or dead letter logic

### Configuration and Initialization Flow

```
Configuration → QueueClientFactory → Provider Selection
      ↓                    ↓                ↓
SessionStrategy → SessionManager → QueueClient
      ↓                    ↓                ↓
RetryPolicy → RetryPolicyEngine → ErrorHandling
```

**Collaboration Rules:**

1. **Factory Pattern**: QueueClientFactory creates appropriate provider implementations
2. **Strategy Injection**: Session and retry strategies configured at initialization
3. **Dependency Injection**: All components receive their dependencies at creation

### Error Handling and Recovery Flow

```
Operation Failure → ErrorClassifier → RetryPolicyEngine
         ↓                ↓                ↓
CircuitBreaker ← RetryDecision → BackoffCalculator
         ↓                ↓                ↓
FastFail ← Retry with Delay → DeadLetterManager
```

**Collaboration Rules:**

1. **Classification First**: All errors classified before retry decisions
2. **Circuit Protection**: Circuit breakers prevent cascading failures
3. **Contextual Retry**: Retry decisions consider error type and history
4. **Ultimate Fallback**: Dead letter queue captures all unrecoverable failures

## Cross-Provider Compatibility Matrix

| Feature | Azure Service Bus | AWS SQS | In-Memory | Notes |
|---------|-------------------|---------|-----------|-------|
| **Message Send** | ✅ Native | ✅ Native | ✅ Simulated | All providers support basic send |
| **Message Receive** | ✅ Native | ✅ Native | ✅ Simulated | All providers support basic receive |
| **Sessions** | ✅ Native | 🔄 Via FIFO | ✅ Simulated | Azure has native sessions, AWS uses message groups |
| **Dead Letter** | ✅ Native | ✅ Native | ✅ Simulated | All providers support DLQ patterns |
| **Batch Operations** | ✅ Native | ✅ Native | ✅ Simulated | Efficiency optimization across providers |
| **Duplicate Detection** | ✅ Native | ✅ FIFO Only | ✅ Simulated | Azure has broader duplicate detection |
| **TTL** | ✅ Native | ✅ Native | ✅ Simulated | Message expiration support |
| **Circuit Breaker** | 🔄 Client-side | 🔄 Client-side | 🔄 Client-side | Implemented in retry policy, not provider |

**Legend:**

- ✅ **Native**: Provider has built-in support
- 🔄 **Emulated**: Feature implemented in client library
- ❌ **Not Supported**: Feature unavailable for this provider

## Responsibility Matrix

| Component | Message Handling | Session Management | Error Handling | Provider Integration | Configuration |
|-----------|------------------|-------------------|----------------|---------------------|---------------|
| **QueueClient** | **Interface** | **Interface** | **Interface** | **Interface** | **Interface** |
| **AzureServiceBusClient** | **Azure Impl** | **Azure Sessions** | **Azure Errors** | **Own** | Use |
| **AwsSqsClient** | **AWS Impl** | **FIFO Groups** | **AWS Errors** | **Own** | Use |
| **InMemoryClient** | **Memory Impl** | **Simulated** | **Simulated** | **Own** | Use |
| **SessionManager** | - | **Own** | Report | Use | Use |
| **RetryPolicyEngine** | - | - | **Own** | - | Use |
| **MessageSerializer** | **Own** | - | Report | - | Use |
| **DeadLetterQueueManager** | **DLQ Only** | Preserve | **Own** | Use | Use |

**Legend:**

- **Own**: Primary responsibility and decision authority
- **Interface**: Defines contracts but delegates implementation
- **Impl**: Implements interfaces for specific providers
- **Use**: Consumes services but has no authority over them
- **Report**: Provides information but does not make decisions

This responsibility model ensures clear component boundaries while enabling provider-agnostic queue operations with consistent behavior across Azure Service Bus, AWS SQS, and testing environments.
