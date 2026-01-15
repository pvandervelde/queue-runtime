# Queue-Runtime Library Architecture

## Overview

The queue-runtime library applies **hexagonal architecture** (ports and adapters) to provide a provider-agnostic abstraction over cloud queue services. The architecture separates business logic (what the library does) from infrastructure concerns (how it connects to providers), enabling applications to switch between Azure Service Bus and AWS SQS without code changes.

## Architectural Principles

1. **Business Logic Independent**: Core queue operations independent of provider specifics
2. **Dependency Inversion**: Business logic depends on abstractions, not concrete providers
3. **Provider Abstraction**: Uniform interface hides provider differences
4. **Session Consistency**: Ordered processing works identically across providers
5. **Explicit Boundaries**: Clear separation between application, library core, and infrastructure

## Hexagonal Architecture Pattern

```mermaid
graph TB
    subgraph "Application Layer (Outside)"
        APP[Bot Applications]
    end

    subgraph "Library - Business Logic (Hexagon Core)"
        API[Queue Operations]
        SESSION[Session Management]
        MESSAGE[Message Handling]
        RETRY[Retry Logic]
        DLQ[Dead Letter Handling]
    end

    subgraph "Library - Ports (Interfaces)"
        PROV_PORT[Provider Port<br/>Queue Operations Interface]
        SESSION_PORT[Session Port<br/>Session Operations Interface]
    end

    subgraph "Library - Adapters (Outside)"
        AZURE[Azure Adapter]
        AWS[AWS Adapter]
        MEMORY[In-Memory Adapter]
    end

    subgraph "External Services"
        ASB[Azure Service Bus]
        SQS[AWS SQS]
    end

    APP -->|uses| API

    API --> MESSAGE
    API --> SESSION
    API --> RETRY
    API --> DLQ

    MESSAGE -->|depends on| PROV_PORT
    SESSION -->|depends on| SESSION_PORT
    RETRY -->|depends on| PROV_PORT
    DLQ -->|depends on| PROV_PORT

    PROV_PORT -.implements.- AZURE
    PROV_PORT -.implements.- AWS
    PROV_PORT -.implements.- MEMORY

    SESSION_PORT -.implements.- AZURE
    SESSION_PORT -.implements.- AWS

    AZURE -->|calls| ASB
    AWS -->|calls| SQS

    classDef app fill:#e8f5e8,stroke:#4caf50
    classDef core fill:#e3f2fd,stroke:#2196f3
    classDef port fill:#f3e5f5,stroke:#9c27b0
    classDef adapter fill:#fff3e0,stroke:#ff9800
    classDef external fill:#f9f9f9,stroke:#333

    class APP app
    class API,SESSION,MESSAGE,RETRY,DLQ core
    class PROV_PORT,SESSION_PORT port
    class AZURE,AWS,MEMORY adapter
    class ASB,SQS external
```

**Key Architectural Elements**:

- **Hexagon Core**: Business logic independent of providers (queue operations, sessions, retry, DLQ)
- **Ports**: Abstract interfaces defining operations needed by business logic
- **Adapters**: Provider-specific implementations of port interfaces
- **Dependency Direction**: Business logic → Ports ← Adapters (dependency inversion)

---

## Logical Component Boundaries

### Business Logic Layer (Core Hexagon)

**Purpose**: Implements provider-agnostic queue behavior and orchestration.

**Components**:

1. **Queue Operations**: Send, receive, complete, abandon, dead letter operations
2. **Session Management**: Session ID generation, session client lifecycle, FIFO ordering
3. **Message Handling**: Message structure, serialization helpers, metadata management
4. **Retry Logic**: Exponential backoff, error classification, circuit breaker
5. **Dead Letter Handling**: Poison message detection, DLQ routing, failure tracking
6. **Cryptography**: Message encryption/decryption, authentication, freshness validation

**Responsibilities**:

- Define queue operation semantics
- Coordinate message lifecycle
- Enforce session ordering constraints
- Manage retry policies and circuit breakers
- Track delivery counts and failure reasons
- Encrypt outgoing messages, decrypt incoming messages
- Validate message authenticity and freshness

**NOT Responsible For**:

- Provider-specific API calls
- Connection management to cloud services
- Provider authentication details
- Physical message transport
- Encryption key storage or rotation (application responsibility)

**Dependencies**:

- Business logic depends only on **Port interfaces**
- NO direct dependencies on provider adapters
- NO imports of Azure SDK or AWS SDK
- Cryptography depends on KeyProvider abstraction (application-provided)

---

### Port Layer (Abstraction Interfaces)

**Purpose**: Define contracts that provider implementations must satisfy.

**Traits Defined**:

1. **QueueProvider**: Queue operations (send, receive, complete, abandon, create_session_client)
2. **SessionProvider**: Session operations (receive, complete, abandon, renew_session_lock, close_session)

**Key Abstractions**:

- **QueueClient**: High-level API trait for application use
- **SessionClient**: High-level API trait for session-based processing
- **ProviderType**: Enum distinguishing Azure, AWS, or InMemory implementations
- **SessionSupport**: Enum indicating Native, Emulated, or Unsupported session capabilities

**Responsibilities**:

- Define behavioral contracts for providers
- Specify error handling expectations
- Document session support semantics

**NOT Responsible For**:

- How providers implement operations
- Provider-specific features beyond core abstractions

---

### Adapter Layer (Provider Implementations)

**Purpose**: Implement port interfaces for specific cloud providers.

**Provider Implementations**:

1. **AzureServiceBusProvider**:
   - Implements `QueueProvider` and `SessionProvider` traits using Azure Service Bus SDK
   - Native session support via Azure Service Bus sessions
   - Connection string and managed identity authentication
   - ProviderType: ProviderType::Azure

2. **AwsSqsProvider**:
   - Implements `QueueProvider` and `SessionProvider` traits using direct HTTP REST API calls
   - Emulated sessions via FIFO queues and message groups
   - IAM role, access key, and credential chain authentication
   - ProviderType: ProviderType::Aws

3. **InMemoryProvider**:
   - Implements `QueueProvider` trait using in-memory data structures
   - For testing and local development only
   - Simulates provider behaviors deterministically
   - ProviderType: ProviderType::InMemory

**Responsibilities**:

- Implement `QueueProvider` trait operations for provider-specific APIs
- Implement `SessionProvider` trait for session-capable providers (Azure, AWS FIFO)
- Handle provider authentication and connection management
- Translate provider-specific errors to `QueueError` variants
- Manage provider-specific resources (connections, HTTP clients, credential caches)

**NOT Responsible For**:

- Business logic (retry, circuit breaking, DLQ decisions defined in client layer)
- Cross-provider orchestration or switching
- Session ordering logic (enforced by cloud provider's native mechanisms)

---

## Dependency Relationships

### Dependency Flow Rules

**Rule 1: Business Logic → Abstractions**

- Business logic components depend only on `QueueProvider` and `SessionProvider` traits
- NO imports of concrete provider implementations (AzureServiceBusProvider, AwsSqsProvider) in client code
- Enforced by module visibility and trait bounds

**Rule 2: Providers → Trait Implementation**

- Provider implementations (`AzureServiceBusProvider`, `AwsSqsProvider`, `InMemoryProvider`) implement `QueueProvider` trait
- Session-capable providers (`AzureServiceBusProvider`, `AwsSqsProvider`) also implement `SessionProvider` trait
- Providers may depend on external SDKs or HTTP clients (Azure SDK, reqwest for AWS)
- Providers MUST NOT depend on other provider implementations

**Rule 3: Application → Client API**

- Applications use high-level client traits (`QueueClient`, `SessionClient`)
- Applications configure provider selection via `QueueClientFactory` at runtime
- Applications receive provider-agnostic `QueueError` results

**Visualization**:

```
Application Layer
    ↓ (uses)
Business Logic (depends on ↓)
    ↓ (abstractions only)
Port Layer (implemented by ↓)
    ↓ (concrete implementations)
Adapter Layer
    ↓ (calls)
External Services (Azure/AWS)
```

### Module Organization Principle

The architecture defines **logical boundaries**, not physical file structure. Implementation will follow language-appropriate organization:

- **Rust**: Modules by domain concept (client, message, session, error, provider)
- **Logical layers**: Enforced through module visibility and trait bounds
- **No "ports" or "adapters" folders**: Use domain names, not architectural terms

---

## Session Abstraction Strategy

### Session Ordering Requirements

**Goal**: Guarantee FIFO delivery of related messages regardless of provider.

**Provider Capabilities**:

| Provider | Mechanism | Library Support |
|----------|-----------|-----------------|
| Azure Service Bus | Native sessions | Direct mapping to port |
| AWS SQS | FIFO queues + message groups | Session ID → message group |
| In-Memory | Internal ordering | Simulated with locks |

**Abstraction Approach**:

1. **Uniform Interface**: SessionClient trait works identically across providers
2. **Capability Detection**: Providers advertise native vs emulated session support
3. **Session Strategy**: Pluggable algorithm for generating session IDs from message content
4. **Lock Semantics**: Exclusive session access enforced by provider or emulated

**Session Lifecycle**:

```
1. Application provides SessionStrategy
2. Strategy generates session ID from message
3. Message sent with session ID
4. Consumer accepts session (blocks until available)
5. SessionClient provides ordered message delivery
6. Consumer completes or abandons session
7. Session becomes available for other consumers
```

---

## Error Boundary Design

### Error Categories

**Transient Errors** (should retry):

- `ConnectionFailed`: Network issues, temporary unavailability
- `Timeout`: Operation exceeded time limit
- `ServiceThrottled`: Rate limit or quota exceeded temporarily

**Permanent Errors** (should NOT retry):

- `QueueNotFound`: Queue does not exist
- `AuthenticationFailed`: Invalid credentials
- `AuthorizationFailed`: Insufficient permissions
- `MessageTooLarge`: Message exceeds size limit
- `InvalidMessage`: Malformed message structure

**Lock/Session Errors** (special handling):

- `InvalidReceipt`: Receipt handle invalid or expired
- `SessionLockLost`: Session lock expired, acquired by another consumer
- `SessionNotFound`: Requested session does not exist

**Error Mapping**:

Providers map their specific errors to common categories:

```
Azure Service Bus          →  Common Error
---------------------         --------------
EntityNotFoundException    →  QueueNotFound
UnauthorizedException      →  AuthenticationFailed
MessageLockLostException   →  InvalidReceipt
ServiceBusException        →  ConnectionFailed

AWS SQS                    →  Common Error
---------------------         --------------
QueueDoesNotExist          →  QueueNotFound
AccessDenied               →  AuthorizationFailed
ReceiptHandleIsInvalid     →  InvalidReceipt
RequestThrottled           →  ServiceThrottled
```

### Error Context Preservation

Each error includes:

- **Error category**: For retry decision logic
- **Context**: Queue name, message ID, operation type
- **Source**: Original provider error (for debugging)
- **Timestamp**: When error occurred

---

## Configuration Boundaries

### Configuration Responsibility

**Application Provides**:

- Provider selection (Azure or AWS)
- Provider-specific credentials and endpoints
- Queue names for operations
- Timeouts and retry policies

**Library Validates**:

- Configuration structure and required fields
- Credential format (not authentication itself)
- Timeout ranges and retry parameters

**Provider Adapters Handle**:

- Connection establishment with credentials
- Authentication with cloud services
- Connection pooling and lifecycle

### Configuration Sources

Applications can load configuration from:

1. Environment variables (12-factor app style)
2. Configuration files (TOML, YAML, JSON)
3. Secret management systems (Key Vault, Secrets Manager)
4. Programmatic construction (builder pattern)

Library provides configuration structs compatible with `serde` for deserialization.

---

## Testing Boundaries

### Test Responsibilities by Layer

**Business Logic Tests** (Unit):

- Use mock providers (test doubles for ports)
- Verify orchestration logic (retry, circuit breaker, DLQ routing)
- Fast, deterministic, no external dependencies
- 100% coverage goal

**Adapter Tests** (Integration):

- Test against real or emulated provider services
- Verify provider-specific behavior and error mapping
- May be slower, require infrastructure
- Verify contract compliance

**Contract Tests** (Specification):

- Define expected behavior for all providers
- Each adapter must pass identical contract tests
- Ensures behavioral consistency across providers
- Serves as executable specification

**Application Tests** (End-to-End):

- Use in-memory provider for fast tests
- Optionally test against real services in CI
- Verify application message handling logic

---

## Extension Points

### Adding New Providers

To add a new provider (e.g., RabbitMQ, Google Pub/Sub):

1. Implement `QueueProvider` port trait
2. Implement `SessionProvider` port trait (if sessions needed)
3. Map provider errors to common `QueueError` variants
4. Pass contract test suite
5. Document provider-specific configuration

**No Changes Required** to:

- Business logic layer
- Existing adapters
- Application code using the library

### Adding New Features

**Feature Addition Pattern**:

1. If feature needed across all providers:
   - Add to port trait
   - Update all adapters to implement
   - Add to contract test suite

2. If feature provider-specific:
   - Add as optional trait method with default implementation
   - Document capability detection
   - Adapters opt-in to advanced feature

**Example**: Lock extension

- Add `extend_lock()` to provider port with default error implementation
- Adapters supporting lock extension override method
- Applications check capability before using

---

## Performance Boundaries

### Performance Responsibilities

**Business Logic Layer**:

- Minimize overhead in orchestration
- Avoid unnecessary memory allocations
- Efficient retry backoff calculations

**Provider Adapters**:

- Connection pooling and reuse
- Batch operations where provider supports
- Efficient serialization/deserialization

**Applications**:

- Concurrent processing with appropriate parallelism
- Message handler performance
- Scaling consumer instances

### Performance Targets

| Metric | Target | Owner |
|--------|--------|-------|
| Send latency (p95) | < 200ms | Adapter + Provider |
| Receive latency (p95) | < 200ms | Adapter + Provider |
| Business logic overhead | < 10ms | Business Logic |
| Memory per message | < 10 KB | All layers |
| Throughput per instance | > 1000 msg/s | All layers |

---

## Security Boundaries

### Security Responsibility by Layer

**Application Layer**:

- Message content validation
- Sensitive data handling in payloads
- Webhook signature verification
- Message signing/encryption if needed

**Business Logic Layer**:

- Does NOT inspect message bodies for security
- Relies on adapters for transport security
- Propagates errors without exposing credentials

**Provider Adapters**:

- Secure credential management (no logging)
- TLS for all network communication
- Certificate validation
- Credential refresh handling

**External Services**:

- Authentication and authorization
- Encryption at rest and in transit
- Access control to queues

---

## Summary: Architectural Boundaries

| Boundary | Inward (Depends On) | Outward (Depended On By) |
|----------|---------------------|--------------------------|
| **Application** | Business Logic API | Nothing (consumer of library) |
| **Business Logic** | Port abstractions only | Application |
| **Ports** | Nothing (pure interfaces) | Business Logic, Adapters |
| **Adapters** | Ports, Provider SDKs | Port implementations |
| **Providers** | Nothing (external services) | Adapters |

**Key Insight**: Business logic is the center, depending only on abstractions. Adapters are at the edges, knowing about both abstractions and concrete providers. This enables easy provider addition and testing without changing core logic.
