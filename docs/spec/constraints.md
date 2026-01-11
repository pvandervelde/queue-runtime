# Queue-Runtime Implementation Constraints

## Overview

This document defines the implementation rules and architectural boundaries that must be enforced when implementing the queue-runtime library. These constraints ensure provider-agnostic design, type safety, and consistent behavior across Azure Service Bus and AWS SQS implementations.

## Type System Constraints

### Branded Types

```rust
// All queue identifiers must use branded types
pub struct QueueName(String);
pub struct MessageId(String);
pub struct ReceiptHandle(String);
pub struct SessionId(String);

// Provider-specific IDs are hidden behind these abstractions
```

### Error Handling

- All queue operations MUST return `Result<T, QueueError>`
- Never use `panic!` in library code - all errors must be recoverable
- Provider-specific errors MUST be mapped to common `QueueError` variants
- Include full error context chains for debugging across provider boundaries

### Async Constraints

- All I/O operations MUST be async and cancellable via `CancellationToken`
- Use `tokio` as the async runtime (no `async-std` compatibility needed)
- All timeouts MUST be configurable and respect cancellation

## Module Boundary Constraints

### Core Library Structure

```
src/
├── client.rs        # QueueClient trait and core operations
├── message.rs       # Message types and operations
├── session.rs       # Session management types and logic
├── error.rs         # Error types and error handling
├── config.rs        # Configuration types and validation
├── providers/       # Cloud provider implementations
│   ├── mod.rs       # Provider trait definitions
│   ├── azure.rs     # Azure Service Bus implementation
│   └── aws.rs       # AWS SQS implementation (future)
└── testing/         # Test utilities and mocks
    ├── mod.rs
    └── mock.rs      # Mock implementations for testing
```

### Dependency Rules

- **Core modules** (client.rs, message.rs, session.rs) NEVER import from `providers/`
- **Provider trait definitions** (providers/mod.rs) define contracts, NEVER import from specific providers
- **Provider implementations** (providers/azure.rs, providers/aws.rs) implement traits, MAY import provider SDKs
- **Integration tests** MAY import from any module

## Provider Abstraction Constraints

### Configuration

- Each provider MUST implement `QueueProviderConfig` trait
- Configuration MUST be serializable via `serde`
- Sensitive values (connection strings) MUST be marked with `#[serde(skip)]`
- Provider selection MUST be runtime configurable

### Session Compatibility

```rust
// Session handling MUST gracefully degrade across providers
pub enum SessionSupport {
    Native,      // Provider has native sessions (Azure Service Bus)
    Emulated,    // Provider emulates sessions (AWS SQS via message groups)
    Unsupported, // Provider cannot support sessions (fail gracefully)
}
```

### Message Ordering

- FIFO ordering MUST be configurable per queue
- When FIFO is enabled:
  - Azure: Use session-enabled queues
  - AWS: Use FIFO queues with message groups
- When FIFO is disabled: Allow concurrent processing

## Performance Constraints

### Throughput

- Support minimum 1000 messages/second per queue instance
- Batch operations where provider supports it (Azure: 100 messages, AWS: 10 messages)
- Connection pooling MUST be implemented for providers that support it

### Resource Management

- Connection objects MUST be reusable and thread-safe
- Implement connection pooling with configurable min/max connections
- MUST support graceful shutdown with connection cleanup
- Memory usage MUST be bounded (no unbounded queues or caches)

### Timeouts

```rust
pub struct QueueTimeouts {
    pub connect_timeout: Duration,      // Default: 30s
    pub send_timeout: Duration,         // Default: 10s
    pub receive_timeout: Duration,      // Default: 30s
    pub visibility_timeout: Duration,   // Default: 5 minutes
}
```

## Security Constraints

### Credential Management

- Connection strings MUST be handled securely (no plaintext logging)
- Support Azure Managed Identity and AWS IAM roles where available
- Credential refresh MUST be handled automatically
- NEVER log or expose credentials in error messages

### Network Security

- MUST support TLS for all provider connections
- Certificate validation MUST be enabled by default
- Support corporate proxy configurations where needed

## Testing Constraints

### Unit Testing

- Core domain MUST have 100% test coverage
- Use test doubles for all port interfaces
- Never test against real cloud services in unit tests

### Integration Testing

- Provider adapters MUST have integration tests against real services
- Use test containers or cloud service emulators where possible
- Integration tests MUST clean up resources after execution

### Contract Testing

- Each provider adapter MUST pass the same contract test suite
- Contract tests verify behavioral compatibility across providers
- Include failure scenario testing (network errors, timeouts, etc.)

## Observability Constraints

### Logging

- Use structured logging via `tracing` crate
- Log levels:
  - `ERROR`: Provider connection failures, unrecoverable errors
  - `WARN`: Retry attempts, degraded functionality
  - `INFO`: Queue creation, successful operations
  - `DEBUG`: Message details, timing information
  - `TRACE`: Provider-specific protocol details

### Metrics

- Expose metrics via `metrics` crate compatible interfaces
- Required metrics:
  - Messages sent/received per queue
  - Operation latency (send, receive, complete)
  - Connection pool statistics
  - Error rates by error type

### Tracing

- Support distributed tracing via OpenTelemetry
- Propagate trace context across async boundaries
- Include provider-specific span attributes for debugging

## Error Recovery Constraints

### Retry Policies

```rust
pub struct RetryPolicy {
    pub max_attempts: u32,           // Default: 3
    pub initial_delay: Duration,     // Default: 1s
    pub max_delay: Duration,         // Default: 30s
    pub backoff_multiplier: f64,     // Default: 2.0
}
```

### Circuit Breaker

- Implement circuit breaker for provider connections
- Circuit opens after 5 consecutive failures
- Half-open state after 30 seconds
- Full recovery after 3 successful operations

### Dead Letter Handling

- Support provider-native dead letter queues where available
- When provider doesn't support DLQ, implement client-side dead letter routing
- MUST preserve original message metadata and failure context

## Compatibility Constraints

### Rust Version

- Minimum Supported Rust Version (MSRV): 1.90
- Use edition = "2021"
- All public APIs MUST be `Send + Sync`

### Provider SDK Versions

- Azure Service Bus: Use latest stable `azure-service-bus` crate
- AWS SQS: Use latest stable `aws-sdk-sqs` crate
- Pin major version dependencies to prevent breaking changes

### Async Runtime

- Primary support: `tokio` 1.0+
- No `async-std` support required
- All timers and I/O MUST use tokio primitives

## Deployment Constraints

### Binary Size

- Library MUST compile with minimal feature flags for embedded use
- Provider adapters MUST be optional features:

  ```toml
  [features]
  azure = ["azure-service-bus"]
  aws = ["aws-sdk-sqs"]
  ```

### Memory Usage

- No global state or singleton patterns
- All configuration MUST be instance-based
- Support multiple concurrent queue clients in same process

## Documentation Constraints

### API Documentation

- All public APIs MUST have rustdoc comments with examples
- Include provider-specific behavior differences in documentation
- Document error conditions and recovery strategies

### Examples

- Provide working examples for each provider
- Include common usage patterns (send, receive, sessions)
- Show configuration examples for different deployment scenarios
