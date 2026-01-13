# Queue Runtime - Architectural Tradeoffs

## Overview

This document analyzes the key architectural decisions made in queue-runtime, evaluating alternatives and documenting the rationale behind chosen approaches. Each tradeoff includes context, options considered, decision made, and consequences.

---

## Tradeoff 1: Provider Abstraction Strategy

### Context

Need to support multiple cloud queue providers (Azure Service Bus, AWS SQS) with a unified API while preserving provider-specific capabilities like sessions and FIFO ordering.

### Options Considered

#### Option A: Lowest Common Denominator

Abstract only features available in all providers.

**Pros**:

- Simplest implementation
- Perfect portability guaranteed
- No provider-specific code paths

**Cons**:

- Loses powerful features like Azure sessions
- Forces awkward workarounds for ordering
- Limits what applications can achieve

#### Option B: Full Feature Exposure

Expose all provider features through trait methods, with optional implementations.

**Pros**:

- Maximum flexibility
- No capabilities lost
- Advanced users can leverage everything

**Cons**:

- Leaky abstraction - provider details visible
- Portability challenges - code becomes provider-dependent
- Complex API with many optional methods

#### Option C: Common Core + Provider Extensions (CHOSEN)

Define core queue operations that all providers must implement, plus optional extensions for capabilities like sessions.

**Pros**:

- Balances portability with capability
- Core operations work everywhere
- Advanced features available where supported
- Graceful degradation possible

**Cons**:

- More complex than Option A
- Requires careful trait design
- Some features need emulation layer

### Decision: Option C - Common Core + Extensions

**Rationale**:

- Sessions are critical for GitHub bot use cases (ordering per PR)
- Full abstraction (Option A) would force reimplementing ordering in application code
- Provider-specific APIs (Option B) defeat purpose of abstraction
- Graceful degradation allows AWS to emulate sessions via FIFO message groups

**Consequences**:

- `QueueClient` trait defines core operations (send, receive, complete)
- Session support abstracted through `SessionClient` trait
- AWS SQS uses message groups to emulate Azure-style sessions
- Applications can detect session support level if needed

---

## Tradeoff 2: Session ID Generation

### Context

Applications need ordered processing for related messages (e.g., all events for PR #123), but shouldn't embed queue-specific logic.

### Options Considered

#### Option A: Application-Specified Session IDs

Applications provide session IDs explicitly when sending messages.

**Pros**:

- Maximum control for applications
- Simple library implementation
- Clear responsibility boundary

**Cons**:

- Applications must understand session semantics
- Inconsistent session ID formats across bots
- Hard to change session strategy later

#### Option B: Automatic Session ID Generation

Library analyzes message content and generates session IDs automatically.

**Pros**:

- Applications don't need queue knowledge
- Consistent session ID format
- Can optimize session distribution

**Cons**:

- Requires message inspection (coupling)
- Hard to customize for different use cases
- May not match application's grouping needs

#### Option C: Pluggable Session Strategy (CHOSEN)

Applications provide a `SessionStrategy` that generates session IDs from message content.

**Pros**:

- Flexible - applications control grouping logic
- Reusable strategies across bots
- Library enforces consistent application of strategy
- Easy to test and reason about

**Cons**:

- Slightly more complex than Option A
- Requires learning session strategy concept
- Strategy implementation is application responsibility

### Decision: Option C - Pluggable Session Strategy

**Rationale**:

- Different bots have different ordering requirements (PR-level, repo-level, issue-level)
- Session strategy makes grouping logic explicit and testable
- Library can provide common strategies (EntityBased, RepositoryBased) for convenience
- Allows changing strategy without modifying message sending code

**Consequences**:

- `SessionStrategy` trait defines `fn generate_session_id(&self, message: &Message) -> Option<SessionId>`
- Applications implement or use provided strategies
- Consistent session ID generation across all messages
- Strategy can be mocked/replaced for testing

---

## Tradeoff 3: Error Handling Strategy

### Context

Queue operations can fail in many ways (network errors, authentication failures, quota limits). Need consistent error handling across providers.

### Options Considered

#### Option A: Exceptions/Panics

Use Rust panics for errors, forcing applications to handle via `catch_unwind`.

**Pros**:

- Simple implementation
- Loud failures are visible

**Cons**:

- Goes against Rust conventions
- Hard to handle gracefully
- Poor error recovery
- Impossible to use with `?` operator

#### Option B: Provider-Specific Error Types

Each provider returns its own error type (AzureError, AwsError).

**Pros**:

- Preserves full error detail
- No information lost in translation
- Type system enforces error handling

**Cons**:

- Breaks abstraction - callers see provider details
- Different error handling per provider
- Hard to write provider-agnostic code
- Portability suffers

#### Option C: Common Error Enum (CHOSEN)

Define `QueueError` enum with variants for all error categories, containing provider-specific details as strings.

**Pros**:

- Provider-agnostic error handling
- Categorizes errors (transient vs permanent)
- Supports `?` operator naturally
- Error context preserved for debugging

**Cons**:

- Some error detail lost in mapping
- Cannot match on provider-specific error codes
- Requires careful error category design

### Decision: Option C - Common Error Enum

**Rationale**:

- Applications should handle errors by category (retry transient, fail permanent), not provider
- Debugging information preserved via error messages and context
- Idiomatic Rust with `Result<T, QueueError>`
- Enables consistent retry/DLQ behavior across providers

**Consequences**:

- `QueueError` enum has variants: `ConnectionFailed`, `AuthenticationFailed`, `QueueNotFound`, `MessageTooLarge`, `Timeout`, etc.
- Each variant includes context (queue name, message ID, underlying error)
- Provider implementations map native errors to common variants
- Retry logic operates on error categories, not specific codes

---

## Tradeoff 4: Async Runtime Choice

### Context

Library performs network I/O and must be async. Rust has multiple async runtimes (tokio, async-std, smol).

### Options Considered

#### Option A: Runtime Agnostic

Support all async runtimes via abstraction layer.

**Pros**:

- Maximum compatibility
- Works in any application
- No runtime forced on users

**Cons**:

- Significant complexity
- Performance overhead from abstraction
- Hard to use runtime-specific features
- More dependencies

#### Option B: Tokio Only (CHOSEN)

Require tokio as the async runtime.

**Pros**:

- Tokio is de facto standard for network I/O
- Azure and AWS SDKs already use tokio
- No abstraction overhead
- Can use tokio features directly
- Simpler implementation

**Cons**:

- Forces runtime choice on applications
- Cannot use with async-std or smol
- Couples to tokio versioning

### Decision: Option B - Tokio Only

**Rationale**:

- Tokio is the ecosystem standard for cloud SDKs
- Both Azure SDK and AWS SDK require tokio
- Runtime abstraction would add complexity without real benefit (no viable alternative)
- Applications using cloud services almost certainly already use tokio

**Consequences**:

- `tokio` is a required dependency
- All async traits require `Send + Sync` bounds
- Can use `tokio::time`, `tokio::sync` directly
- Applications must use tokio runtime

---

## Tradeoff 5: Message Type Design

### Context

Need to represent messages sent to and received from queues with metadata, while supporting serialization.

### Options Considered

#### Option A: Generic Message Container

Single generic `Message<T>` type that wraps any serializable payload.

**Pros**:

- Type-safe payloads
- Compile-time serialization checks
- Ergonomic with Rust generics

**Cons**:

- Forces generic parameters throughout API
- Complicates trait objects
- Harder to store mixed message types
- Provider implementations become complex

#### Option B: Opaque Bytes Only

Messages are just `Vec<u8>`, applications handle serialization.

**Pros**:

- Simple library implementation
- No serialization dependencies
- Maximum flexibility for applications

**Cons**:

- Repeated serialization code in applications
- Easy to make mistakes
- No standardization across bots
- Loses type safety benefits

#### Option C: Structured Message with Bytes Payload (CHOSEN)

Define `Message` struct with `Bytes` body and structured metadata, provide serialization helpers.

**Pros**:

- Consistent message structure across providers
- Metadata (session ID, correlation ID) built-in
- Serialization helpers available but optional
- No generic parameters in core API

**Cons**:

- Less compile-time type safety than Option A
- Applications must handle serialization explicitly
- Slightly more verbose than generic approach

### Decision: Option C - Structured Message with Bytes Payload

**Rationale**:

- Trait objects and runtime provider selection require non-generic API
- Structured metadata enables consistent session/correlation handling
- Serialization helpers (via serde) provide convenience without forcing specific formats
- Matches how underlying providers represent messages

**Consequences**:

- `Message` struct contains: `body: Bytes`, `session_id: Option<SessionId>`, `correlation_id: Option<String>`, `properties: HashMap<String, String>`
- Applications serialize payloads to bytes before sending
- Helper functions provided for common serialization (JSON, bincode)
- Provider implementations work with consistent message structure

---

## Tradeoff 6: Configuration Approach

### Context

Applications need to configure queue connections, credentials, timeouts, and retry policies.

### Options Considered

#### Option A: Builder Pattern

Fluent builder API for constructing clients: `QueueClient::builder().azure().connection_string(cs).build()`.

**Pros**:

- Ergonomic Rust API
- Type-safe configuration
- Compile-time validation

**Cons**:

- Hard to load from environment variables
- Configuration not easily serializable
- Harder to test with different configs

#### Option B: Configuration Files

YAML/TOML files loaded at runtime.

**Pros**:

- External configuration
- Easy to change without recompile
- Can version control separately

**Cons**:

- Requires file I/O
- Parse errors at runtime
- Less discoverable than code

#### Option C: Struct-Based Config with Serde (CHOSEN)

Configuration structs that can be built in code, loaded from environment, or deserialized from files.

**Pros**:

- Flexible - supports all config sources
- Serde integration for serialization
- Validation at deserialization time
- Can use `config` crate for layering

**Cons**:

- More verbose than builder pattern
- Requires understanding config structure
- Validation happens at runtime

### Decision: Option C - Struct-Based Config

**Rationale**:

- GitHub bots typically configure via environment variables (12-factor app)
- Need to support multiple config sources (env, files, code)
- Serde provides serialization for free
- Struct approach enables validation and testing

**Consequences**:

- `QueueRuntimeConfig` struct with provider-specific enums
- Serde `derive(Deserialize)` for environment loading
- Integration with `config` crate for layered configuration
- Validation methods on config structs

---

## Tradeoff 7: Testing Strategy

### Context

Need to test applications using queue-runtime without requiring real cloud services.

### Options Considered

#### Option A: Mock Trait Implementation

Provide mock implementation of `QueueClient` trait for testing.

**Pros**:

- No external dependencies for tests
- Fast test execution
- Deterministic behavior

**Cons**:

- Mocks don't test real provider behavior
- Can miss integration issues
- Divergence between mock and real implementations

#### Option B: Local Emulators

Use Azurite (Azure) and LocalStack (AWS) for testing.

**Pros**:

- Tests against real-ish implementations
- Catches more integration issues
- Closer to production behavior

**Cons**:

- Slow test execution
- Setup complexity
- Emulators may not match production exactly

#### Option C: In-Memory Provider + Contract Tests (CHOSEN)

Provide in-memory provider for unit tests, plus contract test suite that all providers must pass.

**Pros**:

- Fast unit tests with in-memory provider
- Contract tests ensure consistent behavior
- Can run contract tests against real services in CI
- Clear behavioral specification

**Cons**:

- Need to maintain both in-memory and contract tests
- Contract tests can be slow against real services
- In-memory provider may not catch all edge cases

### Decision: Option C - In-Memory Provider + Contract Tests

**Rationale**:

- Fast iteration for application developers using in-memory provider
- Contract tests ensure all providers behave identically
- Contract test suite serves as executable specification
- Can run contract tests nightly against real services for confidence

**Consequences**:

- `InMemoryQueueClient` provided for testing
- Contract test suite in `tests/contract/` directory
- All providers must pass identical contract tests
- CI runs contract tests against emulators and optionally real services

---

## Summary of Key Decisions

| Decision | Choice | Primary Rationale |
|----------|--------|-------------------|
| Provider Abstraction | Common Core + Extensions | Balances portability with capability |
| Session ID Generation | Pluggable Strategy | Flexibility for different ordering requirements |
| Error Handling | Common Error Enum | Provider-agnostic error handling by category |
| Async Runtime | Tokio Only | Ecosystem standard, no viable alternatives |
| Message Types | Structured with Bytes | Consistent metadata, no generic complexity |
| Configuration | Struct-Based with Serde | Supports multiple config sources flexibly |
| Testing | In-Memory + Contract Tests | Fast tests with behavioral guarantees |

These tradeoffs optimize for:

1. **Portability** - Applications can switch providers easily
2. **Capability** - Access to powerful features like sessions
3. **Simplicity** - Clean APIs without excessive abstraction
4. **Correctness** - Type safety and behavioral contracts
5. **Pragmatism** - Choices aligned with Rust ecosystem norms
