# Repository Catalog - What Already Exists

**Purpose:** Prevent reinventing wheels. Check here before creating new modules, helpers, or utilities.

Last updated: 2026-01-24

---

---

## How to Use This Catalog

**Before creating anything:**

1. Search this file for similar functionality
2. Check the linked README/docs for usage
3. If similar exists, use or extend it (don't duplicate)
4. If creating something new, add it here

**Keeping this updated:**

- When adding a module: Document it here
- When adding a utility: Document it here
- Review quarterly to remove deprecated items

---

## Core Traits & Types

### QueueProvider

- **Location**: [src/provider.rs](src/provider.rs)
- **Purpose**: Abstract interface for queue operations (send, receive, complete, abandon)
- **Implementations**: AzureServiceBusProvider, AwsSqsProvider, InMemoryProvider
- **Use When**: Implementing new queue backend or testing code against any provider
- **Note**: All business logic depends on this trait, never on concrete implementations

### SessionProvider

- **Location**: [src/sessions.rs](src/sessions.rs)
- **Purpose**: Session-based (ordered) message delivery
- **Implementations**: AzureSessionProvider, AwsSqsSessionProvider (emulated), InMemorySessionProvider
- **Use When**: Need FIFO ordering guarantees for related messages
- **Note**: See ADR-002 for session abstraction design rationale

### SessionKeyExtractor

- **Location**: [src/sessions.rs](src/sessions.rs)
- **Purpose**: Pluggable strategy for determining session IDs from messages
- **Implementations**: CompositeKeyStrategy, FallbackStrategy, NoOrderingStrategy
- **Use When**: Need custom logic for grouping related messages based on content
- **Example**: Extract PR number from GitHub webhook to ensure all events for same PR are processed in order

### QueueError & Retry Classification

- **Location**: [src/error.rs](src/error.rs)
- **Purpose**: Standardized error types with `is_transient()` and `should_retry()` methods
- **Key Methods**:
  - `is_transient()` - Returns true for temporary errors (connection failures, timeouts)
  - `should_retry()` - Returns true if operation should be retried
  - `retry_after()` - Returns suggested delay before retry
- **Use When**: Implementing retry logic or error handling
- **Note**: All error variants must implement these methods

### Message Types

- **Location**: [src/message.rs](src/message.rs)
- **Types**: Message, ReceivedMessage, ReceiptHandle, MessageId, SessionId, QueueName, Timestamp
- **Use When**: Working with message abstractions across providers
- **Note**: All ID types are newtype wrappers for type safety

## Configuration

### ProviderConfig

- **Location**: [src/provider.rs](src/provider.rs)
- **Variants**: AzureServiceBusConfig, AwsSqsConfig, InMemoryConfig
- **Use When**: Setting up runtime provider selection
- **Note**: Chosen at runtime, not compile-time. See ADR-004 for rationale

### QueueClientFactory

- **Location**: [src/client.rs](src/client.rs)
- **Purpose**: Creates appropriate client based on ProviderConfig (runtime selection)
- **Use When**: Need provider-agnostic client initialization
- **Pattern**: Factory returns `Box<dyn QueueClient>` for polymorphism at runtime

## Testing Utilities

### InMemoryProvider & InMemorySessionProvider

- **Location**: [src/providers/memory.rs](src/providers/memory.rs)
- **Purpose**: Thread-safe in-memory queue for unit/integration tests
- **Use When**: Testing without external dependencies, deterministic testing
- **Advantages**: Fast, no network calls, deterministic ordering, easy to verify state
- **Limitations**: Single-process only, not suitable for distributed testing
