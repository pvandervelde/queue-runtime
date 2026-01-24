# ADR-002: Session/Ordering Abstraction Across Providers

Status: Accepted
Date: 2026-01-24
Owners: queue-runtime team

## Context

Different cloud queue providers have different native capabilities for message ordering:

- **Azure Service Bus**: Native sessions with strict FIFO ordering per session
- **AWS SQS**: FIFO queues with message group IDs for ordering (only available in FIFO queue type)
- **Local development**: Often no built-in ordering support

Applications need predictable ordering guarantees (e.g., all webhook events for the same pull request processed in sequence), but the mechanism differs per provider. We need a unified abstraction that works identically across all providers while respecting each provider's capabilities and constraints.

## Decision

Create a **unified session abstraction** (`SessionProvider` trait) with provider-specific implementations:

1. **SessionId extraction**: Extract ordering key from message content using pluggable `SessionKeyExtractor` strategies
2. **Abstraction level**: Represent sessions as "logical grouping for ordering" regardless of native provider support
3. **Provider mapping**:
   - Azure: Use native sessions directly
   - AWS: Map to FIFO queue message groups (requires queue type selection)
   - In-memory: Emulate using ordered delivery per session key
4. **Session state**: `SessionInfo` tracks acquired time and lock expiry uniformly

Applications work with `SessionClient` trait and never need provider-specific session logic.

## Consequences

**Enables:**

- Same ordering semantics across Azure, AWS, and local development
- Switching providers without changing message ordering logic
- Pluggable session key extraction strategies (composite keys, fallback strategies, etc.)
- Testing ordering behavior in-memory before cloud deployment

**Forbids:**

- Provider-specific session features (e.g., Azure session properties) at the library level
- Hard-coded session IDs - must be extracted from message content for consistency
- Mixing session-based and non-session-based operations on same queue

**Trade-offs:**

- AWS FIFO queue requirement (must use FIFO queue type, not standard SQS)
- In-memory emulation slightly less performant than native (ordered delivery per session)
- Session lock management complexity increases with multi-region scenarios

## Alternatives considered

### Option A: Separate session and non-session APIs

**Why not**: Applications would need to choose ordering strategy upfront; harder to add ordering retroactively; duplicates business logic.

### Option B: Provider-specific session implementations

**Why not**: Applications must know which provider is being used to configure sessions correctly; breaks provider abstraction; code not portable across deployments.

### Option C: Always use provider-native sessions

**Why not**: Requires AWS FIFO queue for any ordering; Azure sessions would be under-utilized; no support for local testing with ordering.

## Implementation notes

**SessionKeyExtractor strategies:**

- `CompositeKeyStrategy`: Combine multiple message fields (e.g., PR ID + repo name)
- `FallbackStrategy`: Try primary key, fall back to secondary if missing
- `NoOrderingStrategy`: No ordering (each message separate session)
- Custom: Implement trait for application-specific extraction logic

**Session lock management:**

- Azure: Native lock renewal via `renew_session_lock()`
- AWS: Extend visibility timeout (simulates lock renewal)
- In-memory: Lock expiry simulated for testing

**Edge cases:**

- Session timeout while processing: Must abandon and retry from DLQ
- Clock skew between services: Validate timestamps, allow configurable clock tolerance
- Empty sessions: Clean up automatically after timeout

**Testing:**

- Use `InMemorySessionProvider` for deterministic testing
- Test session timeout scenarios explicitly
- Verify messages with same session key maintain order

## Examples

**Define session key extraction:**

```rust
use queue_runtime::{SessionKeyExtractor, CompositeKeyStrategy};

let session_strategy = CompositeKeyStrategy::new()
    .with_field("repository")
    .with_field("pull_request");
```

**Create session-based client:**

```rust
let client = SessionClientBuilder::new()
    .with_provider(provider)
    .with_session_extractor(session_strategy)
    .build()
    .await?;

// All messages with same PR are processed in order
let message = client.receive_session().await?;
```

**Handling session lock errors:**

```rust
match client.receive_session().await {
    Err(QueueError::SessionLocked { locked_until, .. }) => {
        // Session locked by another consumer, retry after lock expires
        tokio::time::sleep_until(locked_until.to_instant()).await;
    }
    result => result?,
}
```

## References

- [Sessions Spec](../spec/modules/sessions.md)
- [Architecture Spec - Session Management](../spec/architecture.md#session-management)
- [Azure Service Bus Sessions](https://learn.microsoft.com/en-us/azure/service-bus-messaging/message-sessions)
- [AWS SQS FIFO Queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/FIFO-queues-message-deduplication.html)
