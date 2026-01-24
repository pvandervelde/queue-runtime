# ADR-003: Async-First Design

Status: Accepted
Date: 2026-01-24
Owners: queue-runtime team

## Context

The queue-runtime library is designed for high-throughput, scalable event processing in bot applications that must handle 1000+ messages/second. I/O operations (network calls, queue operations) are inherently asynchronous and non-blocking.

Design options:

- Blocking APIs with async wrapper - forces unnecessary thread allocation, reduces scalability
- Async APIs only - enables true non-blocking I/O, fits modern Rust ecosystem
- Hybrid (blocking + async) - doubles API surface, harder to maintain consistency

The Rust ecosystem has standardized on `tokio` for async runtime and `async-trait` for async trait methods.

## Decision

**All I/O operations must be asynchronous.**

- All `QueueProvider` and `SessionProvider` trait methods are `async`
- All client-facing APIs return `Future` types
- Use `#[async_trait]` from the `async-trait` crate for trait methods
- Require `tokio` runtime for execution (minimum required feature)
- No blocking I/O operations in async context (no `.blocking_*` without explicit separation)

Applications use `#[tokio::main]` or similar for the async runtime.

## Consequences

**Enables:**

- Single thread can handle thousands of concurrent messages (via tokio work-stealing runtime)
- Natural composition with other async libraries (tracing, metrics, etc.)
- Timeouts via `tokio::time::timeout` without thread overhead
- Cancellation patterns via `tokio::select!` for graceful shutdown
- Better resource utilization (fewer threads, more concurrent connections)

**Forbids:**

- Synchronous APIs (e.g., `receive()` returning `T` instead of `Future<Output=T>`)
- Blocking operations in async context (`.unwrap()` on blocking lock, synchronous DNS, etc.)
- Thread allocation for waiting (use `select!` or timeout instead)
- Mixing callback-based APIs with async/await

**Trade-offs:**

- Requires tokio runtime (adds dependency)
- Slightly more complex application code (async/await syntax)
- Harder to debug (stack traces across await points less obvious)
- Some operations may be harder to instrument (tracing setup more involved)

## Alternatives considered

### Option A: Synchronous blocking APIs

**Why not**: Forces one OS thread per concurrent message; cannot scale to 1000+ msg/sec on reasonable hardware; incompatible with modern Rust practices.

### Option B: Hybrid sync + async APIs

**Why not**: Doubles API surface, harder to test, inconsistent error handling between versions, maintenance burden increases.

### Option C: Callback-based async (without async/await)

**Why not**: Error handling becomes verbose; stack traces become unreadable; doesn't compose well with ecosystem libraries.

## Implementation notes

**Timeouts:**

```rust
// Good: Uses async timeout
match tokio::time::timeout(Duration::from_secs(30), client.receive()).await {
    Ok(Ok(msg)) => { /* process */ }
    Ok(Err(e)) => { /* handle error */ }
    Err(_) => { /* handle timeout */ }
}

// Bad: Blocks thread
thread::sleep(Duration::from_secs(5));
```

**Cancellation:**

```rust
// Good: Graceful shutdown via select!
tokio::select! {
    msg = client.receive() => { /* process */ }
    _ = shutdown_signal => { /* cleanup and return */ }
}

// Bad: Spawned task doesn't respect shutdown
tokio::spawn(client.receive());
```

**Resource cleanup:**

```rust
// Good: Cleanup on drop via Drop impl or explicit close
impl Drop for AzureServiceBusProvider {
    fn drop(&mut self) {
        // Close connections cleanly
    }
}

// Bad: Resources held until garbage collection (Rust doesn't have GC)
```

**Trait async methods:**

```rust
// Good: Using async-trait
use async_trait::async_trait;

#[async_trait]
pub trait QueueProvider {
    async fn send(&self, message: Message) -> Result<MessageId, QueueError>;
}

// Bad: Manual impl Future (very verbose)
pub trait QueueProvider {
    fn send(&self, message: Message) -> Box<dyn Future<Output = ...>>;
}
```

**Testing async code:**

```rust
// Good: Use #[tokio::test]
#[tokio::test]
async fn test_receive_message() {
    let provider = InMemoryProvider::new();
    let msg = provider.receive().await.unwrap();
}

// Bad: Blocking .wait() (if available)
#[test]
fn test_receive_message() {
    let msg = block_on(provider.receive()).unwrap();
}
```

## Examples

**Basic async client usage:**

```rust
#[tokio::main]
async fn main() -> Result<()> {
    let config = ProviderConfig::AzureServiceBus(azure_config);
    let client = QueueClientFactory::create(config).await?;

    loop {
        match client.receive().await {
            Ok(message) => {
                if let Err(e) = process_message(&message).await {
                    client.abandon_message(&message.receipt).await?;
                } else {
                    client.complete_message(&message.receipt).await?;
                }
            }
            Err(e) => eprintln!("Receive failed: {}", e),
        }
    }
}
```

**Timeout with graceful handling:**

```rust
let result = tokio::time::timeout(
    Duration::from_secs(30),
    client.receive()
).await;

match result {
    Ok(Ok(msg)) => { /* success */ }
    Ok(Err(QueueError::SessionLocked { locked_until, .. })) => {
        tokio::time::sleep_until(locked_until.to_instant()).await;
    }
    Err(_timeout) => {
        tracing::warn!("Receive operation timed out");
    }
    Ok(Err(e)) => return Err(e),
}
```

## References

- [Tokio Runtime Documentation](https://tokio.rs/)
- [async-trait Crate](https://docs.rs/async-trait/)
- [Rust Async Book](https://rust-lang.github.io/async-book/)
- [Code Standards - Async/Await](../standards/code.md#asyncawait)
