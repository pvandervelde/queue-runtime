# ADR-001: Hexagonal Architecture for Provider Abstraction

Status: Accepted
Date: 2026-01-24
Owners: queue-runtime team

## Context

The queue-runtime library needs to support multiple cloud providers (Azure Service Bus, AWS SQS) while maintaining identical behavior and API across all of them. Different applications deploy to different cloud environments and need the flexibility to switch providers without code changes or recompilation.

Previous approaches considered:
- Provider-specific crates with feature flags (compile-time selection) - limits deployment flexibility
- Monolithic client with conditional logic - creates spaghetti code, harder to test
- Separate completely independent implementations - leads to API drift and duplication

## Decision

Use **Hexagonal Architecture** (Ports and Adapters pattern) to separate business logic from provider implementations:

- **Hexagon (Core)**: Provider-agnostic queue operations, session management, retry logic, message handling
- **Ports (Interfaces)**: `QueueProvider` and `SessionProvider` traits defining operation contracts
- **Adapters (Implementations)**: Azure, AWS, and in-memory implementations of the port interfaces
- **Dependency Direction**: Business logic depends only on port abstractions, never on concrete adapters

This enables runtime provider selection via `QueueClientFactory` based on `ProviderConfig` determined at application startup.

## Consequences

**Enables:**
- Single codebase supporting all providers
- Runtime provider selection without recompilation
- Easy testing against in-memory implementation
- Clear boundaries between business logic and provider concerns
- Adding new providers without touching core logic

**Forbids:**
- Provider-specific optimizations in core business logic
- Compile-time provider selection via feature flags
- Direct imports of provider-specific SDKs (Azure SDK, AWS SDK) in business logic

**Trade-offs:**
- Slightly larger binary (all providers compiled in)
- Potential for provider-specific APIs to diverge if not careful
- Some performance optimization opportunities sacrificed for abstraction consistency

## Alternatives considered

### Option A: Feature-flag-based compile-time selection
**Why not**: Requires recompilation to change providers; breaks deployment flexibility. Users deploying same application across Azure and AWS would need separate builds.

### Option B: Monolithic client with conditional logic
**Why not**: Core business logic becomes polluted with provider-specific branches; difficult to test in isolation; new providers require touching core logic.

### Option C: Separate, independent crate per provider
**Why not**: API drift over time; duplication of business logic (retry, sessions, errors); harder to maintain consistency.

## Implementation notes

**Key boundaries:**
- Core business logic never imports `azure_core`, `aws_sdk_sqs`, or provider-specific types
- All provider-specific code lives in `src/providers/` subdirectory
- Port interfaces (`QueueProvider`, `SessionProvider`) must be provider-neutral

**Testing strategy:**
- Unit tests use `InMemoryProvider` for speed and determinism
- Integration tests should test against all three providers (in CI)
- Contract tests verify each adapter implements port interfaces correctly

**Adding new providers:**
1. Create new directory under `src/providers/new_provider/`
2. Implement `QueueProvider` and `SessionProvider` traits
3. Add `ProviderConfig::NewProvider` variant
4. Update `QueueClientFactory` to instantiate new provider
5. Add tests using shared test patterns

## Examples

**Provider-agnostic business logic:**
```rust
// This code works identically with Azure, AWS, or InMemory providers
impl StandardQueueClient {
    pub async fn receive_and_process(&self) -> Result<(), QueueError> {
        // Never knows which provider is being used
        let message = self.provider.receive().await?;
        // Process message...
        self.provider.complete_message(&message.receipt).await?;
    }
}
```

**Runtime provider selection:**
```rust
let config = ProviderConfig::AzureServiceBus(azure_config);
// Factory returns Box<dyn QueueClient> without exposing provider type
let client = QueueClientFactory::create(config).await?;
```

## References

- [Architecture Spec](../spec/architecture.md)
- [Responsibilities Spec](../spec/responsibilities.md)
- Hexagonal Architecture: https://alistair.cockburn.us/hexagonal-architecture/
