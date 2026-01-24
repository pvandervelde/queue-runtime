# ADR-004: Runtime Provider Selection

Status: Accepted
Date: 2026-01-24
Owners: queue-runtime team

## Context

The queue-runtime library supports multiple cloud providers (Azure Service Bus, AWS SQS) with identical APIs. Applications need flexibility to choose providers based on deployment environment without recompilation or conditional compilation.

Design options:

- Compile-time feature flags (e.g., `azure` vs `aws`) - requires separate builds per provider, breaks deployment flexibility
- Runtime configuration enum - single binary works everywhere, provider chosen at startup
- Dependency injection framework - adds complexity, overkill for this use case

Most cloud-native applications deploy the same binary across environments (dev uses in-memory, staging uses Azure, production uses AWS). Feature flags break this pattern.

## Decision

**Provider selection happens at runtime via `ProviderConfig` enum and `QueueClientFactory`.**

- `ProviderConfig` is an enum with variants: `AzureServiceBus(AzureServiceBusConfig)`, `AwsSqs(AwsSqsConfig)`, `InMemory(InMemoryConfig)`
- `QueueClientFactory` is a factory function that inspects `ProviderConfig` and returns a `Box<dyn QueueClient>`
- Provider is selected at application startup, typically from environment variables or configuration files
- No compile-time feature flags for provider selection

This enables:

1. **Single binary deployment**: Same compiled binary works with all providers
2. **Flexible configuration**: Environment or config file determines provider
3. **Testing/development**: In-memory provider for local testing, cloud provider for CI/staging/production

## Consequences

**Enables:**

- Single Docker image deployable to any cloud environment
- Environment-driven configuration (no code changes needed)
- Easy development workflow (use in-memory locally, cloud provider in staging)
- Configuration management via environment variables, config files, or orchestration platforms

**Forbids:**

- Compile-time optimization based on known provider (all providers must be compiled in)
- Provider-specific features exposed in public API (e.g., Azure-only session properties)
- Static provider knowledge at compile time

**Trade-offs:**

- Binary size includes all provider SDKs (Azure SDK, AWS SDK) even if only one is used
- Slight runtime overhead for trait object indirection (negligible for I/O-bound workloads)
- Runtime errors if configuration is invalid (caught at startup, fail fast)

## Alternatives considered

### Option A: Compile-time feature flags

**Why not**:

- Requires building separate artifacts for each environment
- Prevents "immutable infrastructure" pattern (same artifact everywhere)
- CI pipelines become more complex (conditional builds)
- Example: Bot team builds with `--features azure` for Azure deployment, `--features aws` for AWS - two different binaries in the wild

### Option B: Auto-detection based on environment

**Why not**: Fragile (what if environment variables suggest one provider but credentials exist for another?), confusing error messages when auto-detection fails, harder to debug configuration issues.

### Option C: Provider detected dynamically per-operation

**Why not**: Inconsistent provider behavior within single application instance (confusing), harder to reason about, overhead per operation.

## Implementation notes

**Configuration from environment:**

```rust
let provider_type = std::env::var("QUEUE_PROVIDER").unwrap_or("inmemory");

let config = match provider_type.as_str() {
    "azure" => ProviderConfig::AzureServiceBus(
        AzureServiceBusConfig {
            connection_string: std::env::var("AZURE_CONNECTION_STRING")?,
            ..Default::default()
        }
    ),
    "aws" => ProviderConfig::AwsSqs(
        AwsSqsConfig {
            region: std::env::var("AWS_REGION")?,
            ..Default::default()
        }
    ),
    "inmemory" | _ => ProviderConfig::InMemory(InMemoryConfig::default()),
};
```

**Startup validation:**

- Create client at application startup to fail fast on configuration errors
- Don't wait until first message attempt to discover provider is misconfigured
- Log which provider was selected (helps debugging)

**Binary size consideration:**

- All provider SDKs compiled in (~5-10MB impact)
- Acceptable trade-off for deployment flexibility
- If binary size critical, consider feature flags as last resort (but impacts deployment flexibility)

## Examples

**Application startup with runtime provider selection:**

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Determine provider from environment
    let config = if let Ok(connection_string) = std::env::var("AZURE_CONNECTION_STRING") {
        tracing::info!("Using Azure Service Bus provider");
        ProviderConfig::AzureServiceBus(AzureServiceBusConfig {
            connection_string,
            queue_name: std::env::var("QUEUE_NAME")?,
            ..Default::default()
        })
    } else if std::env::var("AWS_REGION").is_ok() {
        tracing::info!("Using AWS SQS provider");
        ProviderConfig::AwsSqs(AwsSqsConfig {
            region: std::env::var("AWS_REGION")?,
            queue_name: std::env::var("QUEUE_NAME")?,
            ..Default::default()
        })
    } else {
        tracing::info!("Using in-memory provider (local development)");
        ProviderConfig::InMemory(InMemoryConfig::default())
    };

    // Create client - fails fast if configuration invalid
    let client = QueueClientFactory::create(config).await?;
    tracing::info!("Queue client initialized successfully");

    // Run message processing loop
    process_messages(client).await?;
    Ok(())
}
```

**Returning provider-agnostic client:**

```rust
pub struct QueueClientFactory;

impl QueueClientFactory {
    pub async fn create(config: ProviderConfig) -> Result<Box<dyn QueueClient>, QueueError> {
        match config {
            ProviderConfig::AzureServiceBus(azure_config) => {
                let provider = AzureServiceBusProvider::new(azure_config).await?;
                Ok(Box::new(StandardQueueClient::new(Box::new(provider))))
            }
            ProviderConfig::AwsSqs(aws_config) => {
                let provider = AwsSqsProvider::new(aws_config).await?;
                Ok(Box::new(StandardQueueClient::new(Box::new(provider))))
            }
            ProviderConfig::InMemory(memory_config) => {
                let provider = InMemoryProvider::new(memory_config);
                Ok(Box::new(StandardQueueClient::new(Box::new(provider))))
            }
        }
    }
}
```

## References

- [Architecture Spec - Runtime Selection](../spec/architecture.md#runtime-selection)
- [Hexagonal Architecture ADR](./ADR-001-hexagonal-architecture.md)
- [12-Factor App - Store Config in Environment](https://12factor.net/config)
