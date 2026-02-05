# queue-runtime

A **provider-agnostic queue abstraction** for Rust, enabling reliable message processing across cloud platforms with session-based ordering, automatic retries, and dead letter queue handling.

## Overview

`queue-runtime` provides a unified API for working with cloud message queues, currently supporting **Azure Service Bus** with **AWS SQS** support planned. Built with a hexagonal architecture, it allows applications to switch between providers without code changes while maintaining consistent behavior for session management, error handling, and message processing.

**Designed for**: GitHub bot applications and webhook processors that need reliable, ordered event processing with flexible deployment options.

### Why queue-runtime?

- **Write Once, Deploy Anywhere**: Single codebase works with Azure Service Bus or AWS SQS
- **Session-Based Ordering**: Process related messages in order (e.g., all events for one pull request)
- **Resilient by Default**: Automatic retries with exponential backoff, circuit breakers, and dead letter queues
- **Type-Safe**: Compile-time guarantees for message handling with serde serialization
- **Production-Ready**: Built-in observability with tracing and metrics, comprehensive error handling

### Architecture

`queue-runtime` uses **hexagonal architecture** (ports and adapters):

- **Core Business Logic**: Provider-agnostic queue operations, session management, retry logic
- **Port Interfaces**: Abstract traits defining queue and session operations
- **Provider Adapters**: Azure Service Bus implementation (AWS SQS coming soon)
- **In-Memory Provider**: For testing without external dependencies

This design ensures your business logic never depends directly on cloud provider SDKs, making testing easier and provider migration seamless.

### Supported Platforms

- **Rust**: 1.90 or later
- **Cloud Providers**:
  - ✅ Azure Service Bus (native session support)
  - 🚧 AWS SQS (planned - emulated sessions)
  - ✅ In-Memory (for testing)
- **Operating Systems**: Linux, Windows, macOS (x86_64 and ARM64)
- **Async Runtime**: Tokio 1.x

## Features

- **Provider Agnostic** - Unified `QueueClient` API works identically across Azure and AWS
- **Session Management** - Ordered FIFO processing with native or emulated session support
- **Retry Logic** - Configurable exponential backoff with jitter and circuit breakers
- **Dead Letter Queues** - Automatic DLQ routing for poison messages and exceeded retries
- **Type Safe** - Strongly-typed message handling with `serde` serialization/deserialization
- **Observable** - Integrated structured logging with `tracing` and metrics collection
- **Secure** - Credential management through Azure Identity SDK with managed identity support
- **Testable** - In-memory provider for unit tests with contract tests ensuring consistency

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
queue-runtime = "0.1.0"
```

## Quick Start

### Basic Message Sending and Receiving

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, InMemoryConfig};
use queue_runtime::{Message, QueueName};
use bytes::Bytes;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with in-memory provider
    let config = QueueConfig {
        provider: ProviderConfig::InMemory(InMemoryConfig::default()),
        ..Default::default()
    };
    let client = QueueClientFactory::create_client(config).await?;

    // Create queue name
    let queue = QueueName::new("my-queue".to_string())?;

    // Send a message
    let message = Message::new(Bytes::from("Hello, Queue!"));
    let message_id = client.send_message(&queue, message).await?;
    println!("Sent message: {}", message_id.as_str());

    // Receive a message
    let timeout = Duration::seconds(30);
    if let Some(received) = client.receive_message(&queue, timeout).await? {
        println!("Received: {:?}", String::from_utf8(received.body.to_vec()));

        // Mark as completed
        client.complete_message(received.receipt_handle).await?;
    }

    Ok(())
}
```

### Session-Based Ordered Processing

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, Message, QueueName, SessionId};
use bytes::Bytes;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = QueueClientFactory::create_test_client();
    let queue = QueueName::new("orders-queue".to_string())?;

    // Send messages with session ID for ordering
    let session_id = SessionId::new("order-12345".to_string())?;
    for i in 1..=5 {
        let mut message = Message::new(Bytes::from(format!("Order step {}", i)));
        message.session_id = Some(session_id.clone());
        client.send_message(&queue, message).await?;
    }

    // Accept session for ordered processing
    let session = client.accept_session(&queue, Some(session_id.clone())).await?;

    // Process messages in order
    while let Some(msg) = session.receive_message(Duration::seconds(5)).await? {
        println!("Processing: {:?}", String::from_utf8(msg.body.to_vec()));
        session.complete_message(msg.receipt_handle).await?;
    }

    Ok(())
}
```

### Azure Service Bus Example

```rust
use queue_runtime::{QueueClientFactory, QueueConfig, ProviderConfig, AzureServiceBusConfig};
use queue_runtime::{Message, QueueName};
use bytes::Bytes;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure Azure Service Bus
    let azure_config = AzureServiceBusConfig {
        connection_string: Some(std::env::var("AZURE_SERVICEBUS_CONNECTION_STRING")?),
        namespace: None,
        auth_method: queue_runtime::providers::AzureAuthMethod::ConnectionString,
        use_sessions: true,
        session_timeout: Duration::minutes(5),
    };

    let config = QueueConfig {
        provider: ProviderConfig::AzureServiceBus(azure_config),
        default_timeout: Duration::seconds(30),
        max_retry_attempts: 3,
        retry_base_delay: Duration::seconds(2),
        enable_dead_letter: true,
    };

    let client = QueueClientFactory::create_client(config).await?;
    let queue = QueueName::new("production-queue".to_string())?;

    // Send message with custom attributes
    let mut message = Message::new(Bytes::from(r#"{"event": "webhook"}"#));
    message.attributes.insert("source".to_string(), "github".to_string());
    message.attributes.insert("event_type".to_string(), "pull_request".to_string());

    client.send_message(&queue, message).await?;

    Ok(())
}
```

### Error Handling and Dead Letter Queues

```rust
use queue_runtime::{QueueClientFactory, QueueError, Message, QueueName};
use bytes::Bytes;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = QueueClientFactory::create_test_client();
    let queue = QueueName::new("processing-queue".to_string())?;

    // Receive and process with error handling
    let timeout = Duration::seconds(30);
    if let Some(received) = client.receive_message(&queue, timeout).await? {
        match process_message(&received.body).await {
            Ok(_) => {
                // Success - complete the message
                client.complete_message(received.receipt_handle).await?;
            }
            Err(e) if is_retryable(&e) => {
                // Transient error - abandon for retry
                println!("Transient error, will retry: {}", e);
                client.abandon_message(received.receipt_handle).await?;
            }
            Err(e) => {
                // Permanent error - send to dead letter queue
                println!("Permanent error, moving to DLQ: {}", e);
                client.dead_letter_message(
                    received.receipt_handle,
                    format!("Processing failed: {}", e)
                ).await?;
            }
        }
    }

    Ok(())
}

async fn process_message(body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Your processing logic here
    Ok(())
}

fn is_retryable(error: &Box<dyn std::error::Error>) -> bool {
    // Determine if error is transient
    error.to_string().contains("timeout") || error.to_string().contains("unavailable")
}
```

## Documentation

### API Reference

Complete API documentation is available at [docs.rs/queue-runtime](https://docs.rs/queue-runtime).

#### Core Types

- [`QueueClient`](https://docs.rs/queue-runtime/latest/queue_runtime/trait.QueueClient.html) - Main interface for queue operations
- [`SessionClient`](https://docs.rs/queue-runtime/latest/queue_runtime/trait.SessionClient.html) - Interface for session-based ordered processing
- [`QueueClientFactory`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.QueueClientFactory.html) - Factory for creating queue clients
- [`Message`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.Message.html) - Message structure for sending
- [`ReceivedMessage`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.ReceivedMessage.html) - Message structure for receiving

#### Configuration Types

- [`QueueConfig`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.QueueConfig.html) - Main configuration structure
- [`ProviderConfig`](https://docs.rs/queue-runtime/latest/queue_runtime/enum.ProviderConfig.html) - Provider-specific configuration
- [`AzureServiceBusConfig`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.AzureServiceBusConfig.html) - Azure Service Bus configuration
- [`AwsSqsConfig`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.AwsSqsConfig.html) - AWS SQS configuration
- [`InMemoryConfig`](https://docs.rs/queue-runtime/latest/queue_runtime/struct.InMemoryConfig.html) - In-memory provider configuration

#### Error Types

- [`QueueError`](https://docs.rs/queue-runtime/latest/queue_runtime/enum.QueueError.html) - Main error type for queue operations
- [`ValidationError`](https://docs.rs/queue-runtime/latest/queue_runtime/enum.ValidationError.html) - Validation error details
- [`ConfigurationError`](https://docs.rs/queue-runtime/latest/queue_runtime/enum.ConfigurationError.html) - Configuration error details

### Specifications

- [Architecture Overview](docs/spec/architecture.md) - System architecture and design principles
- [API Specification](docs/spec/README.md) - Complete specification documents
- [Provider Specifications](docs/spec/providers.md) - Provider-specific implementation details
- [Security Model](docs/spec/security.md) - Security considerations and best practices

### Module Documentation

- [Client Module](docs/spec/modules/client.md) - Queue client implementation
- [Messages](docs/spec/modules/messages.md) - Message handling and serialization
- [Sessions](docs/spec/modules/sessions.md) - Session-based ordering
- [Retry Logic](docs/spec/modules/retry.md) - Retry policies and exponential backoff
- [Dead Letter Queues](docs/spec/modules/dlq.md) - DLQ handling
- [Azure Provider](docs/spec/modules/azure.md) - Azure Service Bus implementation
- [AWS Provider](docs/spec/modules/aws.md) - AWS SQS implementation (planned)
- [Observability](docs/spec/modules/observability.md) - Logging and metrics

## Configuration

### Azure Service Bus Configuration

#### Connection String Authentication

The simplest way to connect to Azure Service Bus is using a connection string:

```rust
use queue_runtime::{QueueConfig, ProviderConfig, AzureServiceBusConfig};
use queue_runtime::providers::AzureAuthMethod;
use chrono::Duration;

let config = QueueConfig {
    provider: ProviderConfig::AzureServiceBus(AzureServiceBusConfig {
        connection_string: Some("Endpoint=sb://your-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=YOUR_KEY".to_string()),
        namespace: None,
        auth_method: AzureAuthMethod::ConnectionString,
        use_sessions: true,
        session_timeout: Duration::minutes(5),
    }),
    default_timeout: Duration::seconds(30),
    max_retry_attempts: 3,
    retry_base_delay: Duration::seconds(2),
    enable_dead_letter: true,
};
```

**Environment Variable Setup:**

```bash
export AZURE_SERVICEBUS_CONNECTION_STRING="Endpoint=sb://...;SharedAccessKey=..."
```

Then in your code:

```rust
let connection_string = std::env::var("AZURE_SERVICEBUS_CONNECTION_STRING")?;
let azure_config = AzureServiceBusConfig {
    connection_string: Some(connection_string),
    namespace: None,
    auth_method: AzureAuthMethod::ConnectionString,
    use_sessions: true,
    session_timeout: Duration::minutes(5),
};
```

#### Managed Identity Authentication (Recommended for Production)

For production deployments in Azure, use Managed Identity for passwordless authentication:

```rust
use queue_runtime::{AzureServiceBusConfig, AzureAuthMethod};
use chrono::Duration;

let azure_config = AzureServiceBusConfig {
    connection_string: None,
    namespace: Some("your-namespace".to_string()),
    auth_method: AzureAuthMethod::ManagedIdentity,
    use_sessions: true,
    session_timeout: Duration::minutes(5),
};
```

**Environment Variable Setup:**

```bash
# Only namespace required for managed identity
export AZURE_SERVICEBUS_NAMESPACE="your-namespace"
```

#### Service Principal Authentication

For development or CI/CD pipelines, use a service principal:

```rust
use queue_runtime::{AzureServiceBusConfig, AzureAuthMethod};
use chrono::Duration;

let azure_config = AzureServiceBusConfig {
    connection_string: None,
    namespace: Some(std::env::var("AZURE_SERVICEBUS_NAMESPACE")?),
    auth_method: AzureAuthMethod::ClientSecret {
        tenant_id: std::env::var("AZURE_TENANT_ID")?,
        client_id: std::env::var("AZURE_CLIENT_ID")?,
        client_secret: std::env::var("AZURE_CLIENT_SECRET")?,
    },
    use_sessions: true,
    session_timeout: Duration::minutes(5),
};
```

**Environment Variable Setup:**

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SERVICEBUS_NAMESPACE="your-namespace"
```

### AWS SQS Configuration (Planned)

AWS SQS support is planned for a future release. The configuration will support:

```rust
use queue_runtime::{QueueConfig, ProviderConfig, AwsSqsConfig};

let config = QueueConfig {
    provider: ProviderConfig::AwsSqs(AwsSqsConfig {
        region: "us-east-1".to_string(),
        access_key_id: Some(std::env::var("AWS_ACCESS_KEY_ID").ok()),
        secret_access_key: Some(std::env::var("AWS_SECRET_ACCESS_KEY").ok()),
        use_fifo_queues: true,
    }),
    default_timeout: Duration::seconds(30),
    max_retry_attempts: 3,
    retry_base_delay: Duration::seconds(2),
    enable_dead_letter: true,
};
```

### In-Memory Provider Configuration

For testing and development, use the in-memory provider:

```rust
use queue_runtime::{QueueConfig, ProviderConfig, InMemoryConfig};
use chrono::Duration;

let config = QueueConfig {
    provider: ProviderConfig::InMemory(InMemoryConfig {
        max_queue_size: 10000,
        enable_persistence: false,
        max_delivery_count: 3,
        default_message_ttl: Some(Duration::hours(24)),
        enable_dead_letter_queue: true,
        session_lock_duration: Duration::minutes(5),
    }),
    default_timeout: Duration::seconds(30),
    max_retry_attempts: 3,
    retry_base_delay: Duration::seconds(1),
    enable_dead_letter: true,
};
```

Or use the test factory for quick setup:

```rust
let client = QueueClientFactory::create_test_client();
```

### Retry Configuration

Configure automatic retry behavior for transient failures:

```rust
let config = QueueConfig {
    provider: /* your provider config */,
    default_timeout: Duration::seconds(30),
    max_retry_attempts: 5,              // Retry up to 5 times
    retry_base_delay: Duration::seconds(2),  // Start with 2s delay
    enable_dead_letter: true,
};
```

The retry mechanism uses **exponential backoff with jitter**:

- First retry: ~2 seconds
- Second retry: ~4 seconds
- Third retry: ~8 seconds
- And so on...

Messages that exceed `max_retry_attempts` are automatically moved to the dead letter queue if `enable_dead_letter` is true.

### Dead Letter Queue Configuration

Dead letter queues (DLQ) capture messages that cannot be processed successfully:

```rust
let config = QueueConfig {
    provider: /* your provider config */,
    enable_dead_letter: true,  // Enable automatic DLQ routing
    max_retry_attempts: 3,     // Move to DLQ after 3 failed attempts
    /* other settings */
};
```

**Manually sending to DLQ:**

```rust
if let Some(msg) = client.receive_message(&queue, timeout).await? {
    match process_message(&msg).await {
        Ok(_) => client.complete_message(msg.receipt_handle).await?,
        Err(e) => {
            // Send to DLQ with error reason
            client.dead_letter_message(
                msg.receipt_handle,
                format!("Processing failed: {}", e)
            ).await?;
        }
    }
}
```

### Session Configuration

Configure session-based ordered processing:

```rust
// Azure Service Bus (native session support)
let azure_config = AzureServiceBusConfig {
    connection_string: Some(connection_string),
    namespace: None,
    auth_method: AzureAuthMethod::ConnectionString,
    use_sessions: true,               // Enable session support
    session_timeout: Duration::minutes(5),  // Session lock timeout
};

// In-memory provider (for testing)
let memory_config = InMemoryConfig {
    session_lock_duration: Duration::minutes(5),  // Session lock timeout
    ..Default::default()
};
```

### Environment-Based Configuration

Create environment-specific configurations:

```rust
use queue_runtime::*;

pub fn create_queue_config() -> Result<QueueConfig, Box<dyn std::error::Error>> {
    let env = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());

    match env.as_str() {
        "production" => Ok(QueueConfig {
            provider: ProviderConfig::AzureServiceBus(AzureServiceBusConfig {
                connection_string: None,
                namespace: Some(std::env::var("AZURE_SERVICEBUS_NAMESPACE")?),
                auth_method: AzureAuthMethod::ManagedIdentity,
                use_sessions: true,
                session_timeout: Duration::minutes(5),
            }),
            default_timeout: Duration::seconds(60),
            max_retry_attempts: 5,
            retry_base_delay: Duration::seconds(2),
            enable_dead_letter: true,
        }),

        "staging" => Ok(QueueConfig {
            provider: ProviderConfig::AzureServiceBus(AzureServiceBusConfig {
                connection_string: Some(std::env::var("AZURE_SERVICEBUS_CONNECTION_STRING")?),
                namespace: None,
                auth_method: AzureAuthMethod::ConnectionString,
                use_sessions: true,
                session_timeout: Duration::minutes(5),
            }),
            default_timeout: Duration::seconds(30),
            max_retry_attempts: 3,
            retry_base_delay: Duration::seconds(2),
            enable_dead_letter: true,
        }),

        _ => Ok(QueueConfig {
            provider: ProviderConfig::InMemory(InMemoryConfig::default()),
            default_timeout: Duration::seconds(10),
            max_retry_attempts: 2,
            retry_base_delay: Duration::seconds(1),
            enable_dead_letter: false,
        }),
    }
}
```

### Configuration Best Practices

1. **Use Managed Identity in Production**: Avoid storing connection strings in code or environment variables for production deployments on Azure.

2. **Set Appropriate Timeouts**: Match `default_timeout` to your expected message processing time. Too short causes unnecessary retries; too long delays error detection.

3. **Configure Retry Limits**: Set `max_retry_attempts` based on your failure rate tolerance. More retries = higher success rate but longer delays.

4. **Enable Dead Letter Queues**: Always enable DLQ in production to prevent message loss and allow debugging failed messages.

5. **Session Timeout Balance**: Set `session_timeout` long enough for message processing but short enough to recover from failures quickly (typically 5-10 minutes).

6. **Environment-Specific Settings**: Use different retry and timeout values for development, staging, and production environments.

## Examples

See the [examples/](examples/) directory for complete working examples.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
