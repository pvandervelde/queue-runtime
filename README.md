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

- [API Documentation](https://docs.rs/queue-runtime)
- [Specification](docs/specs/)

## Examples

See the [examples/](examples/) directory for complete working examples.

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
