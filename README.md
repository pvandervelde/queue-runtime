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

```rust
// TODO: Add quick start example
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
