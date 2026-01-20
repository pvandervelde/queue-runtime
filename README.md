# queue-runtime

A provider-agnostic queue runtime for Rust, supporting Azure Service Bus and AWS SQS with session-based ordering.

## Features

- **Provider Agnostic** - Unified API for Azure Service Bus and AWS SQS
- **Session Management** - Ordered message processing with session support
- **Retry Logic** - Exponential backoff with jitter
- **Dead Letter Queues** - Automatic DLQ handling
- **Type Safe** - Strongly-typed message handling with serde
- **Observable** - Integrated metrics and tracing

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
