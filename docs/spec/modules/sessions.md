# Session Management Module

The session management module provides a **generic, domain-agnostic** framework for session key generation that enables ordered message processing for any application domain.

## Overview

**Critical Design Principle**: This module is intentionally **NOT GitHub-specific**. It provides infrastructure for session-based ordering without assuming any specific message structure or business domain (GitHub events, e-commerce orders, IoT telemetry, financial transactions, etc.).

The module provides:

1. **SessionKeyExtractor**: Trait for messages to expose metadata
2. **SessionKeyGenerator**: Strategy trait for generating session keys
3. **Pre-built Strategies**: Common patterns for session key generation
4. **Composable Design**: Strategies can be combined and chained

## Core Concepts

### Session Keys

Session keys are strings that group related messages for FIFO ordered processing. Messages with the same session key are guaranteed to be delivered in the order they were sent.

**Session Key Purpose**:

- Group related messages (e.g., all orders for a customer)
- Ensure FIFO delivery within each group
- Allow concurrent processing of different groups
- Provide ordering semantics application can rely on

**Example Session Keys**:

- `order-12345` - All events for order 12345
- `user-alice-cart` - All cart events for user Alice
- `tenant-123-resource-456` - All resource events for tenant 123's resource 456
- `github/owner/repo/pr/42` - All events for PR #42 in owner/repo

### No Ordering

Returning `None` from a session key generator allows **concurrent processing** without ordering constraints. Use for stateless operations that don't require message ordering.

## Core Traits

### SessionKeyExtractor

Trait for extracting metadata from messages. Messages implement this trait to expose data that session key generators can use.

**Trait Definition**:

```rust
pub trait SessionKeyExtractor {
    /// Get a metadata value by key
    ///
    /// Returns `None` if the key doesn't exist or has no value
    fn get_metadata(&self, key: &str) -> Option<String>;

    /// List all available metadata keys for this message
    ///
    /// Useful for debugging and introspection
    fn list_metadata_keys(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get all metadata as a map (optional, for bulk operations)
    fn get_all_metadata(&self) -> HashMap<String, String> {
        /* default implementation provided */
    }
}
```

**Design Philosophy**:

- **Key-Value Interface**: Messages expose named fields without assuming structure
- **No Assumptions**: Works with any message type or domain
- **Pull-Based**: Generators query for data they need

**Example Implementation** (E-commerce):

```rust
use queue_runtime::sessions::SessionKeyExtractor;

struct OrderEvent {
    order_id: String,
    customer_id: String,
    warehouse_id: String,
    timestamp: DateTime<Utc>,
}

impl SessionKeyExtractor for OrderEvent {
    fn get_metadata(&self, key: &str) -> Option<String> {
        match key {
            "order_id" => Some(self.order_id.clone()),
            "customer_id" => Some(self.customer_id.clone()),
            "warehouse_id" => Some(self.warehouse_id.clone()),
            "timestamp" => Some(self.timestamp.to_rfc3339()),
            _ => None,
        }
    }

    fn list_metadata_keys(&self) -> Vec<String> {
        vec![
            "order_id".to_string(),
            "customer_id".to_string(),
            "warehouse_id".to_string(),
            "timestamp".to_string(),
        ]
    }
}
```

**Example Implementation** (IoT):

```rust
struct TelemetryEvent {
    device_id: String,
    sensor_type: String,
    reading: f64,
}

impl SessionKeyExtractor for TelemetryEvent {
    fn get_metadata(&self, key: &str) -> Option<String> {
        match key {
            "device_id" => Some(self.device_id.clone()),
            "sensor_type" => Some(self.sensor_type.clone()),
            "reading" => Some(self.reading.to_string()),
            _ => None,
        }
    }
}
```

### SessionKeyGenerator

Strategy trait for generating session keys from message metadata. Different implementations provide different ordering semantics.

**Trait Definition**:

```rust
pub trait SessionKeyGenerator: Send + Sync {
    /// Generate a session key for the given message
    ///
    /// Returns `None` if the message should not be session-ordered,
    /// allowing concurrent processing without ordering constraints
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId>;
}
```

**Design Principles**:

- **Strategy Pattern**: Different strategies provide different grouping semantics
- **Optional Ordering**: Returning `None` allows concurrent processing
- **Composable**: Strategies can be combined (see FallbackStrategy)
- **Thread-Safe**: `Send + Sync` for use in async contexts

**Example Implementation**:

```rust
use queue_runtime::sessions::{SessionKeyGenerator, SessionKeyExtractor};
use queue_runtime::message::SessionId;

struct OrderSessionStrategy;

impl SessionKeyGenerator for OrderSessionStrategy {
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        extractor.get_metadata("order_id")
            .and_then(|id| SessionId::new(format!("order-{}", id)).ok())
    }
}
```

## Pre-Built Strategies

### SingleFieldStrategy

Generates session keys from a single metadata field with optional prefix.

**Use Cases**:

- Order by entity ID
- Group by user ID
- Partition by tenant ID

**Construction**:

```rust
/// Create single field strategy
pub fn new(field_name: &str, prefix: Option<&str>) -> Self;
```

**Example**:

```rust
use queue_runtime::sessions::SingleFieldStrategy;

// Session keys like "order-12345"
let strategy = SingleFieldStrategy::new("order_id", Some("order"));

// Session keys like "12345" (no prefix)
let strategy = SingleFieldStrategy::new("order_id", None);
```

**Behavior**:

- Extracts single field from message
- Adds optional prefix
- Returns `None` if field is missing
- Validates session ID format

**Usage Scenarios**:

```rust
// E-commerce: Order by customer
let customer_strategy = SingleFieldStrategy::new("customer_id", Some("customer"));

// IoT: Order by device
let device_strategy = SingleFieldStrategy::new("device_id", Some("device"));

// Multi-tenant: Order by tenant
let tenant_strategy = SingleFieldStrategy::new("tenant_id", Some("tenant"));
```

### CompositeKeyStrategy

Generates session keys by composing multiple metadata fields with a separator.

**Use Cases**:

- Hierarchical grouping (tenant + resource)
- Multi-dimensional ordering (region + customer)
- Compound keys (owner + repo + entity)

**Construction**:

```rust
/// Create composite key strategy
pub fn new(fields: Vec<String>, separator: &str) -> Self;
```

**Example**:

```rust
use queue_runtime::sessions::CompositeKeyStrategy;

// Session keys like "tenant-123-resource-456"
let strategy = CompositeKeyStrategy::new(
    vec!["tenant_id".to_string(), "resource_id".to_string()],
    "-"
);

// Session keys like "us-west-2/customer-789"
let strategy = CompositeKeyStrategy::new(
    vec!["region".to_string(), "customer_id".to_string()],
    "/"
);
```

**Behavior**:

- Extracts all specified fields in order
- Returns `None` if ANY field is missing
- Joins field values with separator
- Validates final session ID format

**Usage Scenarios**:

```rust
// Multi-tenant SaaS: tenant + user
let strategy = CompositeKeyStrategy::new(
    vec!["tenant_id".to_string(), "user_id".to_string()],
    "-"
);

// E-commerce: warehouse + order
let strategy = CompositeKeyStrategy::new(
    vec!["warehouse_id".to_string(), "order_id".to_string()],
    "-"
);

// GitHub events: owner + repo + entity_type + entity_id
let strategy = CompositeKeyStrategy::new(
    vec!["owner".to_string(), "repo".to_string(), "entity_type".to_string(), "entity_id".to_string()],
    "/"
);
```

### NoOrderingStrategy

Disables session-based ordering, allowing all messages to be processed concurrently.

**Use Cases**:

- Stateless operations
- Notification delivery
- Independent message processing
- High-throughput scenarios

**Example**:

```rust
use queue_runtime::sessions::NoOrderingStrategy;

let strategy = NoOrderingStrategy;

// Always returns None - no ordering
let session_id = strategy.generate_key(&message); // None
```

**Behavior**:

- Always returns `None`
- All messages can be processed concurrently
- No ordering guarantees
- Maximum throughput

### FallbackStrategy

Tries multiple generators in order, using the first success. Provides fine-grained ordering with coarser fallbacks.

**Use Cases**:

- Entity-level ordering with repository fallback
- Specific-to-general ordering hierarchies
- Graceful degradation of ordering

**Construction**:

```rust
/// Create fallback strategy with ordered generators
pub fn new(generators: Vec<Box<dyn SessionKeyGenerator>>) -> Self;
```

**Example**:

```rust
use queue_runtime::sessions::{FallbackStrategy, SingleFieldStrategy, CompositeKeyStrategy};

// Try order-specific key, fall back to customer-level key
let primary = SingleFieldStrategy::new("order_id", Some("order"));
let fallback = SingleFieldStrategy::new("customer_id", Some("customer"));

let strategy = FallbackStrategy::new(vec![
    Box::new(primary),
    Box::new(fallback),
]);
```

**Behavior**:

- Tries each generator in order
- Returns first non-None result
- Returns None if all generators return None
- Allows fine-grained ordering with coarse fallback

**Usage Scenarios**:

```rust
// E-commerce: Order by line item, fall back to order, fall back to customer
let strategy = FallbackStrategy::new(vec![
    Box::new(SingleFieldStrategy::new("line_item_id", Some("item"))),
    Box::new(SingleFieldStrategy::new("order_id", Some("order"))),
    Box::new(SingleFieldStrategy::new("customer_id", Some("customer"))),
]);

// GitHub: PR-specific, fall back to repo-level
let strategy = FallbackStrategy::new(vec![
    Box::new(CompositeKeyStrategy::new(
        vec!["owner".to_string(), "repo".to_string(), "pr_number".to_string()],
        "/"
    )),
    Box::new(CompositeKeyStrategy::new(
        vec!["owner".to_string(), "repo".to_string()],
        "/"
    )),
]);
```

## Usage Patterns

### Basic Usage

```rust
use queue_runtime::sessions::{SessionKeyGenerator, SessionKeyExtractor, SingleFieldStrategy};
use queue_runtime::message::{Message, SessionId};
use bytes::Bytes;

// Your domain message type
struct OrderEvent {
    order_id: String,
    data: Vec<u8>,
}

// Implement metadata extraction
impl SessionKeyExtractor for OrderEvent {
    fn get_metadata(&self, key: &str) -> Option<String> {
        match key {
            "order_id" => Some(self.order_id.clone()),
            _ => None,
        }
    }
}

// Create strategy
let strategy = SingleFieldStrategy::new("order_id", Some("order"));

// Generate session key
let event = OrderEvent {
    order_id: "12345".to_string(),
    data: vec![1, 2, 3],
};

if let Some(session_id) = strategy.generate_key(&event) {
    // Create message with session ID for ordered processing
    let message = Message::new(Bytes::from(event.data))
        .with_session_id(session_id);

    // Send message
    client.send_message(&queue, message).await?;
}
```

### Multi-Tenant Application

```rust
use queue_runtime::sessions::CompositeKeyStrategy;

// Session keys like "tenant-123-resource-456"
let strategy = CompositeKeyStrategy::new(
    vec!["tenant_id".to_string(), "resource_id".to_string()],
    "-"
);

// Messages for same tenant+resource ordered
// Different tenant/resource combinations processed concurrently
```

### Optional Ordering

```rust
use queue_runtime::sessions::{FallbackStrategy, SingleFieldStrategy, NoOrderingStrategy};

// Try entity-specific ordering, fall back to no ordering
let strategy = FallbackStrategy::new(vec![
    Box::new(SingleFieldStrategy::new("entity_id", Some("entity"))),
    Box::new(NoOrderingStrategy),
]);

// If entity_id exists: ordered by entity
// If entity_id missing: concurrent processing
```

### Time-Partitioned Sessions

Applications can implement time-based partitioning to prevent hot sessions:

```rust
use queue_runtime::sessions::{SessionKeyGenerator, SessionKeyExtractor};
use queue_runtime::message::SessionId;
use chrono::{DateTime, Utc, Timelike};

struct TimePartitionedStrategy {
    base_strategy: Box<dyn SessionKeyGenerator>,
    partition_hours: u32,
}

impl SessionKeyGenerator for TimePartitionedStrategy {
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        // Get base session key
        let base_key = self.base_strategy.generate_key(extractor)?;

        // Add time partition
        let now = Utc::now();
        let partition = now.hour() / self.partition_hours;

        // Create partitioned key
        SessionId::new(format!("{}-p{}", base_key.as_str(), partition)).ok()
    }
}

// Usage: sessions rotate every 4 hours
let strategy = TimePartitionedStrategy {
    base_strategy: Box::new(SingleFieldStrategy::new("order_id", Some("order"))),
    partition_hours: 4,
};

// Produces: "order-12345-p0", "order-12345-p1", etc.
// Prevents single session from growing too large
```

## SessionLifecycleManager

Manager for session metadata and state tracking. **Note**: This is currently just a placeholder type in the implementation.

**Purpose** (Planned):

- Track active sessions
- Monitor session health (message rate, age)
- Detect stalled sessions
- Implement session timeout policies
- Provide session metrics

**Current Status**: Implementation pending - framework in place for future development.

## Design Principles

### Domain-Agnostic

This module makes **zero assumptions** about message content or business domain:

- No GitHub-specific types or logic
- No assumed message structure
- Works with any domain (e-commerce, IoT, finance, etc.)
- Applications implement `SessionKeyExtractor` for their domain

### Flexible Strategy Pattern

Different applications need different ordering semantics:

- **Single-field**: Simple entity-based ordering
- **Composite**: Hierarchical or multi-dimensional ordering
- **Fallback**: Fine-grained with coarse fallback
- **No ordering**: Concurrent processing
- **Custom**: Applications implement `SessionKeyGenerator` trait

### Composable

Strategies can be combined:

- Fallback chains provide multiple ordering levels
- Custom strategies wrap pre-built strategies
- Time-partitioning can wrap any strategy
- Applications build complex ordering logic from simple primitives

## Behavioral Assertions

### SessionKeyExtractor Assertions

1. **get_metadata returns None for unknown keys**: Messages don't error on missing fields
2. **get_metadata returns consistent values**: Same key returns same value (idempotent)
3. **list_metadata_keys lists all available keys**: Complete metadata enumeration

### SessionKeyGenerator Assertions

1. **Same message produces same session key**: Deterministic key generation (idempotent)
2. **Valid session IDs only**: Generated keys must pass SessionId validation
3. **None means concurrent processing**: Returning None allows parallel execution
4. **Generators are thread-safe**: Can be shared across async tasks (Send + Sync)

### Strategy-Specific Assertions

1. **SingleFieldStrategy returns None if field missing**: Graceful handling of missing data
2. **CompositeKeyStrategy requires all fields**: Returns None if any field missing
3. **FallbackStrategy tries in order**: First success returned, not all generators tried
4. **NoOrderingStrategy always returns None**: Guarantees concurrent processing

## Testing Strategy

### Unit Testing

- Test each strategy with mock messages
- Test edge cases (missing fields, invalid characters)
- Test SessionId validation in generated keys
- Test strategy composition (Fallback)

### Property-Based Testing

- Generate random metadata combinations
- Verify deterministic key generation
- Test SessionId validation with generated keys
- Verify thread safety with concurrent generation

### Domain Integration Testing

- Test strategies with real domain messages
- Verify ordering semantics in queue operations
- Test fallback behavior under various conditions
- Measure performance impact of session generation

## Usage Recommendations

### When to Use Sessions

**Use sessions when**:

- Messages for same entity must be processed in order
- State transitions require ordering (FSMs)
- Exactly-once semantics required at entity level
- Distributed coordination needed

**Don't use sessions when**:

- Messages are independent (stateless operations)
- High throughput is critical
- Order doesn't matter (notifications, alerts)
- Messages can be processed in parallel

### Choosing a Strategy

**SingleFieldStrategy**:

- Simple entity-based ordering
- One primary grouping dimension
- Clear entity identification

**CompositeKeyStrategy**:

- Hierarchical data (tenant → user → resource)
- Multi-dimensional ordering
- Compound business keys

**FallbackStrategy**:

- Fine-grained ordering when possible
- Graceful degradation to coarser ordering
- Mixed message types with different metadata

**NoOrderingStrategy**:

- Stateless operations
- Maximum throughput needed
- Order explicitly not required

**Custom Strategy**:

- Domain-specific ordering rules
- Complex business logic
- Time-based partitioning
- Dynamic ordering decisions

## Future Enhancements

Potential additions to this module:

1. **SessionLifecycleManager Implementation**: Active session tracking and health monitoring
2. **Dynamic Strategies**: Strategy selection based on message content
3. **Session Metrics**: Built-in instrumentation for session performance
4. **Time-Based Partitioning**: Pre-built time-partitioning wrapper
5. **Session Affinity**: Hint-based session routing to same worker
6. **Session State Storage**: External state store integration for stateful sessions
