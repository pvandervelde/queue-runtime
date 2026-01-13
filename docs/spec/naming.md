# Queue Naming Strategy

This document defines the standardized naming conventions and patterns for queues, dead letter queues, and related resources across different deployment environments.

## Overview

Consistent queue naming is critical for:

- Clear identification of queue purpose and ownership
- Environment isolation and resource management
- Automated deployment and configuration
- Monitoring and observability
- Troubleshooting and operational support

## Naming Conventions

### Base Queue Naming Pattern

```
[prefix-]environment-botname[-suffix]
```

**Components:**

- **prefix** (optional): Organization or project prefix
- **environment**: Deployment environment (dev, staging, prod)
- **botname**: Bot service name in kebab-case
- **suffix** (optional): Special purpose suffix (dlq, retry, etc.)

### Standard Queue Names

#### Production Environment

```
prod-task-tactician
prod-merge-warden
prod-spec-sentinel
prod-security-scanner
prod-dependency-updater
```

#### Staging Environment

```
staging-task-tactician
staging-merge-warden
staging-spec-sentinel
```

#### Development Environment

```
dev-task-tactician
dev-merge-warden
dev-spec-sentinel
```

#### With Organization Prefix

```
offaxis-prod-task-tactician
offaxis-staging-merge-warden
offaxis-dev-spec-sentinel
```

### Dead Letter Queue Naming

Dead letter queues follow the base queue name with `-dlq` suffix:

```
prod-task-tactician-dlq
prod-merge-warden-dlq
staging-spec-sentinel-dlq
```

### Retry Queue Naming

Retry queues for delayed processing use `-retry` suffix:

```
prod-task-tactician-retry
prod-merge-warden-retry
```

### Session-Based Queue Naming

For providers that support multiple queues per bot (like SQS), session-based queues include the session strategy:

```
prod-task-tactician-entity
prod-task-tactician-repository
prod-merge-warden-fifo
```

## Naming Rules and Constraints

### General Rules

1. **Lowercase Only**: All queue names must be lowercase
2. **Kebab Case**: Use hyphens to separate words
3. **ASCII Characters**: Only letters, numbers, and hyphens
4. **Length Limits**: Maximum 50 characters total
5. **Unique Names**: No duplicate names within an environment

### Provider-Specific Constraints

#### Azure Service Bus

- Maximum length: 50 characters
- Valid characters: letters, numbers, hyphens
- Cannot start or end with hyphen
- Cannot have consecutive hyphens

#### AWS SQS

- Maximum length: 80 characters
- Valid characters: letters, numbers, hyphens, underscores
- FIFO queues must end with `.fifo`
- No periods except for FIFO suffix

#### FIFO Queue Names (AWS SQS)

```
prod-task-tactician.fifo
prod-merge-warden.fifo
staging-spec-sentinel.fifo
```

## Queue Naming Implementation

### QueueNaming Struct

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueNaming {
    /// Optional organization or project prefix
    pub prefix: Option<String>,

    /// Deployment environment
    pub environment: String,

    /// Provider-specific naming rules
    pub provider: QueueProvider,

    /// Maximum queue name length
    pub max_length: usize,
}

impl QueueNaming {
    pub fn new(environment: String, provider: QueueProvider) -> Self {
        let max_length = match provider {
            QueueProvider::AzureServiceBus => 50,
            QueueProvider::AwsSqs => 80,
            QueueProvider::InMemory => 100,
        };

        Self {
            prefix: None,
            environment,
            provider,
            max_length,
        }
    }

    /// Generate main queue name for a bot
    pub fn queue_name(&self, bot_name: &str) -> Result<String, NamingError> {
        let name = match &self.prefix {
            Some(prefix) => format!("{}-{}-{}", prefix, self.environment, bot_name),
            None => format!("{}-{}", self.environment, bot_name),
        };

        self.validate_name(&name)?;
        Ok(name)
    }

    /// Generate dead letter queue name
    pub fn dlq_name(&self, bot_name: &str) -> Result<String, NamingError> {
        let base_name = self.queue_name(bot_name)?;
        let dlq_name = format!("{}-dlq", base_name);

        self.validate_name(&dlq_name)?;
        Ok(dlq_name)
    }

    /// Generate retry queue name
    pub fn retry_name(&self, bot_name: &str) -> Result<String, NamingError> {
        let base_name = self.queue_name(bot_name)?;
        let retry_name = format!("{}-retry", base_name);

        self.validate_name(&retry_name)?;
        Ok(retry_name)
    }

    /// Generate session-specific queue name
    pub fn session_queue_name(&self, bot_name: &str, session_strategy: &str) -> Result<String, NamingError> {
        let base_name = self.queue_name(bot_name)?;
        let session_name = format!("{}-{}", base_name, session_strategy);

        self.validate_name(&session_name)?;
        Ok(session_name)
    }

    /// Generate FIFO queue name for AWS SQS
    pub fn fifo_name(&self, bot_name: &str) -> Result<String, NamingError> {
        if !matches!(self.provider, QueueProvider::AwsSqs) {
            return Err(NamingError::UnsupportedProvider {
                provider: format!("{:?}", self.provider),
                feature: "FIFO queues".to_string(),
            });
        }

        let base_name = self.queue_name(bot_name)?;
        let fifo_name = format!("{}.fifo", base_name);

        self.validate_name(&fifo_name)?;
        Ok(fifo_name)
    }

    /// Validate queue name against provider constraints
    pub fn validate_name(&self, name: &str) -> Result<(), NamingError> {
        // Check length
        if name.len() > self.max_length {
            return Err(NamingError::TooLong {
                name: name.to_string(),
                length: name.len(),
                max_length: self.max_length,
            });
        }

        // Check empty
        if name.is_empty() {
            return Err(NamingError::Empty);
        }

        // Provider-specific validation
        match self.provider {
            QueueProvider::AzureServiceBus => self.validate_azure_name(name)?,
            QueueProvider::AwsSqs => self.validate_aws_name(name)?,
            QueueProvider::InMemory => self.validate_memory_name(name)?,
        }

        Ok(())
    }

    fn validate_azure_name(&self, name: &str) -> Result<(), NamingError> {
        // Azure Service Bus naming rules
        if name.starts_with('-') || name.ends_with('-') {
            return Err(NamingError::InvalidFormat {
                name: name.to_string(),
                reason: "Cannot start or end with hyphen".to_string(),
            });
        }

        if name.contains("--") {
            return Err(NamingError::InvalidFormat {
                name: name.to_string(),
                reason: "Cannot contain consecutive hyphens".to_string(),
            });
        }

        for char in name.chars() {
            if !char.is_ascii_alphanumeric() && char != '-' {
                return Err(NamingError::InvalidCharacter {
                    name: name.to_string(),
                    character: char,
                });
            }
        }

        Ok(())
    }

    fn validate_aws_name(&self, name: &str) -> Result<(), NamingError> {
        // AWS SQS naming rules
        for char in name.chars() {
            if !char.is_ascii_alphanumeric() && char != '-' && char != '_' && char != '.' {
                return Err(NamingError::InvalidCharacter {
                    name: name.to_string(),
                    character: char,
                });
            }
        }

        // FIFO queues must end with .fifo
        if name.contains(".fifo") && !name.ends_with(".fifo") {
            return Err(NamingError::InvalidFormat {
                name: name.to_string(),
                reason: "FIFO suffix '.fifo' must be at the end".to_string(),
            });
        }

        Ok(())
    }

    fn validate_memory_name(&self, name: &str) -> Result<(), NamingError> {
        // In-memory queues have relaxed rules
        for char in name.chars() {
            if !char.is_ascii_alphanumeric() && char != '-' && char != '_' {
                return Err(NamingError::InvalidCharacter {
                    name: name.to_string(),
                    character: char,
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueueProvider {
    AzureServiceBus,
    AwsSqs,
    InMemory,
}
```

### Bot Queue Registry

```rust
use std::collections::HashMap;

/// Registry of all bot queue configurations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotQueueRegistry {
    pub naming: QueueNaming,
    pub bots: HashMap<String, BotQueueConfig>,
}

impl BotQueueRegistry {
    pub fn new(naming: QueueNaming) -> Self {
        Self {
            naming,
            bots: HashMap::new(),
        }
    }

    /// Register a bot with its queue configuration
    pub fn register_bot(&mut self, bot_name: String, config: BotQueueConfig) -> Result<(), NamingError> {
        // Validate the bot name
        let queue_name = self.naming.queue_name(&bot_name)?;

        self.bots.insert(bot_name, config);
        Ok(())
    }

    /// Get all queue names for a bot
    pub fn get_bot_queues(&self, bot_name: &str) -> Result<BotQueues, NamingError> {
        let config = self.bots.get(bot_name)
            .ok_or_else(|| NamingError::BotNotFound { bot_name: bot_name.to_string() })?;

        let main_queue = if config.enable_fifo && matches!(self.naming.provider, QueueProvider::AwsSqs) {
            self.naming.fifo_name(bot_name)?
        } else {
            self.naming.queue_name(bot_name)?
        };

        let dlq = if config.enable_dead_letter {
            Some(self.naming.dlq_name(bot_name)?)
        } else {
            None
        };

        let retry_queue = if config.enable_retry_queue {
            Some(self.naming.retry_name(bot_name)?)
        } else {
            None
        };

        Ok(BotQueues {
            main_queue,
            dead_letter_queue: dlq,
            retry_queue,
            session_queues: Vec::new(), // TODO: Add session queue support
        })
    }

    /// Get all queues in the registry
    pub fn all_queues(&self) -> Result<Vec<String>, NamingError> {
        let mut queues = Vec::new();

        for bot_name in self.bots.keys() {
            let bot_queues = self.get_bot_queues(bot_name)?;
            queues.push(bot_queues.main_queue);

            if let Some(dlq) = bot_queues.dead_letter_queue {
                queues.push(dlq);
            }

            if let Some(retry) = bot_queues.retry_queue {
                queues.push(retry);
            }
        }

        Ok(queues)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotQueueConfig {
    pub enable_sessions: bool,
    pub enable_dead_letter: bool,
    pub enable_retry_queue: bool,
    pub enable_fifo: bool,
    pub max_delivery_count: u32,
    pub message_ttl: Duration,
}

impl Default for BotQueueConfig {
    fn default() -> Self {
        Self {
            enable_sessions: true,
            enable_dead_letter: true,
            enable_retry_queue: false,
            enable_fifo: false,
            max_delivery_count: 3,
            message_ttl: Duration::from_hours(24),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BotQueues {
    pub main_queue: String,
    pub dead_letter_queue: Option<String>,
    pub retry_queue: Option<String>,
    pub session_queues: Vec<String>,
}
```

## Environment-Specific Configurations

### Development Environment

```rust
impl QueueNaming {
    pub fn development() -> Self {
        Self::new("dev".to_string(), QueueProvider::InMemory)
    }

    pub fn development_azure() -> Self {
        Self::new("dev".to_string(), QueueProvider::AzureServiceBus)
    }
}

// Development queue names
// dev-task-tactician
// dev-merge-warden
// dev-spec-sentinel
```

### Staging Environment

```rust
impl QueueNaming {
    pub fn staging() -> Self {
        Self::new("staging".to_string(), QueueProvider::AzureServiceBus)
    }

    pub fn staging_aws() -> Self {
        Self::new("staging".to_string(), QueueProvider::AwsSqs)
    }
}

// Staging queue names
// staging-task-tactician
// staging-merge-warden
// staging-spec-sentinel
```

### Production Environment

```rust
impl QueueNaming {
    pub fn production() -> Self {
        Self::new("prod".to_string(), QueueProvider::AzureServiceBus)
    }

    pub fn production_with_prefix(prefix: String) -> Self {
        let mut naming = Self::production();
        naming.prefix = Some(prefix);
        naming
    }
}

// Production queue names
// prod-task-tactician
// prod-merge-warden
// prod-spec-sentinel

// With prefix
// offaxis-prod-task-tactician
// offaxis-prod-merge-warden
// offaxis-prod-spec-sentinel
```

## Standard Bot Names

### Predefined Bot Identifiers

```rust
pub const TASK_TACTICIAN: &str = "task-tactician";
pub const MERGE_WARDEN: &str = "merge-warden";
pub const SPEC_SENTINEL: &str = "spec-sentinel";
pub const SECURITY_SCANNER: &str = "security-scanner";
pub const DEPENDENCY_UPDATER: &str = "dependency-updater";
pub const BUILD_ORCHESTRATOR: &str = "build-orchestrator";
pub const RELEASE_MANAGER: &str = "release-manager";
pub const DOCS_GENERATOR: &str = "docs-generator";

/// All standard bot names
pub const STANDARD_BOTS: &[&str] = &[
    TASK_TACTICIAN,
    MERGE_WARDEN,
    SPEC_SENTINEL,
    SECURITY_SCANNER,
    DEPENDENCY_UPDATER,
    BUILD_ORCHESTRATOR,
    RELEASE_MANAGER,
    DOCS_GENERATOR,
];
```

### Bot Name Validation

```rust
impl QueueNaming {
    pub fn validate_bot_name(bot_name: &str) -> Result<(), NamingError> {
        if bot_name.is_empty() {
            return Err(NamingError::Empty);
        }

        if bot_name.len() > 30 {
            return Err(NamingError::TooLong {
                name: bot_name.to_string(),
                length: bot_name.len(),
                max_length: 30,
            });
        }

        // Must be kebab-case
        if !bot_name.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            return Err(NamingError::InvalidFormat {
                name: bot_name.to_string(),
                reason: "Bot name must be lowercase kebab-case".to_string(),
            });
        }

        // Cannot start or end with hyphen
        if bot_name.starts_with('-') || bot_name.ends_with('-') {
            return Err(NamingError::InvalidFormat {
                name: bot_name.to_string(),
                reason: "Bot name cannot start or end with hyphen".to_string(),
            });
        }

        // Cannot have consecutive hyphens
        if bot_name.contains("--") {
            return Err(NamingError::InvalidFormat {
                name: bot_name.to_string(),
                reason: "Bot name cannot contain consecutive hyphens".to_string(),
            });
        }

        Ok(())
    }
}
```

## Error Types

```rust
#[derive(Debug, thiserror::Error)]
pub enum NamingError {
    #[error("Queue name is empty")]
    Empty,

    #[error("Queue name too long: '{name}' ({length} chars, max: {max_length})")]
    TooLong { name: String, length: usize, max_length: usize },

    #[error("Invalid character '{character}' in queue name: '{name}'")]
    InvalidCharacter { name: String, character: char },

    #[error("Invalid queue name format: '{name}' - {reason}")]
    InvalidFormat { name: String, reason: String },

    #[error("Bot not found: {bot_name}")]
    BotNotFound { bot_name: String },

    #[error("Provider '{provider}' does not support {feature}")]
    UnsupportedProvider { provider: String, feature: String },

    #[error("Duplicate queue name: {name}")]
    DuplicateName { name: String },
}
```

## Configuration Examples

### Complete Registry Setup

```rust
use queue_runtime::naming::*;
use std::time::Duration;

fn setup_production_registry() -> Result<BotQueueRegistry, NamingError> {
    let naming = QueueNaming::production_with_prefix("offaxis".to_string());
    let mut registry = BotQueueRegistry::new(naming);

    // Task Tactician - handles task automation
    registry.register_bot(TASK_TACTICIAN.to_string(), BotQueueConfig {
        enable_sessions: true,
        enable_dead_letter: true,
        enable_retry_queue: false,
        enable_fifo: false,
        max_delivery_count: 3,
        message_ttl: Duration::from_hours(24),
    })?;

    // Merge Warden - handles PR automation
    registry.register_bot(MERGE_WARDEN.to_string(), BotQueueConfig {
        enable_sessions: true,
        enable_dead_letter: true,
        enable_retry_queue: true,
        enable_fifo: false,
        max_delivery_count: 5,
        message_ttl: Duration::from_hours(48),
    })?;

    // Spec Sentinel - handles specification validation
    registry.register_bot(SPEC_SENTINEL.to_string(), BotQueueConfig::default())?;

    Ok(registry)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = setup_production_registry()?;

    // Get queue names for Task Tactician
    let task_queues = registry.get_bot_queues(TASK_TACTICIAN)?;
    println!("Task Tactician queues:");
    println!("  Main: {}", task_queues.main_queue);
    if let Some(dlq) = &task_queues.dead_letter_queue {
        println!("  DLQ: {}", dlq);
    }

    // List all queues
    let all_queues = registry.all_queues()?;
    println!("\nAll queues:");
    for queue in all_queues {
        println!("  {}", queue);
    }

    Ok(())
}
```

### Environment-Specific Examples

```yaml
# Development configuration
development:
  provider: InMemory
  environment: dev
  bots:
    - name: task-tactician
      sessions: true
      dead_letter: false
      retry: false
    - name: merge-warden
      sessions: true
      dead_letter: false
      retry: false

# Staging configuration
staging:
  provider: AzureServiceBus
  environment: staging
  prefix: offaxis
  bots:
    - name: task-tactician
      sessions: true
      dead_letter: true
      retry: false
    - name: merge-warden
      sessions: true
      dead_letter: true
      retry: true

# Production configuration
production:
  provider: AzureServiceBus
  environment: prod
  prefix: offaxis
  bots:
    - name: task-tactician
      sessions: true
      dead_letter: true
      retry: true
      max_delivery_count: 3
    - name: merge-warden
      sessions: true
      dead_letter: true
      retry: true
      max_delivery_count: 5
    - name: spec-sentinel
      sessions: true
      dead_letter: true
      retry: false
      max_delivery_count: 2
```

## Best Practices

1. **Environment Isolation**: Always include environment in queue names
2. **Consistent Prefixes**: Use organization prefixes for multi-tenant scenarios
3. **Clear Bot Names**: Use descriptive, kebab-case bot names
4. **DLQ Naming**: Always append `-dlq` for dead letter queues
5. **Length Management**: Keep names under provider limits
6. **Character Safety**: Use only ASCII alphanumeric and hyphens
7. **Validation**: Always validate names before creating queues
8. **Documentation**: Maintain registry of all queue names and purposes
