# Session Strategies

This document defines the session management strategies for ordered message processing across different bot types and GitHub event patterns.

## Overview

Session strategies determine how messages are grouped for ordered processing. Different bots have different ordering requirements based on their functionality and the GitHub events they handle.

## Session Strategy Types

### 1. No Ordering (None)

Messages are processed without any ordering guarantees. Suitable for stateless operations.

**Use Cases:**

- Notification bots
- Simple webhook forwarders
- Stateless analysis tools

**Implementation:**

```rust
pub struct NoOrderingStrategy;

impl SessionKeyGenerator for NoOrderingStrategy {
    fn generate_key(&self, _envelope: &EventEnvelope) -> Option<String> {
        None // No session key = no ordering
    }
}
```

### 2. Entity-Based Ordering

Messages are ordered by specific entities (PR, Issue, Branch). Each entity gets its own session.

**Use Cases:**

- Pull request automation
- Issue lifecycle management
- Branch protection enforcement

**Session Keys:**

- Pull Request: `pr-{repo_full_name}-{pr_number}`
- Issue: `issue-{repo_full_name}-{issue_number}`
- Branch: `branch-{repo_full_name}-{branch_name}`

**Implementation:**

```rust
pub struct EntitySessionStrategy;

impl SessionKeyGenerator for EntitySessionStrategy {
    fn generate_key(&self, envelope: &EventEnvelope) -> Option<String> {
        match (&envelope.entity_type, &envelope.entity_id) {
            (EntityType::PullRequest, Some(pr_number)) => {
                Some(format!("pr-{}-{}", envelope.repository.full_name, pr_number))
            }
            (EntityType::Issue, Some(issue_number)) => {
                Some(format!("issue-{}-{}", envelope.repository.full_name, issue_number))
            }
            (EntityType::Branch, Some(branch_name)) => {
                Some(format!("branch-{}-{}", envelope.repository.full_name, branch_name))
            }
            _ => None, // Fall back to no ordering for unsupported entities
        }
    }
}
```

### 3. Repository-Based Ordering

All messages for a repository are processed in order. Ensures repository-level consistency.

**Use Cases:**

- Repository-wide policy enforcement
- Dependency management
- Security scanning coordination

**Session Key:**

- Repository: `repo-{repo_full_name}`

**Implementation:**

```rust
pub struct RepositorySessionStrategy;

impl SessionKeyGenerator for RepositorySessionStrategy {
    fn generate_key(&self, envelope: &EventEnvelope) -> Option<String> {
        Some(format!("repo-{}", envelope.repository.full_name))
    }
}
```

### 4. User-Based Ordering

Messages are ordered by the user who triggered the event. Useful for user-specific workflows.

**Use Cases:**

- User activity tracking
- Personal automation workflows
- User-specific rate limiting

**Session Key:**

- User: `user-{repo_full_name}-{username}`

**Implementation:**

```rust
pub struct UserSessionStrategy;

impl SessionKeyGenerator for UserSessionStrategy {
    fn generate_key(&self, envelope: &EventEnvelope) -> Option<String> {
        envelope.payload
            .get("sender")
            .and_then(|sender| sender.get("login"))
            .and_then(|login| login.as_str())
            .map(|username| format!("user-{}-{}", envelope.repository.full_name, username))
    }
}
```

### 5. Hybrid Strategies

Combinations of multiple strategies for complex ordering requirements.

#### Entity-Repository Hybrid

Entities get priority ordering, with repository-level fallback:

```rust
pub struct EntityRepositoryHybridStrategy;

impl SessionKeyGenerator for EntityRepositoryHybridStrategy {
    fn generate_key(&self, envelope: &EventEnvelope) -> Option<String> {
        // Try entity-based first
        if let Some(entity_key) = EntitySessionStrategy.generate_key(envelope) {
            Some(entity_key)
        } else {
            // Fall back to repository-based
            RepositorySessionStrategy.generate_key(envelope)
        }
    }
}
```

#### Time-Based Partitioning

Partition sessions by time periods to prevent hot sessions:

```rust
pub struct TimePartitionedEntityStrategy {
    partition_duration: Duration,
}

impl SessionKeyGenerator for TimePartitionedEntityStrategy {
    fn generate_key(&self, envelope: &EventEnvelope) -> Option<String> {
        let entity_key = EntitySessionStrategy.generate_key(envelope)?;

        // Add time partition to spread load
        let partition = envelope.metadata.received_at.timestamp() / self.partition_duration.as_secs() as i64;

        Some(format!("{}-p{}", entity_key, partition))
    }
}
```

## Bot-Specific Strategy Configuration

### Task Tactician

Handles task automation and requires entity-level ordering:

```rust
pub fn task_tactician_strategy() -> Box<dyn SessionKeyGenerator> {
    Box::new(EntitySessionStrategy)
}

// Configuration
let config = BotSessionConfig {
    strategy: SessionStrategyType::Entity,
    max_session_duration: Duration::from_hours(2),
    max_messages_per_session: 1000,
    session_timeout: Duration::from_minutes(30),
};
```

**Ordering Requirements:**

- Pull request events must be processed in sequence
- Issue events must maintain temporal order
- Branch events should be ordered per branch

### Merge Warden

Manages PR merging and requires strict PR ordering:

```rust
pub fn merge_warden_strategy() -> Box<dyn SessionKeyGenerator> {
    Box::new(EntitySessionStrategy)
}

// Configuration
let config = BotSessionConfig {
    strategy: SessionStrategyType::Entity,
    max_session_duration: Duration::from_hours(1),
    max_messages_per_session: 500,
    session_timeout: Duration::from_minutes(15),
};
```

**Ordering Requirements:**

- PR state changes must be sequential
- Merge/close operations must not race
- Review events must be ordered

### Spec Sentinel

Validates specifications and can use repository-level ordering:

```rust
pub fn spec_sentinel_strategy() -> Box<dyn SessionKeyGenerator> {
    Box::new(RepositorySessionStrategy)
}

// Configuration
let config = BotSessionConfig {
    strategy: SessionStrategyType::Repository,
    max_session_duration: Duration::from_hours(4),
    max_messages_per_session: 2000,
    session_timeout: Duration::from_hours(1),
};
```

**Ordering Requirements:**

- Repository-wide consistency for spec validation
- File change events should be coordinated
- Less strict ordering requirements than PR bots

## Session Management Implementation

### SessionManager

Central coordinator for session key generation and management:

```rust
use std::collections::HashMap;

pub struct SessionManager {
    strategies: HashMap<String, Box<dyn SessionKeyGenerator>>,
    default_strategy: Box<dyn SessionKeyGenerator>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
            default_strategy: Box::new(NoOrderingStrategy),
        }
    }

    pub fn register_bot_strategy(&mut self, bot_name: String, strategy: Box<dyn SessionKeyGenerator>) {
        self.strategies.insert(bot_name, strategy);
    }

    pub fn generate_session_key(&self, bot_name: &str, envelope: &EventEnvelope) -> Option<String> {
        let strategy = self.strategies
            .get(bot_name)
            .unwrap_or(&self.default_strategy);

        strategy.generate_key(envelope)
    }

    pub fn supports_ordering(&self, bot_name: &str, envelope: &EventEnvelope) -> bool {
        self.generate_session_key(bot_name, envelope).is_some()
    }
}

// Factory function for standard bot strategies
pub fn create_standard_session_manager() -> SessionManager {
    let mut manager = SessionManager::new();

    // Register standard bot strategies
    manager.register_bot_strategy(
        "task-tactician".to_string(),
        Box::new(EntitySessionStrategy)
    );

    manager.register_bot_strategy(
        "merge-warden".to_string(),
        Box::new(EntitySessionStrategy)
    );

    manager.register_bot_strategy(
        "spec-sentinel".to_string(),
        Box::new(RepositorySessionStrategy)
    );

    manager.register_bot_strategy(
        "security-scanner".to_string(),
        Box::new(RepositorySessionStrategy)
    );

    manager.register_bot_strategy(
        "dependency-updater".to_string(),
        Box::new(EntityRepositoryHybridStrategy)
    );

    manager
}
```

### Session Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotSessionConfig {
    /// Strategy type for session key generation
    pub strategy: SessionStrategyType,

    /// Maximum duration a session can be active
    pub max_session_duration: Duration,

    /// Maximum number of messages per session
    pub max_messages_per_session: u32,

    /// Timeout for inactive sessions
    pub session_timeout: Duration,

    /// Whether to enable session affinity (same consumer for session)
    pub enable_session_affinity: bool,

    /// Custom strategy parameters
    pub strategy_params: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionStrategyType {
    None,
    Entity,
    Repository,
    User,
    EntityRepositoryHybrid,
    TimePartitionedEntity { partition_minutes: u32 },
    Custom { class_name: String },
}

impl Default for BotSessionConfig {
    fn default() -> Self {
        Self {
            strategy: SessionStrategyType::Entity,
            max_session_duration: Duration::from_hours(2),
            max_messages_per_session: 1000,
            session_timeout: Duration::from_minutes(30),
            enable_session_affinity: true,
            strategy_params: HashMap::new(),
        }
    }
}
```

## Provider-Specific Implementation

### Azure Service Bus Sessions

Azure Service Bus has native session support:

```rust
impl AzureServiceBusClient {
    async fn send_with_session(&self, queue_name: &str, message: &EventEnvelope, session_id: &str) -> Result<MessageId, AzureError> {
        let session_message = ServiceBusMessage::new(MessageSerializer::serialize(message)?)
            .with_session_id(session_id)
            .with_message_id(&message.event_id);

        self.sender.send_message(session_message).await
            .map_err(AzureError::from)
    }

    async fn receive_from_session(&self, queue_name: &str, session_id: &str) -> Result<Vec<ReceivedMessage<EventEnvelope, AzureReceipt>>, AzureError> {
        let session_receiver = self.client
            .accept_session(queue_name, session_id)
            .await?;

        let messages = session_receiver
            .receive_messages(10)
            .await?;

        // Convert to our message format
        messages.into_iter()
            .map(|msg| self.convert_received_message(msg))
            .collect()
    }
}
```

### AWS SQS FIFO Queues

AWS SQS uses MessageGroupId for ordering:

```rust
impl AwsSqsClient {
    async fn send_with_session(&self, queue_name: &str, message: &EventEnvelope, session_id: &str) -> Result<MessageId, AwsError> {
        let send_request = SendMessageRequest {
            queue_url: self.get_queue_url(queue_name)?,
            message_body: String::from_utf8(MessageSerializer::serialize(message)?)?,
            message_group_id: Some(session_id.to_string()),
            message_deduplication_id: Some(message.event_id.clone()),
            ..Default::default()
        };

        let response = self.sqs_client
            .send_message(send_request)
            .await?;

        Ok(MessageId::new(response.message_id.unwrap_or_default()))
    }

    async fn receive_fifo_messages(&self, queue_name: &str) -> Result<Vec<ReceivedMessage<EventEnvelope, AwsReceipt>>, AwsError> {
        let receive_request = ReceiveMessageRequest {
            queue_url: self.get_queue_url(queue_name)?,
            max_number_of_messages: Some(10),
            wait_time_seconds: Some(20),
            attribute_names: Some(vec!["MessageGroupId".to_string()]),
            ..Default::default()
        };

        let response = self.sqs_client
            .receive_message(receive_request)
            .await?;

        // Group messages by MessageGroupId for ordered processing
        response.messages
            .unwrap_or_default()
            .into_iter()
            .map(|msg| self.convert_received_message(msg))
            .collect()
    }
}
```

## Session Key Examples

### Pull Request Events

```rust
// PR opened
let envelope = EventEnvelope {
    event_type: "pull_request".to_string(),
    repository: Repository::new("octocat", "Hello-World"),
    entity_type: EntityType::PullRequest,
    entity_id: Some("123".to_string()),
    // ...
};

let session_key = EntitySessionStrategy.generate_key(&envelope);
// Result: "pr-octocat/Hello-World-123"
```

### Issue Events

```rust
// Issue commented
let envelope = EventEnvelope {
    event_type: "issue_comment".to_string(),
    repository: Repository::new("octocat", "Hello-World"),
    entity_type: EntityType::Issue,
    entity_id: Some("456".to_string()),
    // ...
};

let session_key = EntitySessionStrategy.generate_key(&envelope);
// Result: "issue-octocat/Hello-World-456"
```

### Repository Events

```rust
// Repository push
let envelope = EventEnvelope {
    event_type: "push".to_string(),
    repository: Repository::new("octocat", "Hello-World"),
    entity_type: EntityType::Branch,
    entity_id: Some("main".to_string()),
    // ...
};

let session_key = RepositorySessionStrategy.generate_key(&envelope);
// Result: "repo-octocat/Hello-World"
```

## Performance Considerations

### Session Distribution

Monitor session key distribution to avoid hot sessions:

```rust
pub struct SessionMetrics {
    session_counts: HashMap<String, u64>,
    session_durations: HashMap<String, Duration>,
    last_activity: HashMap<String, DateTime<Utc>>,
}

impl SessionMetrics {
    pub fn record_message(&mut self, session_id: &str) {
        *self.session_counts.entry(session_id.to_string()).or_insert(0) += 1;
        self.last_activity.insert(session_id.to_string(), Utc::now());
    }

    pub fn get_hot_sessions(&self, threshold: u64) -> Vec<String> {
        self.session_counts
            .iter()
            .filter(|(_, &count)| count > threshold)
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }

    pub fn get_session_distribution(&self) -> HashMap<String, u64> {
        self.session_counts.clone()
    }
}
```

### Session Lifecycle Management

```rust
pub struct SessionLifecycleManager {
    active_sessions: HashMap<String, SessionInfo>,
    config: BotSessionConfig,
}

impl SessionLifecycleManager {
    pub fn should_close_session(&self, session_id: &str) -> bool {
        if let Some(session_info) = self.active_sessions.get(session_id) {
            // Check duration limit
            if session_info.duration() > self.config.max_session_duration {
                return true;
            }

            // Check message count limit
            if session_info.message_count > self.config.max_messages_per_session {
                return true;
            }

            // Check timeout
            if session_info.idle_time() > self.config.session_timeout {
                return true;
            }
        }

        false
    }

    pub async fn cleanup_expired_sessions(&mut self) -> Result<Vec<String>, SessionError> {
        let expired_sessions: Vec<String> = self.active_sessions
            .iter()
            .filter(|(session_id, _)| self.should_close_session(session_id))
            .map(|(session_id, _)| session_id.clone())
            .collect();

        for session_id in &expired_sessions {
            self.active_sessions.remove(session_id);
        }

        Ok(expired_sessions)
    }
}
```

## Best Practices

1. **Choose Appropriate Strategy**: Match strategy to bot's ordering requirements
2. **Monitor Session Distribution**: Avoid hot sessions that create bottlenecks
3. **Set Reasonable Timeouts**: Balance ordering with throughput
4. **Handle Session Failures**: Implement session recovery and error handling
5. **Test Ordering Behavior**: Verify correct message sequencing in tests
6. **Document Strategy Choice**: Clearly document why each bot uses its strategy
7. **Plan for Growth**: Consider session partitioning for high-volume scenarios
8. **Monitor Performance**: Track session metrics and processing delays
