# Dead Letter Queue Management

This document defines the dead letter queue (DLQ) functionality for handling failed messages in the Queue Runtime.

## Overview

Dead Letter Queues provide a mechanism to handle messages that cannot be processed successfully after multiple retry attempts, enabling error analysis, manual intervention, and message recovery.

## Dead Letter Queue Types

### 1. Provider-Native DLQ

Uses the queue provider's built-in dead letter functionality:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeDlqConfig {
    /// Maximum delivery attempts before dead lettering
    pub max_delivery_count: u32,

    /// Dead letter queue naming pattern
    pub dlq_name_pattern: String, // e.g., "{queue_name}-dlq"

    /// Whether to preserve original message properties
    pub preserve_message_properties: bool,

    /// Additional metadata to add to dead letter messages
    pub add_failure_metadata: bool,
}

impl Default for NativeDlqConfig {
    fn default() -> Self {
        Self {
            max_delivery_count: 5,
            dlq_name_pattern: "{queue_name}-dlq".to_string(),
            preserve_message_properties: true,
            add_failure_metadata: true,
        }
    }
}
```

### 2. Application-Managed DLQ

Manual dead letter handling with custom logic:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedDlqConfig {
    /// Storage backend for dead letter messages
    pub storage_backend: DlqStorageBackend,

    /// Retention period for dead letter messages
    pub retention_period: Duration,

    /// Enable automatic cleanup of expired messages
    pub auto_cleanup: bool,

    /// Maximum size per dead letter message
    pub max_message_size: usize,

    /// Compression for large messages
    pub enable_compression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DlqStorageBackend {
    Queue { dlq_name: String },
    Database { connection_string: String, table_name: String },
    FileSystem { directory_path: String },
    S3 { bucket_name: String, prefix: String },
}
```

## Dead Letter Message Format

### Enhanced Message Envelope

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage<T> {
    /// Original message payload
    pub original_message: T,

    /// Original message metadata
    pub original_metadata: MessageMetadata,

    /// Failure information
    pub failure_info: FailureInfo,

    /// Dead letter metadata
    pub dlq_metadata: DlqMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageMetadata {
    pub message_id: String,
    pub queue_name: String,
    pub session_id: Option<String>,
    pub enqueued_at: DateTime<Utc>,
    pub first_received_at: DateTime<Utc>,
    pub delivery_count: u32,
    pub original_attributes: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureInfo {
    /// Error that caused dead lettering
    pub error_type: String,
    pub error_message: String,
    pub error_details: Option<String>,

    /// Stack trace if available
    pub stack_trace: Option<String>,

    /// Retry history
    pub retry_attempts: Vec<RetryAttempt>,

    /// Final failure timestamp
    pub failed_at: DateTime<Utc>,

    /// Processing context
    pub processing_context: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryAttempt {
    pub attempt_number: u32,
    pub attempted_at: DateTime<Utc>,
    pub error_type: String,
    pub error_message: String,
    pub processing_duration: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqMetadata {
    /// When message was dead lettered
    pub dead_lettered_at: DateTime<Utc>,

    /// Bot that was processing the message
    pub processing_bot: Option<String>,

    /// Environment where failure occurred
    pub environment: Option<String>,

    /// Version of processing code
    pub code_version: Option<String>,

    /// Additional tags for categorization
    pub tags: HashMap<String, String>,

    /// Expiration time for DLQ message
    pub expires_at: Option<DateTime<Utc>>,
}
```

## Dead Letter Queue Manager

### Core Implementation

```rust
use async_trait::async_trait;

#[async_trait]
pub trait DeadLetterQueueManager<T>: Send + Sync {
    /// Send a message to the dead letter queue
    async fn dead_letter_message(
        &self,
        original_message: &ReceivedMessage<T, impl MessageReceipt>,
        failure_info: FailureInfo,
    ) -> Result<(), DlqError>;

    /// Retrieve messages from dead letter queue
    async fn retrieve_dead_letters(
        &self,
        queue_name: &str,
        max_messages: u32,
    ) -> Result<Vec<DeadLetterMessage<T>>, DlqError>;

    /// Requeue a dead letter message back to original queue
    async fn requeue_message(
        &self,
        dlq_message: &DeadLetterMessage<T>,
        reset_delivery_count: bool,
    ) -> Result<MessageId, DlqError>;

    /// Delete a dead letter message permanently
    async fn delete_dead_letter(
        &self,
        message_id: &str,
    ) -> Result<(), DlqError>;

    /// Get statistics for dead letter queue
    async fn get_dlq_stats(
        &self,
        queue_name: &str,
    ) -> Result<DlqStats, DlqError>;

    /// Cleanup expired dead letter messages
    async fn cleanup_expired_messages(
        &self,
        queue_name: &str,
    ) -> Result<u32, DlqError>;
}

pub struct StandardDlqManager<T> {
    queue_client: Arc<dyn QueueClient<DeadLetterMessage<T>>>,
    config: DlqConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> StandardDlqManager<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(queue_client: Arc<dyn QueueClient<DeadLetterMessage<T>>>, config: DlqConfig) -> Self {
        Self {
            queue_client,
            config,
            _phantom: std::marker::PhantomData,
        }
    }

    fn generate_dlq_name(&self, original_queue_name: &str) -> String {
        self.config.dlq_name_pattern
            .replace("{queue_name}", original_queue_name)
            .replace("{environment}", &self.config.environment.unwrap_or_default())
    }

    fn create_failure_info(&self, error: &ProcessingError, retry_attempts: Vec<RetryAttempt>) -> FailureInfo {
        FailureInfo {
            error_type: format!("{:?}", error).split('(').next().unwrap_or("Unknown").to_string(),
            error_message: error.to_string(),
            error_details: None,
            stack_trace: None,
            retry_attempts,
            failed_at: Utc::now(),
            processing_context: HashMap::new(),
        }
    }

    fn create_dlq_metadata(&self, processing_bot: Option<String>) -> DlqMetadata {
        let expires_at = if let Some(retention) = self.config.retention_period {
            Some(Utc::now() + chrono::Duration::from_std(retention).unwrap())
        } else {
            None
        };

        DlqMetadata {
            dead_lettered_at: Utc::now(),
            processing_bot,
            environment: self.config.environment.clone(),
            code_version: self.config.code_version.clone(),
            tags: HashMap::new(),
            expires_at,
        }
    }
}

#[async_trait]
impl<T> DeadLetterQueueManager<T> for StandardDlqManager<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn dead_letter_message(
        &self,
        original_message: &ReceivedMessage<T, impl MessageReceipt>,
        failure_info: FailureInfo,
    ) -> Result<(), DlqError> {
        let dlq_name = self.generate_dlq_name(&original_message.queue_name);

        let message_metadata = MessageMetadata {
            message_id: original_message.message_id.to_string(),
            queue_name: original_message.queue_name.clone(),
            session_id: original_message.session_id.clone(),
            enqueued_at: original_message.enqueued_at,
            first_received_at: original_message.enqueued_at, // Simplified
            delivery_count: original_message.delivery_count,
            original_attributes: HashMap::new(),
        };

        let dlq_metadata = self.create_dlq_metadata(None);

        let dead_letter_message = DeadLetterMessage {
            original_message: original_message.payload.clone(),
            original_metadata: message_metadata,
            failure_info,
            dlq_metadata,
        };

        // Use same session ID for ordering if applicable
        let session_id = original_message.session_id.as_deref();

        self.queue_client
            .send(&dlq_name, &dead_letter_message, session_id)
            .await
            .map_err(DlqError::from)?;

        Ok(())
    }

    async fn retrieve_dead_letters(
        &self,
        queue_name: &str,
        max_messages: u32,
    ) -> Result<Vec<DeadLetterMessage<T>>, DlqError> {
        let dlq_name = self.generate_dlq_name(queue_name);

        let received_messages = self.queue_client
            .receive(&dlq_name, max_messages)
            .await
            .map_err(DlqError::from)?;

        Ok(received_messages.into_iter().map(|msg| msg.payload).collect())
    }

    async fn requeue_message(
        &self,
        dlq_message: &DeadLetterMessage<T>,
        reset_delivery_count: bool,
    ) -> Result<MessageId, DlqError> {
        let original_queue = &dlq_message.original_metadata.queue_name;
        let session_id = dlq_message.original_metadata.session_id.as_deref();

        // Create a new message with reset metadata if requested
        let message = if reset_delivery_count {
            // Reset the message as if it's new
            &dlq_message.original_message
        } else {
            // Keep original message as-is
            &dlq_message.original_message
        };

        let message_id = self.queue_client
            .send(original_queue, message, session_id)
            .await
            .map_err(DlqError::from)?;

        Ok(message_id)
    }

    async fn delete_dead_letter(
        &self,
        message_id: &str,
    ) -> Result<(), DlqError> {
        // This would require additional tracking of receipts
        // For now, return an error indicating manual cleanup needed
        Err(DlqError::UnsupportedOperation("Direct deletion not supported, use cleanup_expired_messages".to_string()))
    }

    async fn get_dlq_stats(
        &self,
        queue_name: &str,
    ) -> Result<DlqStats, DlqError> {
        let dlq_name = self.generate_dlq_name(queue_name);

        // This would depend on the underlying queue client supporting stats
        // For now, return basic stats
        Ok(DlqStats {
            total_messages: 0,
            oldest_message_age: None,
            newest_message_age: None,
            error_type_distribution: HashMap::new(),
            bot_failure_distribution: HashMap::new(),
        })
    }

    async fn cleanup_expired_messages(
        &self,
        queue_name: &str,
    ) -> Result<u32, DlqError> {
        let dlq_name = self.generate_dlq_name(queue_name);
        let mut cleaned_count = 0;

        // Retrieve messages and check expiration
        loop {
            let messages = self.queue_client
                .receive(&dlq_name, 10)
                .await
                .map_err(DlqError::from)?;

            if messages.is_empty() {
                break;
            }

            for message in messages {
                if let Some(expires_at) = message.payload.dlq_metadata.expires_at {
                    if Utc::now() > expires_at {
                        // Message has expired, acknowledge to delete it
                        self.queue_client
                            .acknowledge(&message.receipt)
                            .await
                            .map_err(DlqError::from)?;

                        cleaned_count += 1;
                    } else {
                        // Message not expired, reject to make it available again
                        self.queue_client
                            .reject(&message.receipt)
                            .await
                            .map_err(DlqError::from)?;
                    }
                } else {
                    // No expiration, reject to make available
                    self.queue_client
                        .reject(&message.receipt)
                        .await
                        .map_err(DlqError::from)?;
                }
            }
        }

        Ok(cleaned_count)
    }
}
```

## Configuration

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqConfig {
    /// Dead letter queue naming pattern
    pub dlq_name_pattern: String,

    /// Retention period for dead letter messages
    pub retention_period: Option<Duration>,

    /// Environment identifier
    pub environment: Option<String>,

    /// Code version for tracking
    pub code_version: Option<String>,

    /// Enable automatic cleanup
    pub auto_cleanup: bool,

    /// Cleanup interval
    pub cleanup_interval: Duration,

    /// Maximum retry attempts before dead lettering
    pub max_retry_attempts: u32,

    /// Additional metadata to include
    pub include_stack_traces: bool,
    pub include_processing_context: bool,
}

impl Default for DlqConfig {
    fn default() -> Self {
        Self {
            dlq_name_pattern: "{queue_name}-dlq".to_string(),
            retention_period: Some(Duration::from_days(30)),
            environment: None,
            code_version: None,
            auto_cleanup: true,
            cleanup_interval: Duration::from_hours(6),
            max_retry_attempts: 5,
            include_stack_traces: false, // Privacy/security consideration
            include_processing_context: true,
        }
    }
}
```

## Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum DlqError {
    #[error("Queue operation failed: {0}")]
    QueueError(#[from] QueueError),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Message not found: {0}")]
    MessageNotFound(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Storage backend error: {0}")]
    StorageError(String),
}
```

## Statistics and Monitoring

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqStats {
    pub total_messages: u64,
    pub oldest_message_age: Option<Duration>,
    pub newest_message_age: Option<Duration>,
    pub error_type_distribution: HashMap<String, u64>,
    pub bot_failure_distribution: HashMap<String, u64>,
}

pub struct DlqAnalyzer<T> {
    dlq_manager: Arc<dyn DeadLetterQueueManager<T>>,
}

impl<T> DlqAnalyzer<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(dlq_manager: Arc<dyn DeadLetterQueueManager<T>>) -> Self {
        Self { dlq_manager }
    }

    pub async fn analyze_failures(&self, queue_name: &str, max_messages: u32) -> Result<FailureAnalysis, DlqError> {
        let dead_letters = self.dlq_manager
            .retrieve_dead_letters(queue_name, max_messages)
            .await?;

        let mut error_types = HashMap::new();
        let mut bot_failures = HashMap::new();
        let mut hourly_distribution = HashMap::new();
        let mut retry_patterns = Vec::new();

        for dlq_message in &dead_letters {
            // Count error types
            let error_type = &dlq_message.failure_info.error_type;
            *error_types.entry(error_type.clone()).or_insert(0) += 1;

            // Count bot failures
            if let Some(bot) = &dlq_message.dlq_metadata.processing_bot {
                *bot_failures.entry(bot.clone()).or_insert(0) += 1;
            }

            // Hourly distribution
            let hour = dlq_message.failure_info.failed_at.hour();
            *hourly_distribution.entry(hour).or_insert(0) += 1;

            // Retry patterns
            let retry_count = dlq_message.failure_info.retry_attempts.len();
            retry_patterns.push(retry_count);
        }

        Ok(FailureAnalysis {
            total_failures: dead_letters.len() as u64,
            error_type_distribution: error_types,
            bot_failure_distribution: bot_failures,
            hourly_failure_distribution: hourly_distribution,
            average_retry_attempts: retry_patterns.iter().sum::<usize>() as f64 / retry_patterns.len() as f64,
            common_failure_patterns: self.identify_patterns(&dead_letters),
        })
    }

    fn identify_patterns(&self, dead_letters: &[DeadLetterMessage<T>]) -> Vec<FailurePattern> {
        let mut patterns = Vec::new();

        // Group by error type and analyze
        let mut error_groups: HashMap<String, Vec<&DeadLetterMessage<T>>> = HashMap::new();
        for dlq_message in dead_letters {
            error_groups
                .entry(dlq_message.failure_info.error_type.clone())
                .or_default()
                .push(dlq_message);
        }

        for (error_type, messages) in error_groups {
            if messages.len() >= 3 { // Pattern threshold
                let pattern = FailurePattern {
                    error_type: error_type.clone(),
                    frequency: messages.len() as u64,
                    common_contexts: self.extract_common_contexts(messages),
                    time_range: self.calculate_time_range(messages),
                    affected_bots: self.extract_affected_bots(messages),
                };
                patterns.push(pattern);
            }
        }

        patterns.sort_by(|a, b| b.frequency.cmp(&a.frequency));
        patterns
    }

    fn extract_common_contexts(&self, messages: &[&DeadLetterMessage<T>]) -> HashMap<String, String> {
        let mut context_counts: HashMap<String, HashMap<String, u32>> = HashMap::new();

        for message in messages {
            for (key, value) in &message.failure_info.processing_context {
                context_counts
                    .entry(key.clone())
                    .or_default()
                    .entry(value.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
            }
        }

        // Find most common values for each context key
        let mut common_contexts = HashMap::new();
        for (key, value_counts) in context_counts {
            if let Some((most_common_value, _)) = value_counts.iter().max_by_key(|(_, count)| *count) {
                common_contexts.insert(key, most_common_value.clone());
            }
        }

        common_contexts
    }

    fn calculate_time_range(&self, messages: &[&DeadLetterMessage<T>]) -> (DateTime<Utc>, DateTime<Utc>) {
        let times: Vec<DateTime<Utc>> = messages
            .iter()
            .map(|m| m.failure_info.failed_at)
            .collect();

        let earliest = times.iter().min().copied().unwrap_or_else(Utc::now);
        let latest = times.iter().max().copied().unwrap_or_else(Utc::now);

        (earliest, latest)
    }

    fn extract_affected_bots(&self, messages: &[&DeadLetterMessage<T>]) -> Vec<String> {
        messages
            .iter()
            .filter_map(|m| m.dlq_metadata.processing_bot.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .cloned()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureAnalysis {
    pub total_failures: u64,
    pub error_type_distribution: HashMap<String, u64>,
    pub bot_failure_distribution: HashMap<String, u64>,
    pub hourly_failure_distribution: HashMap<u32, u64>,
    pub average_retry_attempts: f64,
    pub common_failure_patterns: Vec<FailurePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailurePattern {
    pub error_type: String,
    pub frequency: u64,
    pub common_contexts: HashMap<String, String>,
    pub time_range: (DateTime<Utc>, DateTime<Utc>),
    pub affected_bots: Vec<String>,
}
```

## Recovery Operations

```rust
pub struct DlqRecoveryManager<T> {
    dlq_manager: Arc<dyn DeadLetterQueueManager<T>>,
    queue_client: Arc<dyn QueueClient<T>>,
}

impl<T> DlqRecoveryManager<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(
        dlq_manager: Arc<dyn DeadLetterQueueManager<T>>,
        queue_client: Arc<dyn QueueClient<T>>,
    ) -> Self {
        Self {
            dlq_manager,
            queue_client,
        }
    }

    pub async fn bulk_requeue(&self, queue_name: &str, max_messages: u32, reset_delivery_count: bool) -> Result<RecoveryResult, DlqError> {
        let dead_letters = self.dlq_manager
            .retrieve_dead_letters(queue_name, max_messages)
            .await?;

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut failures = Vec::new();

        for dlq_message in dead_letters {
            match self.dlq_manager.requeue_message(&dlq_message, reset_delivery_count).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    failure_count += 1;
                    failures.push(RecoveryFailure {
                        message_id: dlq_message.original_metadata.message_id.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        Ok(RecoveryResult {
            success_count,
            failure_count,
            failures,
        })
    }

    pub async fn selective_requeue(
        &self,
        queue_name: &str,
        filter: Box<dyn Fn(&DeadLetterMessage<T>) -> bool + Send + Sync>,
        reset_delivery_count: bool,
    ) -> Result<RecoveryResult, DlqError> {
        let dead_letters = self.dlq_manager
            .retrieve_dead_letters(queue_name, 100) // Get more for filtering
            .await?;

        let filtered_messages: Vec<_> = dead_letters
            .into_iter()
            .filter(|msg| filter(msg))
            .collect();

        let mut success_count = 0;
        let mut failure_count = 0;
        let mut failures = Vec::new();

        for dlq_message in filtered_messages {
            match self.dlq_manager.requeue_message(&dlq_message, reset_delivery_count).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    failure_count += 1;
                    failures.push(RecoveryFailure {
                        message_id: dlq_message.original_metadata.message_id.clone(),
                        error: e.to_string(),
                    });
                }
            }
        }

        Ok(RecoveryResult {
            success_count,
            failure_count,
            failures,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResult {
    pub success_count: u32,
    pub failure_count: u32,
    pub failures: Vec<RecoveryFailure>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFailure {
    pub message_id: String,
    pub error: String,
}
```

## Testing Support

```rust
#[cfg(test)]
pub mod testing {
    use super::*;
    use mockall::mock;

    mock! {
        pub DeadLetterQueueManager<T: Clone + Send + Sync + 'static> {}

        #[async_trait]
        impl<T: Clone + Send + Sync + 'static> DeadLetterQueueManager<T> for DeadLetterQueueManager<T> {
            async fn dead_letter_message(
                &self,
                original_message: &ReceivedMessage<T, impl MessageReceipt>,
                failure_info: FailureInfo,
            ) -> Result<(), DlqError>;

            async fn retrieve_dead_letters(
                &self,
                queue_name: &str,
                max_messages: u32,
            ) -> Result<Vec<DeadLetterMessage<T>>, DlqError>;

            async fn requeue_message(
                &self,
                dlq_message: &DeadLetterMessage<T>,
                reset_delivery_count: bool,
            ) -> Result<MessageId, DlqError>;

            async fn delete_dead_letter(
                &self,
                message_id: &str,
            ) -> Result<(), DlqError>;

            async fn get_dlq_stats(
                &self,
                queue_name: &str,
            ) -> Result<DlqStats, DlqError>;

            async fn cleanup_expired_messages(
                &self,
                queue_name: &str,
            ) -> Result<u32, DlqError>;
        }
    }

    pub fn create_test_failure_info() -> FailureInfo {
        FailureInfo {
            error_type: "TestError".to_string(),
            error_message: "Test error message".to_string(),
            error_details: None,
            stack_trace: None,
            retry_attempts: vec![
                RetryAttempt {
                    attempt_number: 1,
                    attempted_at: Utc::now() - chrono::Duration::minutes(5),
                    error_type: "TestError".to_string(),
                    error_message: "First attempt failed".to_string(),
                    processing_duration: Duration::from_millis(100),
                },
            ],
            failed_at: Utc::now(),
            processing_context: HashMap::new(),
        }
    }

    pub fn create_test_dead_letter_message<T: Clone>(payload: T) -> DeadLetterMessage<T> {
        DeadLetterMessage {
            original_message: payload,
            original_metadata: MessageMetadata {
                message_id: "test-message-123".to_string(),
                queue_name: "test-queue".to_string(),
                session_id: None,
                enqueued_at: Utc::now() - chrono::Duration::minutes(10),
                first_received_at: Utc::now() - chrono::Duration::minutes(10),
                delivery_count: 3,
                original_attributes: HashMap::new(),
            },
            failure_info: create_test_failure_info(),
            dlq_metadata: DlqMetadata {
                dead_lettered_at: Utc::now(),
                processing_bot: Some("test-bot".to_string()),
                environment: Some("test".to_string()),
                code_version: Some("1.0.0".to_string()),
                tags: HashMap::new(),
                expires_at: Some(Utc::now() + chrono::Duration::days(30)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlq_name_generation() {
        let config = DlqConfig {
            dlq_name_pattern: "{queue_name}-dlq".to_string(),
            ..Default::default()
        };

        let manager = StandardDlqManager::new(
            Arc::new(create_mock_queue_client()),
            config,
        );

        let dlq_name = manager.generate_dlq_name("test-queue");
        assert_eq!(dlq_name, "test-queue-dlq");
    }

    #[test]
    fn test_failure_info_creation() {
        let error = ProcessingError::ValidationError("Invalid input".to_string());
        let retry_attempts = vec![
            RetryAttempt {
                attempt_number: 1,
                attempted_at: Utc::now(),
                error_type: "ValidationError".to_string(),
                error_message: "Invalid input".to_string(),
                processing_duration: Duration::from_millis(50),
            },
        ];

        let config = DlqConfig::default();
        let manager = StandardDlqManager::new(
            Arc::new(create_mock_queue_client()),
            config,
        );

        let failure_info = manager.create_failure_info(&error, retry_attempts);
        assert_eq!(failure_info.error_type, "ValidationError");
        assert_eq!(failure_info.retry_attempts.len(), 1);
    }
}
```

## Best Practices

1. **Preserve Context**: Include comprehensive failure information for debugging
2. **Set Retention Limits**: Configure appropriate retention periods for DLQ messages
3. **Monitor DLQ Growth**: Alert on increasing dead letter volumes
4. **Analyze Patterns**: Regularly analyze failure patterns to identify systemic issues
5. **Implement Recovery**: Provide tools for selective message recovery
6. **Security Considerations**: Be careful with sensitive data in dead letter messages
7. **Cost Management**: Clean up expired messages to control storage costs
8. **Alerting**: Set up alerts for high dead letter rates or critical failures
