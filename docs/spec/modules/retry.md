# Retry Strategies

This document defines the design requirements for retry policies and backoff strategies for handling message processing failures in the queue-runtime.

## Overview

The retry system provides configurable strategies for handling transient failures, permanent errors, and dead letter queue management across different queue providers. The implementation must support multiple backoff algorithms and error classification patterns.

## Retry Policy Requirements

### Exponential Backoff Policy

**Configuration Requirements**:

- Initial delay configuration (default 100ms)
- Maximum delay ceiling (default 5 minutes)
- Multiplier for exponential growth (default 2.0)
- Maximum retry attempt limits (default 5)
- Jitter enablement to prevent thundering herd scenarios

**Behavioral Requirements**:

- Exponential delay calculation with configurable multiplier
- Maximum delay enforcement to prevent excessive waits
- Random jitter application (±20%) when enabled
- Retry attempt validation against error classification
- Thread-safe delay duration calculation

### Linear Backoff Policy

**Configuration Requirements**:

- Initial delay specification for first retry
- Linear increment value for each subsequent attempt
- Maximum delay ceiling to prevent unbounded growth
- Maximum attempt limits for failure scenarios

**Behavioral Requirements**:

- Linear delay progression with fixed increments
- Delay ceiling enforcement for controlled backoff
- Error type validation for retry eligibility
- Consistent delay calculation across attempts

### Fixed Interval Policy

**Configuration Requirements**:

- Fixed delay duration between retry attempts
- Maximum retry attempt limits
- Consistent timing regardless of failure patterns

**Behavioral Requirements**:

- Constant delay between all retry attempts
- Error classification validation for retry eligibility
- Simple implementation for predictable retry patterns

### Circuit Breaker Policy

**State Management Requirements**:

- Three-state circuit breaker (Closed, Open, Half-Open)
- Failure threshold configuration for circuit opening
- Recovery timeout before testing service availability
- Success threshold for circuit closing from half-open state

**Circuit Breaker Behavioral Requirements**:

- Closed state: Allow requests, count failures, open on threshold
- Open state: Reject requests, transition to half-open after timeout
- Half-open state: Test with limited requests, close on success threshold
- Thread-safe state management with proper synchronization
- Failure and success count tracking with automatic reset

## Error Classification

### Retryable vs Non-Retryable Errors

```rust
#[derive(Debug, Clone)]
pub enum ProcessingError {
    // Retryable errors
    TemporaryServiceUnavailable(String),
    NetworkTimeout(String),
    RateLimitExceeded { retry_after: Option<Duration> },
    ProviderThrottling(String),
    TransientDatabaseError(String),

    // Non-retryable errors
    InvalidMessage(String),
    AuthenticationFailure(String),
    AuthorizationFailure(String),
    ValidationError(String),
    PermanentServiceError(String),

    // Provider-specific errors
    AzureError(AzureErrorKind),
    AwsError(AwsErrorKind),
}

impl ProcessingError {
    pub fn is_retryable(&self) -> bool {
        match self {
            // Retryable
            Self::TemporaryServiceUnavailable(_) => true,
            Self::NetworkTimeout(_) => true,
            Self::RateLimitExceeded { .. } => true,
            Self::ProviderThrottling(_) => true,
            Self::TransientDatabaseError(_) => true,

            // Non-retryable
            Self::InvalidMessage(_) => false,
            Self::AuthenticationFailure(_) => false,
            Self::AuthorizationFailure(_) => false,
            Self::ValidationError(_) => false,
            Self::PermanentServiceError(_) => false,

            // Provider-specific
            Self::AzureError(err) => err.is_retryable(),
            Self::AwsError(err) => err.is_retryable(),
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RateLimitExceeded { retry_after } => *retry_after,
            Self::ProviderThrottling(_) => Some(Duration::from_secs(60)),
            _ => None,
        }
    }
}
```

### Provider-Specific Error Handling

```rust
#[derive(Debug, Clone)]
pub enum AzureErrorKind {
    ServiceBusUnavailable,
    MessageLockLost,
    SessionLockLost,
    QuotaExceeded,
    InvalidOperation,
    UnauthorizedAccess,
}

impl AzureErrorKind {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::ServiceBusUnavailable => true,
            Self::MessageLockLost => true,
            Self::SessionLockLost => true,
            Self::QuotaExceeded => true,
            Self::InvalidOperation => false,
            Self::UnauthorizedAccess => false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AwsErrorKind {
    SqsUnavailable,
    VisibilityTimeoutExpired,
    MessageNotInflight,
    ThrottlingException,
    InvalidParameterValue,
    AccessDenied,
}

impl AwsErrorKind {
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::SqsUnavailable => true,
            Self::VisibilityTimeoutExpired => true,
            Self::MessageNotInflight => true,
            Self::ThrottlingException => true,
            Self::InvalidParameterValue => false,
            Self::AccessDenied => false,
        }
    }
}
```

## Retry Configuration

### Bot-Specific Retry Settings

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub policy_type: RetryPolicyType,
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: Option<f64>,
    pub jitter_enabled: bool,
    pub dead_letter_enabled: bool,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryPolicyType {
    ExponentialBackoff,
    LinearBackoff,
    FixedInterval,
    CircuitBreaker,
    NoRetry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub recovery_timeout: Duration,
    pub success_threshold: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            policy_type: RetryPolicyType::ExponentialBackoff,
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(60),
            multiplier: Some(2.0),
            jitter_enabled: true,
            dead_letter_enabled: true,
            circuit_breaker: None,
        }
    }
}

// Bot-specific configurations
pub fn task_tactician_retry_config() -> RetryConfig {
    RetryConfig {
        policy_type: RetryPolicyType::ExponentialBackoff,
        max_attempts: 5,
        initial_delay: Duration::from_millis(200),
        max_delay: Duration::from_secs(300),
        multiplier: Some(2.0),
        jitter_enabled: true,
        dead_letter_enabled: true,
        circuit_breaker: None,
    }
}

pub fn merge_warden_retry_config() -> RetryConfig {
    RetryConfig {
        policy_type: RetryPolicyType::ExponentialBackoff,
        max_attempts: 3,
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(120),
        multiplier: Some(1.5),
        jitter_enabled: true,
        dead_letter_enabled: true,
        circuit_breaker: Some(CircuitBreakerConfig {
            failure_threshold: 10,
            recovery_timeout: Duration::from_secs(300),
            success_threshold: 3,
        }),
    }
}

pub fn spec_sentinel_retry_config() -> RetryConfig {
    RetryConfig {
        policy_type: RetryPolicyType::LinearBackoff,
        max_attempts: 4,
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(600),
        multiplier: None,
        jitter_enabled: false,
        dead_letter_enabled: true,
        circuit_breaker: None,
    }
}
```

## Retry Executor

### Core Retry Logic

```rust
use async_trait::async_trait;
use tokio::time::{sleep, timeout};

pub struct RetryExecutor {
    policy: Box<dyn RetryPolicy>,
    timeout_duration: Option<Duration>,
}

impl RetryExecutor {
    pub fn new(policy: Box<dyn RetryPolicy>) -> Self {
        Self {
            policy,
            timeout_duration: Some(Duration::from_secs(300)), // 5 minutes default
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_duration = Some(timeout);
        self
    }

    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, RetryError<E>>
    where
        F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>> + Send + Sync,
        E: Into<ProcessingError> + Clone + Send + Sync,
        T: Send,
    {
        let mut attempt = 0;
        let start_time = Instant::now();

        loop {
            // Check timeout
            if let Some(timeout_duration) = self.timeout_duration {
                if start_time.elapsed() > timeout_duration {
                    return Err(RetryError::Timeout);
                }
            }

            // Execute operation
            let result = if let Some(timeout_duration) = self.timeout_duration {
                timeout(timeout_duration, operation()).await
                    .map_err(|_| RetryError::Timeout)?
            } else {
                operation().await
            };

            match result {
                Ok(value) => {
                    self.policy.on_success();
                    return Ok(value);
                }
                Err(error) => {
                    let processing_error = error.clone().into();

                    if !self.policy.should_retry(attempt, &processing_error) {
                        return Err(RetryError::MaxAttemptsExceeded {
                            attempts: attempt + 1,
                            last_error: error,
                        });
                    }

                    attempt += 1;

                    // Handle rate limiting
                    let delay = if let Some(retry_after) = processing_error.retry_after() {
                        retry_after
                    } else {
                        self.policy.delay_duration(attempt)
                    };

                    sleep(delay).await;
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum RetryError<E> {
    Timeout,
    MaxAttemptsExceeded { attempts: u32, last_error: E },
}

#[async_trait]
pub trait RetryPolicy: Send + Sync {
    fn should_retry(&self, attempt: u32, error: &ProcessingError) -> bool;
    fn delay_duration(&self, attempt: u32) -> Duration;
    fn on_success(&self) {}
    fn on_failure(&self, _attempt: u32, _error: &ProcessingError) {}
}
```

## Integration with Queue Clients

### Retry-Aware Message Processing

```rust
impl<T> QueueClient<T> for RetryAwareQueueClient<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn send(&self, queue_name: &str, message: &T, session_id: Option<&str>) -> Result<MessageId, QueueError> {
        let retry_executor = RetryExecutor::new(self.create_retry_policy());

        retry_executor.execute(|| {
            Box::pin(self.inner_client.send(queue_name, message, session_id))
        }).await
        .map_err(|retry_error| match retry_error {
            RetryError::Timeout => QueueError::Timeout,
            RetryError::MaxAttemptsExceeded { last_error, .. } => last_error,
        })
    }

    async fn receive(&self, queue_name: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError> {
        let retry_executor = RetryExecutor::new(self.create_retry_policy());

        retry_executor.execute(|| {
            Box::pin(self.inner_client.receive(queue_name, max_messages))
        }).await
        .map_err(|retry_error| match retry_error {
            RetryError::Timeout => QueueError::Timeout,
            RetryError::MaxAttemptsExceeded { last_error, .. } => last_error,
        })
    }
}
```

### Message Processing with Retry

```rust
pub struct MessageProcessor<T> {
    queue_client: Arc<dyn QueueClient<T>>,
    retry_config: RetryConfig,
}

impl<T> MessageProcessor<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub async fn process_with_retry<F>(&self, message: ReceivedMessage<T, impl MessageReceipt>, processor: F) -> Result<(), ProcessingError>
    where
        F: Fn(&T) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ProcessingError>> + Send>> + Send + Sync,
    {
        let retry_executor = RetryExecutor::new(self.create_retry_policy());

        let result = retry_executor.execute(|| {
            Box::pin(processor(&message.payload))
        }).await;

        match result {
            Ok(_) => {
                // Acknowledge successful processing
                self.queue_client.acknowledge(&message.receipt).await?;
                Ok(())
            }
            Err(RetryError::MaxAttemptsExceeded { last_error, .. }) => {
                // Send to dead letter queue
                if self.retry_config.dead_letter_enabled {
                    self.send_to_dead_letter(&message, &last_error).await?;
                }

                // Reject the message
                self.queue_client.reject(&message.receipt).await?;
                Err(last_error)
            }
            Err(RetryError::Timeout) => {
                self.queue_client.reject(&message.receipt).await?;
                Err(ProcessingError::NetworkTimeout("Processing timeout".to_string()))
            }
        }
    }

    async fn send_to_dead_letter(&self, message: &ReceivedMessage<T, impl MessageReceipt>, error: &ProcessingError) -> Result<(), QueueError> {
        let dead_letter_message = DeadLetterMessage {
            original_message: message.payload.clone(),
            error_details: error.clone(),
            retry_count: message.delivery_count,
            failed_at: Utc::now(),
            original_queue: message.queue_name.clone(),
        };

        let dlq_name = format!("{}-dlq", message.queue_name);
        self.queue_client.send(&dlq_name, &dead_letter_message, None).await?;

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterMessage<T> {
    pub original_message: T,
    pub error_details: ProcessingError,
    pub retry_count: u32,
    pub failed_at: DateTime<Utc>,
    pub original_queue: String,
}
```

## Monitoring and Observability

### Retry Metrics

```rust
use prometheus::{Counter, Histogram, Gauge};

pub struct RetryMetrics {
    pub retry_attempts: Counter,
    pub retry_successes: Counter,
    pub retry_failures: Counter,
    pub retry_delay_duration: Histogram,
    pub circuit_breaker_state: Gauge,
    pub dead_letter_messages: Counter,
}

impl RetryMetrics {
    pub fn new() -> Self {
        Self {
            retry_attempts: Counter::new("queue_retry_attempts_total", "Total retry attempts").unwrap(),
            retry_successes: Counter::new("queue_retry_successes_total", "Successful retries").unwrap(),
            retry_failures: Counter::new("queue_retry_failures_total", "Failed retries").unwrap(),
            retry_delay_duration: Histogram::new("queue_retry_delay_seconds", "Retry delay duration").unwrap(),
            circuit_breaker_state: Gauge::new("queue_circuit_breaker_state", "Circuit breaker state (0=closed, 1=open, 2=half-open)").unwrap(),
            dead_letter_messages: Counter::new("queue_dead_letter_messages_total", "Messages sent to dead letter queue").unwrap(),
        }
    }

    pub fn record_retry_attempt(&self, policy_type: &str, attempt: u32) {
        self.retry_attempts.with_label_values(&[policy_type, &attempt.to_string()]).inc();
    }

    pub fn record_retry_success(&self, policy_type: &str, attempts: u32) {
        self.retry_successes.with_label_values(&[policy_type]).inc();
    }

    pub fn record_retry_failure(&self, policy_type: &str, error_type: &str) {
        self.retry_failures.with_label_values(&[policy_type, error_type]).inc();
    }

    pub fn record_dead_letter(&self, queue_name: &str, error_type: &str) {
        self.dead_letter_messages.with_label_values(&[queue_name, error_type]).inc();
    }
}
```

### Tracing Integration

```rust
use tracing::{info, warn, error, instrument};

impl RetryExecutor {
    #[instrument(skip(self, operation), fields(attempt = 0, delay_ms = 0))]
    pub async fn execute_with_tracing<F, T, E>(&self, operation: F) -> Result<T, RetryError<E>>
    where
        F: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>> + Send + Sync,
        E: Into<ProcessingError> + Clone + Send + Sync + std::fmt::Debug,
        T: Send,
    {
        let mut attempt = 0;
        let start_time = Instant::now();

        loop {
            tracing::Span::current().record("attempt", &attempt);

            info!("Executing operation, attempt {}", attempt + 1);

            let result = operation().await;

            match result {
                Ok(value) => {
                    info!("Operation succeeded after {} attempts", attempt + 1);
                    self.policy.on_success();
                    return Ok(value);
                }
                Err(error) => {
                    let processing_error = error.clone().into();

                    warn!("Operation failed on attempt {}: {:?}", attempt + 1, error);

                    if !self.policy.should_retry(attempt, &processing_error) {
                        error!("Max retry attempts exceeded, giving up");
                        return Err(RetryError::MaxAttemptsExceeded {
                            attempts: attempt + 1,
                            last_error: error,
                        });
                    }

                    attempt += 1;

                    let delay = if let Some(retry_after) = processing_error.retry_after() {
                        retry_after
                    } else {
                        self.policy.delay_duration(attempt)
                    };

                    tracing::Span::current().record("delay_ms", &delay.as_millis());
                    info!("Retrying after {}ms delay", delay.as_millis());

                    sleep(delay).await;
                }
            }
        }
    }
}
```

## Testing Support

### Retry Policy Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{pause, resume};

    #[tokio::test]
    async fn test_exponential_backoff_delays() {
        let policy = ExponentialBackoffPolicy {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            max_attempts: 5,
            jitter_enabled: false,
        };

        assert_eq!(policy.delay_duration(1), Duration::from_millis(200));
        assert_eq!(policy.delay_duration(2), Duration::from_millis(400));
        assert_eq!(policy.delay_duration(3), Duration::from_millis(800));
    }

    #[tokio::test]
    async fn test_circuit_breaker_state_transitions() {
        pause();

        let policy = CircuitBreakerPolicy {
            failure_threshold: 3,
            recovery_timeout: Duration::from_secs(60),
            success_threshold: 2,
            state: Arc::new(RwLock::new(CircuitBreakerState {
                state: CircuitState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
            })),
        };

        let retryable_error = ProcessingError::TemporaryServiceUnavailable("Test".to_string());

        // Should retry first few failures
        assert!(policy.should_retry(0, &retryable_error));
        assert!(policy.should_retry(1, &retryable_error));
        assert!(policy.should_retry(2, &retryable_error));

        // Circuit should open after threshold
        assert!(!policy.should_retry(3, &retryable_error));

        resume();
    }

    #[tokio::test]
    async fn test_retry_executor_with_mock_operation() {
        let policy = Box::new(ExponentialBackoffPolicy::default());
        let executor = RetryExecutor::new(policy);

        let mut call_count = 0;
        let operation = || {
            call_count += 1;
            Box::pin(async move {
                if call_count < 3 {
                    Err(ProcessingError::TemporaryServiceUnavailable("Mock failure".to_string()))
                } else {
                    Ok("Success".to_string())
                }
            })
        };

        let result = executor.execute(operation).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Success");
        assert_eq!(call_count, 3);
    }
}
```

## Best Practices

1. **Choose Appropriate Policy**: Match retry strategy to failure patterns
2. **Set Reasonable Limits**: Avoid infinite retries and excessive delays
3. **Classify Errors Correctly**: Don't retry non-retryable errors
4. **Monitor Circuit Breakers**: Track state transitions and recovery
5. **Use Dead Letter Queues**: Preserve failed messages for analysis
6. **Add Jitter**: Prevent thundering herd problems
7. **Test Retry Behavior**: Verify retry logic with failure injection
8. **Track Metrics**: Monitor retry success rates and patterns
