# Testing Strategy

This document defines the testing requirements for the Queue Runtime to ensure reliable queue operations, message handling, and error recovery across Azure Service Bus and AWS SQS providers.

## Overview

The testing strategy focuses on **what** must be validated to ensure correct behavior across different queue providers while maintaining consistent session management, retry logic, and observability.

## Test Categories

### 1. Unit Tests

Test individual components in isolation:

```rust
#[cfg(test)]
mod unit_tests {
    use super::*;
    use mockall::{mock, predicate::*};
    use tokio_test;

    mock! {
        QueueClient<T: Clone + Send + Sync + 'static> {}

        #[async_trait]
        impl<T: Clone + Send + Sync + 'static> QueueClient<T> for QueueClient<T> {
            type Receipt = MockReceipt;

            async fn send(&self, queue_name: &str, message: &T, session_id: Option<&str>) -> Result<MessageId, QueueError>;
            async fn receive(&self, queue_name: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError>;
            async fn acknowledge(&self, receipt: &Self::Receipt) -> Result<(), QueueError>;
            async fn reject(&self, receipt: &Self::Receipt) -> Result<(), QueueError>;
            async fn dead_letter(&self, receipt: &Self::Receipt, reason: &str) -> Result<(), QueueError>;
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockReceipt {
        pub id: String,
    }

    impl MessageReceipt for MockReceipt {
        fn message_id(&self) -> &str {
            &self.id
        }

        fn is_valid(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn test_message_send_success() {
        let mut mock_client = MockQueueClient::new();

        mock_client
            .expect_send()
            .with(eq("test-queue"), always(), eq(None))
            .times(1)
            .returning(|_, _, _| Ok(MessageId::new("msg-123".to_string())));

        let message = TestMessage {
            content: "test message".to_string(),
        };

        let result = mock_client.send("test-queue", &message, None).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "msg-123");
    }

    #[tokio::test]
    async fn test_message_send_error() {
        let mut mock_client = MockQueueClient::new();

        mock_client
            .expect_send()
            .with(eq("test-queue"), always(), eq(None))
            .times(1)
            .returning(|_, _, _| Err(QueueError::NetworkError("Connection failed".to_string())));

        let message = TestMessage {
            content: "test message".to_string(),
        };

        let result = mock_client.send("test-queue", &message, None).await;

        assert!(result.is_err());
        match result {
            Err(QueueError::NetworkError(msg)) => assert_eq!(msg, "Connection failed"),
            _ => panic!("Expected NetworkError"),
        }
    }

    #[tokio::test]
    async fn test_session_key_generation() {
        let strategy = EntitySessionStrategy;

        let envelope = create_test_envelope(EntityType::PullRequest, Some("123".to_string()));
        let session_key = strategy.generate_key(&envelope);

        assert_eq!(session_key, Some("pr-test/repo-123".to_string()));
    }

    #[tokio::test]
    async fn test_retry_policy_exponential_backoff() {
        let policy = ExponentialBackoffPolicy {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            max_attempts: 5,
            jitter_enabled: false,
        };

        let retryable_error = ProcessingError::TemporaryServiceUnavailable("Service down".to_string());
        let non_retryable_error = ProcessingError::ValidationError("Invalid data".to_string());

        assert!(policy.should_retry(0, &retryable_error));
        assert!(policy.should_retry(4, &retryable_error));
        assert!(!policy.should_retry(5, &retryable_error));
        assert!(!policy.should_retry(0, &non_retryable_error));

        assert_eq!(policy.delay_duration(1), Duration::from_millis(200));
        assert_eq!(policy.delay_duration(2), Duration::from_millis(400));
    }
}
```

### 2. Integration Tests

Test component interactions with real or embedded providers:

```rust
#[cfg(test)]
mod integration_tests {
    use super::*;
    use testcontainers::*;
    use testcontainers_modules::{localstack::LocalStack, azurite::Azurite};

    #[tokio::test]
    async fn test_azure_servicebus_integration() {
        // Use Azurite for local Azure Service Bus emulation
        let docker = clients::Cli::default();
        let azurite = docker.run(Azurite::default());

        let connection_string = format!(
            "Endpoint=sb://localhost:{}/;SharedAccessKeyName=test;SharedAccessKey=test",
            azurite.get_host_port_ipv4(10000)
        );

        let config = AzureServiceBusConfig {
            connection_string: Some(connection_string),
            auth_method: AzureAuthMethod::ConnectionString,
            enable_sessions: true,
            ..Default::default()
        };

        let client = AzureServiceBusClient::<TestMessage>::new(
            &config.connection_string.unwrap()
        ).await.unwrap();

        // Test queue creation
        let queue_manager = AzureQueueManager::new(config.clone()).await.unwrap();
        queue_manager.create_queue("integration-test-queue", false).await.unwrap();

        // Test message send/receive cycle
        let test_message = TestMessage {
            content: "integration test message".to_string(),
        };

        let message_id = client.send("integration-test-queue", &test_message, None).await.unwrap();
        assert!(!message_id.to_string().is_empty());

        let received_messages = client.receive("integration-test-queue", 10).await.unwrap();
        assert_eq!(received_messages.len(), 1);
        assert_eq!(received_messages[0].payload.content, test_message.content);

        // Test acknowledgment
        client.acknowledge(&received_messages[0].receipt).await.unwrap();

        // Verify queue is empty
        let empty_messages = client.receive("integration-test-queue", 10).await.unwrap();
        assert_eq!(empty_messages.len(), 0);
    }

    #[tokio::test]
    async fn test_aws_sqs_integration() {
        // Use LocalStack for local AWS SQS emulation
        let docker = clients::Cli::default();
        let localstack = docker.run(LocalStack::default());

        let config = AwsSqsConfig {
            region: Some("us-east-1".to_string()),
            endpoint_url: Some(format!("http://localhost:{}", localstack.get_host_port_ipv4(4566))),
            auth_method: AwsAuthMethod::AccessKey {
                access_key_id: "test".to_string(),
                secret_access_key: "test".to_string(),
                session_token: None,
            },
            ..Default::default()
        };

        let client = AwsSqsClient::<TestMessage>::new(config.clone()).await.unwrap();

        // Test queue creation
        let queue_manager = AwsQueueManager::new(config).await.unwrap();
        let _queue_url = queue_manager.create_queue("integration-test-queue", false).await.unwrap();

        // Test message send/receive cycle
        let test_message = TestMessage {
            content: "integration test message".to_string(),
        };

        let message_id = client.send("integration-test-queue", &test_message, None).await.unwrap();
        assert!(!message_id.to_string().is_empty());

        let received_messages = client.receive("integration-test-queue", 10).await.unwrap();
        assert_eq!(received_messages.len(), 1);
        assert_eq!(received_messages[0].payload.content, test_message.content);

        // Test acknowledgment
        client.acknowledge(&received_messages[0].receipt).await.unwrap();

        // Verify message is deleted
        let empty_messages = client.receive("integration-test-queue", 10).await.unwrap();
        assert_eq!(empty_messages.len(), 0);
    }

    #[tokio::test]
    async fn test_session_ordering_integration() {
        let client = create_test_azure_client().await;
        let session_id = "test-session-123";

        // Send multiple messages with same session ID
        let messages = vec![
            TestMessage { content: "message 1".to_string() },
            TestMessage { content: "message 2".to_string() },
            TestMessage { content: "message 3".to_string() },
        ];

        for message in &messages {
            client.send("session-test-queue", message, Some(session_id)).await.unwrap();
        }

        // Receive messages from session
        let received_messages = client.receive_from_session("session-test-queue", session_id, 10).await.unwrap();

        assert_eq!(received_messages.len(), 3);

        // Verify order is maintained
        for (i, received_message) in received_messages.iter().enumerate() {
            assert_eq!(received_message.payload.content, messages[i].content);
            assert_eq!(received_message.session_id.as_deref(), Some(session_id));
        }

        // Acknowledge all messages
        for message in &received_messages {
            client.acknowledge(&message.receipt).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_dead_letter_queue_integration() {
        let client = create_test_azure_client().await;
        let dlq_manager = create_test_dlq_manager().await;

        // Send a message
        let test_message = TestMessage {
            content: "test dlq message".to_string(),
        };

        client.send("dlq-test-queue", &test_message, None).await.unwrap();

        // Receive and simulate processing failure
        let received_messages = client.receive("dlq-test-queue", 1).await.unwrap();
        assert_eq!(received_messages.len(), 1);

        let failure_info = FailureInfo {
            error_type: "TestError".to_string(),
            error_message: "Simulated failure".to_string(),
            error_details: None,
            stack_trace: None,
            retry_attempts: vec![],
            failed_at: Utc::now(),
            processing_context: HashMap::new(),
        };

        // Dead letter the message
        dlq_manager.dead_letter_message(&received_messages[0], failure_info).await.unwrap();

        // Verify message is in DLQ
        let dlq_messages = dlq_manager.retrieve_dead_letters("dlq-test-queue", 10).await.unwrap();
        assert_eq!(dlq_messages.len(), 1);
        assert_eq!(dlq_messages[0].original_message.content, test_message.content);

        // Test requeue functionality
        let requeue_result = dlq_manager.requeue_message(&dlq_messages[0], true).await;
        assert!(requeue_result.is_ok());
    }
}
```

### 3. End-to-End Tests

Test complete workflows across multiple components:

```rust
#[cfg(test)]
mod e2e_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_complete_message_processing_workflow() {
        let test_scenario = TestScenario::new().await;

        // Setup: Create queues and configure components
        test_scenario.setup_queues().await;

        let processed_count = Arc::new(AtomicU32::new(0));
        let processed_count_clone = processed_count.clone();

        // Message processor that simulates bot logic
        let message_processor = move |message: &TestMessage| {
            let count = processed_count_clone.clone();
            Box::pin(async move {
                // Simulate processing time
                tokio::time::sleep(Duration::from_millis(100)).await;

                if message.content.contains("fail") {
                    Err(ProcessingError::ValidationError("Simulated failure".to_string()))
                } else {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
        };

        // Send test messages
        let test_messages = vec![
            TestMessage { content: "success message 1".to_string() },
            TestMessage { content: "success message 2".to_string() },
            TestMessage { content: "fail message 1".to_string() },
            TestMessage { content: "success message 3".to_string() },
        ];

        for message in &test_messages {
            test_scenario.queue_client.send("e2e-test-queue", message, None).await.unwrap();
        }

        // Process messages with retry logic
        let mut retry_executor = RetryExecutor::new(Box::new(ExponentialBackoffPolicy::default()));

        loop {
            let messages = test_scenario.queue_client.receive("e2e-test-queue", 10).await.unwrap();

            if messages.is_empty() {
                break;
            }

            for message in messages {
                let result = retry_executor.execute(|| {
                    Box::pin(message_processor(&message.payload))
                }).await;

                match result {
                    Ok(_) => {
                        test_scenario.queue_client.acknowledge(&message.receipt).await.unwrap();
                    }
                    Err(RetryError::MaxAttemptsExceeded { last_error, .. }) => {
                        test_scenario.dlq_manager.dead_letter_message(
                            &message,
                            create_failure_info(&last_error)
                        ).await.unwrap();

                        test_scenario.queue_client.acknowledge(&message.receipt).await.unwrap();
                    }
                    Err(RetryError::Timeout) => {
                        test_scenario.queue_client.reject(&message.receipt).await.unwrap();
                    }
                }
            }
        }

        // Verify results
        assert_eq!(processed_count.load(Ordering::SeqCst), 3); // 3 successful messages

        let dlq_messages = test_scenario.dlq_manager.retrieve_dead_letters("e2e-test-queue", 10).await.unwrap();
        assert_eq!(dlq_messages.len(), 1); // 1 failed message
        assert!(dlq_messages[0].original_message.content.contains("fail"));

        // Verify metrics
        let metrics = test_scenario.metrics;
        assert_eq!(metrics.messages_sent_total.get(), 4);
        assert_eq!(metrics.messages_acknowledged_total.get(), 4);
        assert_eq!(metrics.messages_dead_lettered_total.get(), 1);
    }

    #[tokio::test]
    async fn test_session_based_ordering_e2e() {
        let test_scenario = TestScenario::new().await;
        test_scenario.setup_queues().await;

        let processing_order = Arc::new(RwLock::new(Vec::new()));
        let processing_order_clone = processing_order.clone();

        // Processor that records processing order
        let message_processor = move |message: &TestMessage| {
            let order = processing_order_clone.clone();
            Box::pin(async move {
                order.write().await.push(message.content.clone());
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(())
            })
        };

        // Send messages to different sessions
        let session_a_messages = vec![
            TestMessage { content: "A1".to_string() },
            TestMessage { content: "A2".to_string() },
            TestMessage { content: "A3".to_string() },
        ];

        let session_b_messages = vec![
            TestMessage { content: "B1".to_string() },
            TestMessage { content: "B2".to_string() },
        ];

        // Send session A messages
        for message in &session_a_messages {
            test_scenario.queue_client.send("session-test-queue", message, Some("session-a")).await.unwrap();
        }

        // Send session B messages
        for message in &session_b_messages {
            test_scenario.queue_client.send("session-test-queue", message, Some("session-b")).await.unwrap();
        }

        // Process messages from each session sequentially
        let session_a_task = {
            let client = test_scenario.queue_client.clone();
            let processor = message_processor.clone();

            tokio::spawn(async move {
                loop {
                    let messages = client.receive_from_session("session-test-queue", "session-a", 1).await.unwrap();
                    if messages.is_empty() {
                        break;
                    }

                    for message in messages {
                        processor(&message.payload).await.unwrap();
                        client.acknowledge(&message.receipt).await.unwrap();
                    }
                }
            })
        };

        let session_b_task = {
            let client = test_scenario.queue_client.clone();
            let processor = message_processor.clone();

            tokio::spawn(async move {
                loop {
                    let messages = client.receive_from_session("session-test-queue", "session-b", 1).await.unwrap();
                    if messages.is_empty() {
                        break;
                    }

                    for message in messages {
                        processor(&message.payload).await.unwrap();
                        client.acknowledge(&message.receipt).await.unwrap();
                    }
                }
            })
        };

        // Wait for both sessions to complete
        tokio::try_join!(session_a_task, session_b_task).unwrap();

        // Verify session ordering is maintained
        let final_order = processing_order.read().await;

        // Find positions of session A messages
        let a1_pos = final_order.iter().position(|x| x == "A1").unwrap();
        let a2_pos = final_order.iter().position(|x| x == "A2").unwrap();
        let a3_pos = final_order.iter().position(|x| x == "A3").unwrap();

        // Verify A1 < A2 < A3
        assert!(a1_pos < a2_pos);
        assert!(a2_pos < a3_pos);

        // Find positions of session B messages
        let b1_pos = final_order.iter().position(|x| x == "B1").unwrap();
        let b2_pos = final_order.iter().position(|x| x == "B2").unwrap();

        // Verify B1 < B2
        assert!(b1_pos < b2_pos);
    }
}
```

## Test Utilities

### Test Data Builders

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TestMessage {
    pub content: String,
}

pub struct TestEventBuilder {
    event_type: String,
    repository: Repository,
    entity_type: EntityType,
    entity_id: Option<String>,
    payload: serde_json::Value,
}

impl TestEventBuilder {
    pub fn new() -> Self {
        Self {
            event_type: "test_event".to_string(),
            repository: Repository::new("test-owner", "test-repo"),
            entity_type: EntityType::Repository,
            entity_id: None,
            payload: serde_json::json!({}),
        }
    }

    pub fn with_event_type(mut self, event_type: &str) -> Self {
        self.event_type = event_type.to_string();
        self
    }

    pub fn with_repository(mut self, owner: &str, name: &str) -> Self {
        self.repository = Repository::new(owner, name);
        self
    }

    pub fn with_pull_request(mut self, pr_number: u32) -> Self {
        self.entity_type = EntityType::PullRequest;
        self.entity_id = Some(pr_number.to_string());
        self.event_type = "pull_request".to_string();
        self
    }

    pub fn with_issue(mut self, issue_number: u32) -> Self {
        self.entity_type = EntityType::Issue;
        self.entity_id = Some(issue_number.to_string());
        self.event_type = "issues".to_string();
        self
    }

    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    pub fn build(self) -> EventEnvelope {
        EventEnvelope {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type: self.event_type,
            repository: self.repository,
            entity_type: self.entity_type,
            entity_id: self.entity_id,
            payload: self.payload,
            metadata: EventMetadata {
                received_at: Utc::now(),
                source_ip: Some("127.0.0.1".to_string()),
                user_agent: Some("test-client".to_string()),
                correlation_id: Some(uuid::Uuid::new_v4().to_string()),
                idempotency_key: None,
            },
        }
    }
}

pub fn create_test_envelope(entity_type: EntityType, entity_id: Option<String>) -> EventEnvelope {
    EventEnvelope {
        event_id: uuid::Uuid::new_v4().to_string(),
        event_type: "test_event".to_string(),
        repository: Repository::new("test", "repo"),
        entity_type,
        entity_id,
        payload: serde_json::json!({"test": "data"}),
        metadata: EventMetadata {
            received_at: Utc::now(),
            source_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("test-client".to_string()),
            correlation_id: Some(uuid::Uuid::new_v4().to_string()),
            idempotency_key: None,
        },
    }
}

pub fn create_failure_info(error: &ProcessingError) -> FailureInfo {
    FailureInfo {
        error_type: format!("{:?}", error).split('(').next().unwrap_or("Unknown").to_string(),
        error_message: error.to_string(),
        error_details: None,
        stack_trace: None,
        retry_attempts: vec![],
        failed_at: Utc::now(),
        processing_context: HashMap::new(),
    }
}
```

### Test Scenario Framework

```rust
pub struct TestScenario {
    pub queue_client: Arc<dyn QueueClient<TestMessage>>,
    pub dlq_manager: Arc<dyn DeadLetterQueueManager<TestMessage>>,
    pub metrics: Arc<QueueMetrics>,
    pub health_monitor: Arc<QueueHealthMonitor>,
    pub provider_type: ProviderType,
}

#[derive(Debug, Clone)]
pub enum ProviderType {
    Azure,
    Aws,
    InMemory,
}

impl TestScenario {
    pub async fn new() -> Self {
        Self::with_provider(ProviderType::InMemory).await
    }

    pub async fn with_provider(provider_type: ProviderType) -> Self {
        let metrics = Arc::new(QueueMetrics::new().unwrap());
        let health_monitor = Arc::new(QueueHealthMonitor::new(Duration::from_secs(5)));

        let (queue_client, dlq_manager) = match provider_type {
            ProviderType::Azure => {
                let config = create_test_azure_config();
                let client = Arc::new(AzureServiceBusClient::new(&config.connection_string.unwrap()).await.unwrap());
                let dlq_client = client.clone();
                let dlq_manager = Arc::new(StandardDlqManager::new(dlq_client, DlqConfig::default()));
                (client as Arc<dyn QueueClient<TestMessage>>, dlq_manager as Arc<dyn DeadLetterQueueManager<TestMessage>>)
            },
            ProviderType::Aws => {
                let config = create_test_aws_config();
                let client = Arc::new(AwsSqsClient::new(config).await.unwrap());
                let dlq_client = client.clone();
                let dlq_manager = Arc::new(StandardDlqManager::new(dlq_client, DlqConfig::default()));
                (client as Arc<dyn QueueClient<TestMessage>>, dlq_manager as Arc<dyn DeadLetterQueueManager<TestMessage>>)
            },
            ProviderType::InMemory => {
                let client = Arc::new(InMemoryQueueClient::new());
                let dlq_client = client.clone();
                let dlq_manager = Arc::new(StandardDlqManager::new(dlq_client, DlqConfig::default()));
                (client as Arc<dyn QueueClient<TestMessage>>, dlq_manager as Arc<dyn DeadLetterQueueManager<TestMessage>>)
            },
        };

        Self {
            queue_client,
            dlq_manager,
            metrics,
            health_monitor,
            provider_type,
        }
    }

    pub async fn setup_queues(&self) {
        match self.provider_type {
            ProviderType::Azure => {
                let config = create_test_azure_config();
                let manager = AzureQueueManager::new(config).await.unwrap();
                manager.create_queue("e2e-test-queue", false).await.unwrap();
                manager.create_queue("session-test-queue", true).await.unwrap();
                manager.create_queue("dlq-test-queue", false).await.unwrap();
            },
            ProviderType::Aws => {
                let config = create_test_aws_config();
                let manager = AwsQueueManager::new(config).await.unwrap();
                manager.create_queue("e2e-test-queue", false).await.unwrap();
                manager.create_queue("session-test-queue.fifo", true).await.unwrap();
                manager.create_queue("dlq-test-queue", false).await.unwrap();
            },
            ProviderType::InMemory => {
                // In-memory queues are created automatically
            },
        }
    }

    pub async fn cleanup(&self) {
        match self.provider_type {
            ProviderType::Azure => {
                let config = create_test_azure_config();
                let manager = AzureQueueManager::new(config).await.unwrap();
                let _ = manager.delete_queue("e2e-test-queue").await;
                let _ = manager.delete_queue("session-test-queue").await;
                let _ = manager.delete_queue("dlq-test-queue").await;
            },
            ProviderType::Aws => {
                let config = create_test_aws_config();
                let manager = AwsQueueManager::new(config).await.unwrap();
                let _ = manager.delete_queue("e2e-test-queue").await;
                let _ = manager.delete_queue("session-test-queue.fifo").await;
                let _ = manager.delete_queue("dlq-test-queue").await;
            },
            ProviderType::InMemory => {
                // In-memory cleanup is automatic
            },
        }
    }
}

impl Drop for TestScenario {
    fn drop(&mut self) {
        // Async cleanup in drop is not ideal, but provides fallback
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(rt) = rt {
            rt.spawn(async move {
                // Cleanup code here if needed
            });
        }
    }
}
```

### In-Memory Test Provider

```rust
pub struct InMemoryQueueClient<T> {
    queues: Arc<RwLock<HashMap<String, VecDeque<InMemoryMessage<T>>>>>,
    session_queues: Arc<RwLock<HashMap<String, HashMap<String, VecDeque<InMemoryMessage<T>>>>>>,
    next_message_id: Arc<AtomicU64>,
}

#[derive(Debug, Clone)]
struct InMemoryMessage<T> {
    id: String,
    payload: T,
    session_id: Option<String>,
    enqueued_at: DateTime<Utc>,
    delivery_count: u32,
    receipt_handle: String,
}

#[derive(Debug, Clone)]
pub struct InMemoryReceipt {
    queue_name: String,
    message_id: String,
    receipt_handle: String,
    client: Arc<InMemoryQueueClient<()>>, // Type erased for simplicity
}

impl<T> InMemoryQueueClient<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn new() -> Self {
        Self {
            queues: Arc::new(RwLock::new(HashMap::new())),
            session_queues: Arc::new(RwLock::new(HashMap::new())),
            next_message_id: Arc::new(AtomicU64::new(1)),
        }
    }

    async fn get_or_create_queue(&self, queue_name: &str) -> VecDeque<InMemoryMessage<T>> {
        let queues = self.queues.read().await;
        queues.get(queue_name).cloned().unwrap_or_default()
    }

    async fn get_or_create_session_queue(&self, queue_name: &str, session_id: &str) -> VecDeque<InMemoryMessage<T>> {
        let session_queues = self.session_queues.read().await;
        session_queues
            .get(queue_name)
            .and_then(|sessions| sessions.get(session_id))
            .cloned()
            .unwrap_or_default()
    }
}

#[async_trait]
impl<T> QueueClient<T> for InMemoryQueueClient<T>
where
    T: Clone + Send + Sync + 'static,
{
    type Receipt = InMemoryReceipt;

    async fn send(&self, queue_name: &str, message: &T, session_id: Option<&str>) -> Result<MessageId, QueueError> {
        let message_id = self.next_message_id.fetch_add(1, Ordering::SeqCst);
        let receipt_handle = uuid::Uuid::new_v4().to_string();

        let in_memory_message = InMemoryMessage {
            id: message_id.to_string(),
            payload: message.clone(),
            session_id: session_id.map(|s| s.to_string()),
            enqueued_at: Utc::now(),
            delivery_count: 0,
            receipt_handle: receipt_handle.clone(),
        };

        if let Some(session_id) = session_id {
            let mut session_queues = self.session_queues.write().await;
            session_queues
                .entry(queue_name.to_string())
                .or_default()
                .entry(session_id.to_string())
                .or_default()
                .push_back(in_memory_message);
        } else {
            let mut queues = self.queues.write().await;
            queues
                .entry(queue_name.to_string())
                .or_default()
                .push_back(in_memory_message);
        }

        Ok(MessageId::new(message_id.to_string()))
    }

    async fn receive(&self, queue_name: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError> {
        let mut queues = self.queues.write().await;
        let queue = queues.entry(queue_name.to_string()).or_default();

        let mut messages = Vec::new();
        let count = (max_messages as usize).min(queue.len());

        for _ in 0..count {
            if let Some(mut message) = queue.pop_front() {
                message.delivery_count += 1;

                let receipt = InMemoryReceipt {
                    queue_name: queue_name.to_string(),
                    message_id: message.id.clone(),
                    receipt_handle: message.receipt_handle.clone(),
                    client: Arc::new(InMemoryQueueClient::new()), // Simplified
                };

                let received_message = ReceivedMessage {
                    message_id: MessageId::new(message.id.clone()),
                    payload: message.payload.clone(),
                    receipt,
                    delivery_count: message.delivery_count,
                    enqueued_at: message.enqueued_at,
                    queue_name: queue_name.to_string(),
                    session_id: message.session_id.clone(),
                };

                messages.push(received_message);

                // Put message back at front for potential retry (not acknowledged yet)
                queue.push_front(message);
            }
        }

        Ok(messages)
    }

    async fn receive_from_session(&self, queue_name: &str, session_id: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError> {
        let mut session_queues = self.session_queues.write().await;
        let queue = session_queues
            .entry(queue_name.to_string())
            .or_default()
            .entry(session_id.to_string())
            .or_default();

        let mut messages = Vec::new();
        let count = (max_messages as usize).min(queue.len());

        for _ in 0..count {
            if let Some(mut message) = queue.pop_front() {
                message.delivery_count += 1;

                let receipt = InMemoryReceipt {
                    queue_name: queue_name.to_string(),
                    message_id: message.id.clone(),
                    receipt_handle: message.receipt_handle.clone(),
                    client: Arc::new(InMemoryQueueClient::new()),
                };

                let received_message = ReceivedMessage {
                    message_id: MessageId::new(message.id.clone()),
                    payload: message.payload.clone(),
                    receipt,
                    delivery_count: message.delivery_count,
                    enqueued_at: message.enqueued_at,
                    queue_name: queue_name.to_string(),
                    session_id: Some(session_id.to_string()),
                };

                messages.push(received_message);
                queue.push_front(message);
            }
        }

        Ok(messages)
    }

    async fn acknowledge(&self, receipt: &Self::Receipt) -> Result<(), QueueError> {
        // Remove message from queue (it's acknowledged)
        if let Some(session_id) = &receipt.message_id {
            let mut session_queues = self.session_queues.write().await;
            if let Some(sessions) = session_queues.get_mut(&receipt.queue_name) {
                for (_, queue) in sessions.iter_mut() {
                    queue.retain(|msg| msg.receipt_handle != receipt.receipt_handle);
                }
            }
        } else {
            let mut queues = self.queues.write().await;
            if let Some(queue) = queues.get_mut(&receipt.queue_name) {
                queue.retain(|msg| msg.receipt_handle != receipt.receipt_handle);
            }
        }

        Ok(())
    }

    async fn reject(&self, _receipt: &Self::Receipt) -> Result<(), QueueError> {
        // Message remains in queue for retry
        Ok(())
    }

    async fn dead_letter(&self, receipt: &Self::Receipt, _reason: &str) -> Result<(), QueueError> {
        // Move to dead letter queue (simplified)
        self.acknowledge(receipt).await
    }
}

impl MessageReceipt for InMemoryReceipt {
    fn message_id(&self) -> &str {
        &self.message_id
    }

    fn is_valid(&self) -> bool {
        true
    }
}
```

## Performance Testing

### Load Testing Framework

```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_throughput_performance() {
        let test_scenario = TestScenario::new().await;
        test_scenario.setup_queues().await;

        let message_count = 1000;
        let concurrent_senders = 10;
        let messages_per_sender = message_count / concurrent_senders;

        let start_time = Instant::now();

        // Send messages concurrently
        let send_tasks: Vec<_> = (0..concurrent_senders)
            .map(|sender_id| {
                let client = test_scenario.queue_client.clone();
                tokio::spawn(async move {
                    for i in 0..messages_per_sender {
                        let message = TestMessage {
                            content: format!("Message {} from sender {}", i, sender_id),
                        };

                        client.send("performance-test-queue", &message, None).await.unwrap();
                    }
                })
            })
            .collect();

        futures::future::try_join_all(send_tasks).await.unwrap();

        let send_duration = start_time.elapsed();
        let send_throughput = message_count as f64 / send_duration.as_secs_f64();

        println!("Send throughput: {:.2} messages/sec", send_throughput);

        // Receive messages concurrently
        let receive_start = Instant::now();
        let concurrent_receivers = 5;
        let mut total_received = 0;

        let receive_tasks: Vec<_> = (0..concurrent_receivers)
            .map(|_| {
                let client = test_scenario.queue_client.clone();
                tokio::spawn(async move {
                    let mut received_count = 0;

                    loop {
                        let messages = client.receive("performance-test-queue", 10).await.unwrap();
                        if messages.is_empty() {
                            break;
                        }

                        for message in messages {
                            client.acknowledge(&message.receipt).await.unwrap();
                            received_count += 1;
                        }
                    }

                    received_count
                })
            })
            .collect();

        let receive_results = futures::future::try_join_all(receive_tasks).await.unwrap();
        total_received = receive_results.iter().sum::<u32>();

        let receive_duration = receive_start.elapsed();
        let receive_throughput = total_received as f64 / receive_duration.as_secs_f64();

        println!("Receive throughput: {:.2} messages/sec", receive_throughput);

        assert_eq!(total_received, message_count);
        assert!(send_throughput > 100.0, "Send throughput too low: {}", send_throughput);
        assert!(receive_throughput > 100.0, "Receive throughput too low: {}", receive_throughput);
    }

    #[tokio::test]
    async fn test_latency_performance() {
        let test_scenario = TestScenario::new().await;
        test_scenario.setup_queues().await;

        let message_count = 100;
        let mut latencies = Vec::new();

        for i in 0..message_count {
            let send_start = Instant::now();

            let message = TestMessage {
                content: format!("Latency test message {}", i),
            };

            // Send message
            test_scenario.queue_client.send("latency-test-queue", &message, None).await.unwrap();

            // Receive message
            let messages = test_scenario.queue_client.receive("latency-test-queue", 1).await.unwrap();
            assert_eq!(messages.len(), 1);

            // Acknowledge message
            test_scenario.queue_client.acknowledge(&messages[0].receipt).await.unwrap();

            let latency = send_start.elapsed();
            latencies.push(latency);
        }

        // Calculate statistics
        latencies.sort();
        let min_latency = latencies[0];
        let max_latency = latencies[latencies.len() - 1];
        let avg_latency = latencies.iter().sum::<Duration>() / latencies.len() as u32;
        let p50_latency = latencies[latencies.len() / 2];
        let p95_latency = latencies[(latencies.len() as f64 * 0.95) as usize];
        let p99_latency = latencies[(latencies.len() as f64 * 0.99) as usize];

        println!("Latency statistics:");
        println!("  Min: {:?}", min_latency);
        println!("  Max: {:?}", max_latency);
        println!("  Avg: {:?}", avg_latency);
        println!("  P50: {:?}", p50_latency);
        println!("  P95: {:?}", p95_latency);
        println!("  P99: {:?}", p99_latency);

        // Assert performance requirements
        assert!(avg_latency < Duration::from_millis(100), "Average latency too high: {:?}", avg_latency);
        assert!(p95_latency < Duration::from_millis(200), "P95 latency too high: {:?}", p95_latency);
    }

    #[tokio::test]
    async fn test_session_ordering_performance() {
        let test_scenario = TestScenario::new().await;
        test_scenario.setup_queues().await;

        let sessions_count = 10;
        let messages_per_session = 100;
        let total_messages = sessions_count * messages_per_session;

        let start_time = Instant::now();

        // Send messages to different sessions concurrently
        let send_tasks: Vec<_> = (0..sessions_count)
            .map(|session_id| {
                let client = test_scenario.queue_client.clone();
                tokio::spawn(async move {
                    for i in 0..messages_per_session {
                        let message = TestMessage {
                            content: format!("Session {} message {}", session_id, i),
                        };

                        client.send(
                            "session-performance-queue",
                            &message,
                            Some(&format!("session-{}", session_id))
                        ).await.unwrap();
                    }
                })
            })
            .collect();

        futures::future::try_join_all(send_tasks).await.unwrap();

        let send_duration = start_time.elapsed();

        // Process messages from each session
        let process_start = Instant::now();
        let process_tasks: Vec<_> = (0..sessions_count)
            .map(|session_id| {
                let client = test_scenario.queue_client.clone();
                tokio::spawn(async move {
                    let session_name = format!("session-{}", session_id);
                    let mut processed_count = 0;

                    loop {
                        let messages = client.receive_from_session(
                            "session-performance-queue",
                            &session_name,
                            10
                        ).await.unwrap();

                        if messages.is_empty() {
                            break;
                        }

                        for message in messages {
                            // Simulate processing
                            tokio::time::sleep(Duration::from_millis(1)).await;
                            client.acknowledge(&message.receipt).await.unwrap();
                            processed_count += 1;
                        }
                    }

                    processed_count
                })
            })
            .collect();

        let process_results = futures::future::try_join_all(process_tasks).await.unwrap();
        let total_processed: u32 = process_results.iter().sum();

        let process_duration = process_start.elapsed();

        println!("Session ordering performance:");
        println!("  Total messages: {}", total_messages);
        println!("  Send duration: {:?}", send_duration);
        println!("  Process duration: {:?}", process_duration);
        println!("  Send throughput: {:.2} msgs/sec", total_messages as f64 / send_duration.as_secs_f64());
        println!("  Process throughput: {:.2} msgs/sec", total_processed as f64 / process_duration.as_secs_f64());

        assert_eq!(total_processed, total_messages);
    }
}
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Queue Runtime Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      localstack:
        image: localstack/localstack:latest
        ports:
          - 4566:4566
        env:
          SERVICES: sqs
          DEFAULT_REGION: us-east-1

      azurite:
        image: mcr.microsoft.com/azure-storage/azurite:latest
        ports:
          - 10000:10000
          - 10001:10001
          - 10002:10002

    steps:
    - uses: actions/checkout@v3

    - name: Install Rust
      uses: dtolnay/rust-toolchain@stable
      with:
        components: clippy, rustfmt

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: |
          ~/.cargo/registry
          ~/.cargo/git
          target/
        key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

    - name: Check formatting
      run: cargo fmt -- --check

    - name: Run clippy
      run: cargo clippy -- -D warnings

    - name: Run unit tests
      run: cargo test --lib

    - name: Run integration tests
      run: cargo test --test integration
      env:
        AWS_ENDPOINT_URL: http://localhost:4566
        AWS_ACCESS_KEY_ID: test
        AWS_SECRET_ACCESS_KEY: test
        AWS_DEFAULT_REGION: us-east-1
        AZURE_STORAGE_CONNECTION_STRING: DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://localhost:10000/devstoreaccount1;

    - name: Run performance tests
      run: cargo test --test performance --release

    - name: Generate coverage report
      run: |
        cargo install cargo-tarpaulin
        cargo tarpaulin --out xml

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./cobertura.xml
        fail_ci_if_error: true
```

## Best Practices

1. **Test Pyramid**: Focus on unit tests, supplement with integration and e2e tests
2. **Provider Agnostic**: Test against multiple queue providers to ensure compatibility
3. **Failure Scenarios**: Test error conditions, timeouts, and edge cases
4. **Performance Validation**: Include throughput and latency benchmarks
5. **Test Data Management**: Use builders and factories for consistent test data
6. **Isolation**: Ensure tests don't interfere with each other
7. **Continuous Testing**: Run tests in CI/CD pipeline with real services
8. **Monitoring Tests**: Include tests for observability and alerting features
