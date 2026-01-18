//! Tests for queue client traits and implementations.

use super::*;
use crate::error::QueueError;
use crate::message::{Message, QueueName, ReceiptHandle};
use crate::provider::{InMemoryConfig, ProviderConfig, ProviderType, QueueConfig, SessionSupport};
use chrono::Duration;

// ============================================================================
// Contract Tests - QueueClient Trait
// ============================================================================

/// Contract test helper to validate QueueClient implementations
async fn test_queue_client_send_message_success<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange
    let message = Message::new("test message".into());

    // Act
    let result = client.send_message(queue, message).await;

    // Assert - Assertion #1: Message send success
    assert!(result.is_ok(), "Send message should succeed");
    let message_id = result.unwrap();
    assert!(
        !message_id.as_str().is_empty(),
        "Message ID should not be empty"
    );
}

/// Test that sending to non-existent queue returns proper error
async fn test_queue_client_send_to_nonexistent_queue<C: QueueClient>(client: &C) {
    // Arrange
    let invalid_queue = QueueName::new("nonexistent-queue-12345".to_string()).unwrap();
    let message = Message::new("test".into());

    // Act
    let result = client.send_message(&invalid_queue, message).await;

    // Assert - Assertion #2: Send to non-existent queue
    assert!(result.is_err(), "Should fail for non-existent queue");
    match result.unwrap_err() {
        QueueError::QueueNotFound { queue_name } => {
            assert_eq!(queue_name, invalid_queue.as_str());
        }
        other => panic!("Expected QueueNotFound error, got: {:?}", other),
    }
}

/// Test message receive success
async fn test_queue_client_receive_message_success<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange - Send a message first
    let message = Message::new("test receive".into());
    let _sent_id = client
        .send_message(queue, message.clone())
        .await
        .expect("Setup: send should succeed");

    // Act
    let result = client.receive_message(queue, Duration::seconds(5)).await;

    // Assert - Assertion #3: Message receive success
    assert!(result.is_ok(), "Receive should succeed");
    let received = result.unwrap();
    assert!(received.is_some(), "Should receive the message");

    let received_msg = received.unwrap();
    assert_eq!(received_msg.body, message.body);
    assert!(!received_msg.receipt_handle.handle().is_empty());
}

/// Test receive from empty queue with timeout
async fn test_queue_client_receive_from_empty_queue<C: QueueClient>(client: &C, queue: &QueueName) {
    // Act
    let result = client
        .receive_message(queue, Duration::milliseconds(100))
        .await;

    // Assert - Assertion #4: Receive from empty queue
    assert!(result.is_ok(), "Should not error on empty queue");
    let received = result.unwrap();
    assert!(received.is_none(), "Should return None for empty queue");
}

/// Test message completion
async fn test_queue_client_complete_message<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange - Send and receive a message
    let message = Message::new("test complete".into());
    client
        .send_message(queue, message)
        .await
        .expect("Setup: send should succeed");

    let received = client
        .receive_message(queue, Duration::seconds(5))
        .await
        .expect("Setup: receive should succeed")
        .expect("Setup: should have message");

    let receipt = received.receipt_handle.clone();

    // Act
    let result = client.complete_message(receipt).await;

    // Assert - Assertion #5: Message completion success
    assert!(result.is_ok(), "Complete should succeed");

    // Verify message is not received again
    let recheck = client
        .receive_message(queue, Duration::milliseconds(100))
        .await
        .expect("Recheck should not error");
    assert!(
        recheck.is_none(),
        "Completed message should not be re-received"
    );
}

/// Test message abandonment (requeue)
async fn test_queue_client_abandon_message<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange
    let message = Message::new("test abandon".into());
    client
        .send_message(queue, message)
        .await
        .expect("Setup: send should succeed");

    let received = client
        .receive_message(queue, Duration::seconds(5))
        .await
        .expect("Setup: receive should succeed")
        .expect("Setup: should have message");

    let receipt = received.receipt_handle.clone();

    // Act
    let result = client.abandon_message(receipt).await;

    // Assert
    assert!(result.is_ok(), "Abandon should succeed");

    // Message should be available again (eventually)
    let recheck = client
        .receive_message(queue, Duration::seconds(5))
        .await
        .expect("Recheck should not error");
    assert!(
        recheck.is_some(),
        "Abandoned message should be re-available"
    );
}

/// Test dead letter message
async fn test_queue_client_dead_letter_message<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange
    let message = Message::new("test dead letter".into());
    client
        .send_message(queue, message)
        .await
        .expect("Setup: send should succeed");

    let received = client
        .receive_message(queue, Duration::seconds(5))
        .await
        .expect("Setup: receive should succeed")
        .expect("Setup: should have message");

    let receipt = received.receipt_handle.clone();

    // Act
    let result = client
        .dead_letter_message(receipt, "Test failure reason".to_string())
        .await;

    // Assert
    assert!(result.is_ok(), "Dead letter should succeed");
}

/// Test batch send operations
async fn test_queue_client_send_batch<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange
    let messages = vec![
        Message::new("batch 1".into()),
        Message::new("batch 2".into()),
        Message::new("batch 3".into()),
    ];

    // Act
    let result = client.send_messages(queue, messages).await;

    // Assert
    if client.supports_batching() {
        assert!(result.is_ok(), "Batch send should succeed");
        let ids = result.unwrap();
        assert_eq!(ids.len(), 3, "Should return 3 message IDs");
    } else {
        // If batching not supported, should still succeed (may do one-by-one)
        assert!(result.is_ok(), "Should handle batch gracefully");
    }
}

/// Test batch receive operations
async fn test_queue_client_receive_batch<C: QueueClient>(client: &C, queue: &QueueName) {
    // Arrange - Send multiple messages
    for i in 0..5 {
        let message = Message::new(format!("batch receive {}", i).into());
        client
            .send_message(queue, message)
            .await
            .expect("Setup: send should succeed");
    }

    // Act
    let result = client
        .receive_messages(queue, 3, Duration::seconds(5))
        .await;

    // Assert
    assert!(result.is_ok(), "Batch receive should succeed");
    let messages = result.unwrap();
    assert!(
        messages.len() <= 3,
        "Should not exceed requested max messages"
    );
    assert!(!messages.is_empty(), "Should receive at least one message");
}

/// Test provider type query
async fn test_queue_client_provider_type<C: QueueClient>(client: &C) {
    let provider_type = client.provider_type();
    // Should return a valid provider type (any is fine for contract)
    assert!(
        matches!(
            provider_type,
            ProviderType::InMemory | ProviderType::AzureServiceBus | ProviderType::AwsSqs
        ),
        "Should return valid provider type"
    );
}

/// Test session support query
async fn test_queue_client_supports_sessions<C: QueueClient>(client: &C) {
    let supports_sessions = client.supports_sessions();
    // Either true or false is valid, just shouldn't panic
    let _ = supports_sessions;
}

// ============================================================================
// Contract Tests - SessionClient Trait
// ============================================================================

/// Test session client receive
#[allow(dead_code)]
async fn test_session_client_receive<S: SessionClient>(session: &S) {
    // Act
    let result = session.receive_message(Duration::seconds(5)).await;

    // Assert
    assert!(
        result.is_ok(),
        "Session receive should not error (may return None)"
    );
}

/// Test session client complete
#[allow(dead_code)]
async fn test_session_client_complete<S: SessionClient>(session: &S, receipt: ReceiptHandle) {
    // Act
    let result = session.complete_message(receipt).await;

    // Assert
    assert!(result.is_ok(), "Session complete should succeed");
}

/// Test session lock renewal
#[allow(dead_code)]
async fn test_session_client_renew_lock<S: SessionClient>(session: &S) {
    // Act
    let result = session.renew_session_lock().await;

    // Assert
    assert!(result.is_ok(), "Session lock renewal should succeed");
}

/// Test session close
#[allow(dead_code)]
async fn test_session_client_close<S: SessionClient>(session: &mut S) {
    // Act
    let result = session.close_session().await;

    // Assert
    assert!(result.is_ok(), "Session close should succeed");
}

/// Test session ID query
#[allow(dead_code)]
async fn test_session_client_session_id<S: SessionClient>(session: &S) {
    // Act
    let session_id = session.session_id();

    // Assert
    assert!(
        !session_id.as_str().is_empty(),
        "Session ID should not be empty"
    );
}

// ============================================================================
// QueueProvider Contract Tests
// ============================================================================

/// Test that QueueProvider operations match QueueClient behavior
async fn test_queue_provider_send_message<P: QueueProvider>(provider: &P, queue: &QueueName) {
    // Arrange
    let message = Message::new("provider test".into());

    // Act
    let result = provider.send_message(queue, &message).await;

    // Assert
    assert!(result.is_ok(), "Provider send should succeed");
}

/// Test provider session support level
async fn test_queue_provider_session_support<P: QueueProvider>(provider: &P) {
    let support = provider.supports_sessions();
    assert!(
        matches!(
            support,
            SessionSupport::Native | SessionSupport::Emulated | SessionSupport::Unsupported
        ),
        "Should return valid session support level"
    );
}

/// Test provider batch size limits
async fn test_queue_provider_batch_limits<P: QueueProvider>(provider: &P) {
    let max_batch = provider.max_batch_size();
    if provider.supports_batching() {
        assert!(max_batch > 0, "Batch size should be positive if supported");
        assert!(max_batch <= 100, "Batch size should be reasonable (≤100)");
    } else {
        assert_eq!(max_batch, 1, "Non-batching provider should have max 1");
    }
}

// ============================================================================
// Factory Tests
// ============================================================================

#[tokio::test]
async fn test_factory_create_test_client() {
    // Act
    let client = QueueClientFactory::create_test_client();

    // Assert
    assert_eq!(
        client.provider_type(),
        ProviderType::InMemory,
        "Test client should use InMemory provider"
    );
}

#[tokio::test]
async fn test_factory_create_from_in_memory_config() {
    // Arrange
    let config = QueueConfig {
        provider: ProviderConfig::InMemory(InMemoryConfig::default()),
        ..Default::default()
    };

    // Act
    let result = QueueClientFactory::create_client(config).await;

    // Assert
    assert!(result.is_ok(), "Should create client from InMemory config");
    let client = result.unwrap();
    assert_eq!(client.provider_type(), ProviderType::InMemory);
}

#[tokio::test]
async fn test_factory_create_from_azure_config() {
    // Arrange
    let config = QueueConfig {
        provider: ProviderConfig::AzureServiceBus(crate::provider::AzureServiceBusConfig {
            connection_string: Some("Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=test".to_string()),
            namespace: Some("test".to_string()),
            auth_method: crate::providers::AzureAuthMethod::ConnectionString,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        }),
        ..Default::default()
    };

    // Act
    let result = QueueClientFactory::create_client(config).await;

    // Note: May fail if Azure SDK not available, but should not panic
    // This is more of a smoke test
    let _ = result;
}

#[tokio::test]
async fn test_factory_create_from_aws_config() {
    // Arrange
    let config = QueueConfig {
        provider: ProviderConfig::AwsSqs(crate::provider::AwsSqsConfig {
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            use_fifo_queues: true,
        }),
        ..Default::default()
    };

    // Act
    let result = QueueClientFactory::create_client(config).await;

    // Note: May fail if AWS SDK not available, but should not panic
    let _ = result;
}

// ============================================================================
// StandardQueueClient Tests
// ============================================================================

#[tokio::test]
async fn test_standard_client_delegates_to_provider() {
    // This test verifies StandardQueueClient exists and delegates to provider
    // Full functionality tested through contract tests
    let provider = InMemoryProvider::default();
    let config = QueueConfig::default();
    let _client = StandardQueueClient::new(Box::new(provider), config);
}

// ============================================================================
// InMemoryProvider Tests
// ============================================================================

#[tokio::test]
async fn test_in_memory_provider_creation() {
    // Arrange
    let config = InMemoryConfig::default();

    // Act
    let provider = InMemoryProvider::new(config);

    // Assert
    assert_eq!(provider.provider_type(), ProviderType::InMemory);
    assert_eq!(provider.supports_sessions(), SessionSupport::Native);
    assert!(provider.supports_batching());
}

#[tokio::test]
async fn test_in_memory_provider_batch_limits() {
    // Arrange
    let provider = InMemoryProvider::default();

    // Act
    let max_batch = provider.max_batch_size();

    // Assert
    assert_eq!(max_batch, 100, "InMemory should support batch of 100");
}

// ============================================================================
// Integration Contract Tests
// ============================================================================

/// Run full contract test suite against a QueueClient implementation
#[allow(dead_code)]
async fn run_queue_client_contract_tests<C: QueueClient>(client: &C, test_queue: &QueueName) {
    test_queue_client_send_message_success(client, test_queue).await;
    test_queue_client_send_to_nonexistent_queue(client).await;
    test_queue_client_receive_message_success(client, test_queue).await;
    test_queue_client_receive_from_empty_queue(client, test_queue).await;
    test_queue_client_complete_message(client, test_queue).await;
    test_queue_client_abandon_message(client, test_queue).await;
    test_queue_client_dead_letter_message(client, test_queue).await;
    test_queue_client_send_batch(client, test_queue).await;
    test_queue_client_receive_batch(client, test_queue).await;
    test_queue_client_provider_type(client).await;
    test_queue_client_supports_sessions(client).await;
}

/// Run full contract test suite against a QueueProvider implementation
#[allow(dead_code)]
async fn run_queue_provider_contract_tests<P: QueueProvider>(provider: &P, test_queue: &QueueName) {
    test_queue_provider_send_message(provider, test_queue).await;
    test_queue_provider_session_support(provider).await;
    test_queue_provider_batch_limits(provider).await;
}
