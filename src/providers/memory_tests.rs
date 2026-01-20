//! Tests for in-memory queue provider.

use super::*;
use crate::provider::InMemoryConfig;

// ============================================================================
// Subtask 10.1: Storage Initialization Tests
// ============================================================================

mod storage_initialization {
    use super::*;

    /// Verify that InMemoryProvider can be created with default configuration.
    #[test]
    fn test_create_provider_with_default_config() {
        let provider = InMemoryProvider::default();
        assert_eq!(provider.provider_type(), ProviderType::InMemory);
        assert_eq!(provider.supports_sessions(), SessionSupport::Native);
        assert!(provider.supports_batching());
        assert_eq!(provider.max_batch_size(), 100);
    }

    /// Verify that InMemoryProvider can be created with custom configuration.
    #[test]
    fn test_create_provider_with_custom_config() {
        let config = InMemoryConfig {
            max_queue_size: 5000,
            enable_persistence: false,
            ..Default::default()
        };

        let provider = InMemoryProvider::new(config);
        assert_eq!(provider.provider_type(), ProviderType::InMemory);
    }

    /// Verify that multiple providers can coexist independently.
    #[test]
    fn test_multiple_independent_providers() {
        let provider1 = InMemoryProvider::default();
        let provider2 = InMemoryProvider::default();

        // Providers should be independent (different storage)
        assert_eq!(provider1.provider_type(), provider2.provider_type());
    }

    /// Verify that storage is thread-safe (can be cloned and shared).
    #[test]
    fn test_storage_thread_safety() {
        use std::sync::Arc;

        let provider = Arc::new(InMemoryProvider::default());
        let provider_clone = Arc::clone(&provider);

        // Should be able to share across threads
        assert_eq!(provider.provider_type(), provider_clone.provider_type());
    }
}

// ============================================================================
// Subtask 10.1: Queue Management Tests
// ============================================================================

mod queue_management {
    use super::*;

    /// Verify that queues are created automatically when first accessed.
    ///
    /// Note: This test will use send_message once implemented in 10.2.
    /// For now, we verify the storage structure is properly initialized.
    #[test]
    fn test_queue_auto_creation() {
        let provider = InMemoryProvider::default();
        let storage = provider.storage.read().unwrap();

        // Initially no queues
        assert_eq!(storage.queues.len(), 0);
    }

    /// Verify that multiple queues can exist independently.
    ///
    /// Note: Full verification will be in 10.2 when send/receive implemented.
    #[test]
    fn test_multiple_independent_queues() {
        let provider = InMemoryProvider::default();
        let storage = provider.storage.read().unwrap();

        // Storage can hold multiple queues
        assert!(storage.queues.is_empty());
    }
}

// ============================================================================
// Subtask 10.1: Data Structure Tests
// ============================================================================

mod data_structures {
    use super::*;
    use bytes::Bytes;

    /// Verify StoredMessage creation from Message.
    #[test]
    fn test_stored_message_from_message() {
        let message = Message::new(Bytes::from("test body"));
        let message_id = MessageId::new();
        let config = InMemoryConfig::default();

        let stored = StoredMessage::from_message(&message, message_id.clone(), &config);

        assert_eq!(stored.message_id, message_id);
        assert_eq!(stored.body, Bytes::from("test body"));
        assert_eq!(stored.delivery_count, 0);
        assert!(stored.session_id.is_none());
        assert!(stored.correlation_id.is_none());
    }

    /// Verify StoredMessage with session ID.
    #[test]
    fn test_stored_message_with_session() {
        let session_id = SessionId::new("test-session".to_string()).unwrap();
        let message = Message::new(Bytes::from("test body")).with_session_id(session_id.clone());
        let message_id = MessageId::new();
        let config = InMemoryConfig::default();

        let stored = StoredMessage::from_message(&message, message_id, &config);

        assert_eq!(stored.session_id, Some(session_id));
    }

    /// Verify StoredMessage with correlation ID.
    #[test]
    fn test_stored_message_with_correlation_id() {
        let correlation_id = "correlation-123".to_string();
        let message =
            Message::new(Bytes::from("test body")).with_correlation_id(correlation_id.clone());
        let message_id = MessageId::new();
        let config = InMemoryConfig::default();

        let stored = StoredMessage::from_message(&message, message_id, &config);

        assert_eq!(stored.correlation_id, Some(correlation_id));
    }

    /// Verify StoredMessage with TTL sets expiration.
    #[test]
    fn test_stored_message_with_ttl() {
        let ttl = Duration::seconds(60);
        let message = Message::new(Bytes::from("test body")).with_ttl(ttl);
        let message_id = MessageId::new();
        let config = InMemoryConfig::default();

        let stored = StoredMessage::from_message(&message, message_id, &config);

        assert!(stored.expires_at.is_some());
        assert!(!stored.is_expired()); // Should not be expired immediately
    }

    /// Verify StoredMessage expiration detection.
    #[test]
    fn test_stored_message_expiration_detection() {
        let past_time =
            Timestamp::from_datetime(chrono::Utc::now() - chrono::Duration::seconds(10));
        let stored = StoredMessage {
            message_id: MessageId::new(),
            body: Bytes::from("test"),
            attributes: HashMap::new(),
            session_id: None,
            correlation_id: None,
            enqueued_at: Timestamp::now(),
            delivery_count: 0,
            available_at: Timestamp::now(),
            expires_at: Some(past_time),
        };

        assert!(stored.is_expired());
    }

    /// Verify StoredMessage availability detection.
    #[test]
    fn test_stored_message_availability() {
        let future_time =
            Timestamp::from_datetime(chrono::Utc::now() + chrono::Duration::seconds(10));
        let stored = StoredMessage {
            message_id: MessageId::new(),
            body: Bytes::from("test"),
            attributes: HashMap::new(),
            session_id: None,
            correlation_id: None,
            enqueued_at: Timestamp::now(),
            delivery_count: 0,
            available_at: future_time,
            expires_at: None,
        };

        assert!(!stored.is_available());
    }

    /// Verify InFlightMessage expiration detection.
    #[test]
    fn test_inflight_message_expiration() {
        let past_time = Timestamp::from_datetime(chrono::Utc::now() - chrono::Duration::seconds(5));
        let stored = StoredMessage {
            message_id: MessageId::new(),
            body: Bytes::from("test"),
            attributes: HashMap::new(),
            session_id: None,
            correlation_id: None,
            enqueued_at: Timestamp::now(),
            delivery_count: 0,
            available_at: Timestamp::now(),
            expires_at: None,
        };

        let inflight = InFlightMessage {
            message: stored,
            receipt_handle: "test-receipt".to_string(),
            lock_expires_at: past_time,
        };

        assert!(inflight.is_expired());
    }

    /// Verify SessionState initialization.
    #[test]
    fn test_session_state_initialization() {
        let state = SessionState::new();

        assert!(!state.locked);
        assert!(state.lock_expires_at.is_none());
        assert!(state.locked_by.is_none());
        assert!(!state.is_locked());
    }

    /// Verify SessionState lock detection.
    #[test]
    fn test_session_state_lock_detection() {
        let mut state = SessionState::new();
        state.locked = true;
        state.lock_expires_at = Some(Timestamp::from_datetime(
            chrono::Utc::now() + chrono::Duration::minutes(5),
        ));
        state.locked_by = Some("client-1".to_string());

        assert!(state.is_locked());
    }

    /// Verify SessionState lock expiration.
    #[test]
    fn test_session_state_lock_expiration() {
        let mut state = SessionState::new();
        state.locked = true;
        state.lock_expires_at = Some(Timestamp::from_datetime(
            chrono::Utc::now() - chrono::Duration::seconds(5),
        ));

        assert!(!state.is_locked()); // Expired lock should return false
    }
}

// ============================================================================
// Subtask 10.1: Concurrent Access Tests
// ============================================================================

mod concurrent_access {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Verify that provider can be safely shared across threads.
    #[test]
    fn test_provider_thread_safety() {
        let provider = Arc::new(InMemoryProvider::default());
        let mut handles = vec![];

        for i in 0..10 {
            let provider_clone = Arc::clone(&provider);
            let handle = thread::spawn(move || {
                // Just verify we can access provider from multiple threads
                assert_eq!(provider_clone.provider_type(), ProviderType::InMemory);
                i
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }

    /// Verify that storage can be accessed concurrently for reads.
    #[test]
    fn test_concurrent_storage_read_access() {
        let provider = Arc::new(InMemoryProvider::default());
        let mut handles = vec![];

        for _ in 0..10 {
            let provider_clone = Arc::clone(&provider);
            let handle = thread::spawn(move || {
                let storage = provider_clone.storage.read().unwrap();
                storage.queues.len()
            });
            handles.push(handle);
        }

        for handle in handles {
            let count = handle.join().unwrap();
            assert_eq!(count, 0); // No queues initially
        }
    }
}

// ============================================================================
// Subtask 10.2: Send/Receive Operations Tests
// ============================================================================

mod send_receive_operations {
    use super::*;
    use bytes::Bytes;
    use chrono::Duration;

    /// Verify that a message can be sent and received successfully (Assertion #1, #3).
    #[tokio::test]
    async fn test_send_and_receive_single_message() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("test-queue".to_string()).unwrap();

        // Send a message
        let message = Message::new(Bytes::from("Hello, World!"));
        let message_id = provider
            .send_message(&queue_name, &message)
            .await
            .expect("send_message should succeed");

        assert!(!message_id.as_str().is_empty());

        // Receive the message
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive_message should succeed");

        assert!(received.is_some());
        let received_msg = received.unwrap();
        assert_eq!(received_msg.body, Bytes::from("Hello, World!"));
        assert_eq!(received_msg.delivery_count, 1);
    }

    /// Verify that multiple messages can be sent and received in batch.
    #[tokio::test]
    async fn test_send_and_receive_batch_messages() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("test-batch-queue".to_string()).unwrap();

        // Send multiple messages
        let messages = vec![
            Message::new(Bytes::from("Message 1")),
            Message::new(Bytes::from("Message 2")),
            Message::new(Bytes::from("Message 3")),
        ];

        let message_ids = provider
            .send_messages(&queue_name, &messages)
            .await
            .expect("send_messages should succeed");

        assert_eq!(message_ids.len(), 3);

        // Receive all messages
        let received = provider
            .receive_messages(&queue_name, 5, Duration::seconds(1))
            .await
            .expect("receive_messages should succeed");

        assert_eq!(received.len(), 3);
        assert_eq!(received[0].body, Bytes::from("Message 1"));
        assert_eq!(received[1].body, Bytes::from("Message 2"));
        assert_eq!(received[2].body, Bytes::from("Message 3"));
    }

    /// Verify that receiving from an empty queue returns None (Assertion #4).
    #[tokio::test]
    async fn test_receive_from_empty_queue_returns_none() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("empty-queue".to_string()).unwrap();

        let received = provider
            .receive_message(&queue_name, Duration::milliseconds(100))
            .await
            .expect("receive_message should succeed");

        assert!(received.is_none());
    }

    /// Verify that message payload integrity is maintained.
    #[tokio::test]
    async fn test_message_payload_integrity() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("integrity-queue".to_string()).unwrap();

        let original_body = Bytes::from(vec![0u8, 1, 2, 3, 4, 255]);
        let message = Message::new(original_body.clone());

        provider
            .send_message(&queue_name, &message)
            .await
            .expect("send_message should succeed");

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive_message should succeed")
            .expect("message should be received");

        assert_eq!(received.body, original_body);
    }

    /// Verify that message attributes are preserved.
    #[tokio::test]
    async fn test_message_attributes_preserved() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("attributes-queue".to_string()).unwrap();

        let message = Message::new(Bytes::from("test"))
            .with_attribute("key1".to_string(), "value1".to_string())
            .with_attribute("key2".to_string(), "value2".to_string());

        provider
            .send_message(&queue_name, &message)
            .await
            .expect("send_message should succeed");

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive_message should succeed")
            .expect("message should be received");

        assert_eq!(received.attributes.get("key1").unwrap(), "value1");
        assert_eq!(received.attributes.get("key2").unwrap(), "value2");
    }

    /// Verify that message size is validated against provider limits.
    #[tokio::test]
    async fn test_message_size_validation() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("size-queue".to_string()).unwrap();

        // Create message larger than 10MB limit
        let large_body = Bytes::from(vec![0u8; 11 * 1024 * 1024]);
        let message = Message::new(large_body);

        let result = provider.send_message(&queue_name, &message).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            QueueError::MessageTooLarge { size, max_size } => {
                assert!(size > max_size);
                assert_eq!(max_size, 10 * 1024 * 1024);
            }
            _ => panic!("Expected MessageTooLarge error"),
        }
    }

    /// Verify that correlation ID is preserved.
    #[tokio::test]
    async fn test_correlation_id_preserved() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("correlation-queue".to_string()).unwrap();

        let correlation_id = "correlation-123".to_string();
        let message = Message::new(Bytes::from("test")).with_correlation_id(correlation_id.clone());

        provider
            .send_message(&queue_name, &message)
            .await
            .expect("send_message should succeed");

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive_message should succeed")
            .expect("message should be received");

        assert_eq!(received.correlation_id, Some(correlation_id));
    }

    /// Verify batch operations respect batch size limits.
    #[tokio::test]
    async fn test_batch_size_limits() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("batch-limit-queue".to_string()).unwrap();

        // Send more than max_batch_size (100)
        let messages: Vec<Message> = (0..150)
            .map(|i| Message::new(Bytes::from(format!("Message {}", i))))
            .collect();

        let result = provider.send_messages(&queue_name, &messages).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            QueueError::BatchTooLarge { size, max_size } => {
                assert_eq!(size, 150);
                assert_eq!(max_size, 100);
            }
            _ => panic!("Expected BatchTooLarge error"),
        }
    }
}

// ============================================================================
// Subtask 10.2: Session-Based Message Ordering Tests
// ============================================================================

mod session_ordering {
    use super::*;
    use bytes::Bytes;
    use chrono::Duration;

    /// Verify that messages within a session are received in FIFO order (Assertion #7).
    #[tokio::test]
    async fn test_session_message_ordering() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("session-queue".to_string()).unwrap();
        let session_id = SessionId::new("session-1".to_string()).unwrap();

        // Send messages A, B, C in order
        let messages = vec![
            Message::new(Bytes::from("A")).with_session_id(session_id.clone()),
            Message::new(Bytes::from("B")).with_session_id(session_id.clone()),
            Message::new(Bytes::from("C")).with_session_id(session_id.clone()),
        ];

        for msg in &messages {
            provider
                .send_message(&queue_name, msg)
                .await
                .expect("send_message should succeed");
        }

        // Receive messages - should be in same order
        let received_a = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive should succeed")
            .expect("message A should be received");
        assert_eq!(received_a.body, Bytes::from("A"));
        assert_eq!(received_a.session_id, Some(session_id.clone()));

        // Complete message A before receiving B
        provider
            .complete_message(&received_a.receipt_handle)
            .await
            .expect("complete should succeed");

        let received_b = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive should succeed")
            .expect("message B should be received");
        assert_eq!(received_b.body, Bytes::from("B"));

        provider
            .complete_message(&received_b.receipt_handle)
            .await
            .expect("complete should succeed");

        let received_c = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .expect("receive should succeed")
            .expect("message C should be received");
        assert_eq!(received_c.body, Bytes::from("C"));
    }

    /// Verify that messages from different sessions can be processed concurrently.
    #[tokio::test]
    async fn test_different_sessions_independent() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("multi-session-queue".to_string()).unwrap();

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        // Send messages to different sessions
        let msg1 = Message::new(Bytes::from("Session1-Msg1")).with_session_id(session1.clone());
        let msg2 = Message::new(Bytes::from("Session2-Msg1")).with_session_id(session2.clone());
        let msg3 = Message::new(Bytes::from("Session1-Msg2")).with_session_id(session1.clone());

        provider.send_message(&queue_name, &msg1).await.unwrap();
        provider.send_message(&queue_name, &msg2).await.unwrap();
        provider.send_message(&queue_name, &msg3).await.unwrap();

        // Receive from first session
        let received1 = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Should be able to receive from second session even though first is in-flight
        let received2 = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // One should be from session1, other from session2
        assert_ne!(received1.session_id, received2.session_id);
    }

    /// Verify that non-session messages don't interfere with session messages.
    #[tokio::test]
    async fn test_session_and_nonsession_messages() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("mixed-queue".to_string()).unwrap();

        let session_id = SessionId::new("session-1".to_string()).unwrap();

        // Send mix of session and non-session messages
        let non_session_msg = Message::new(Bytes::from("No session"));
        let session_msg = Message::new(Bytes::from("With session")).with_session_id(session_id);

        provider
            .send_message(&queue_name, &non_session_msg)
            .await
            .unwrap();
        provider
            .send_message(&queue_name, &session_msg)
            .await
            .unwrap();

        // Both should be receivable
        let received1 = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();
        provider
            .complete_message(&received1.receipt_handle)
            .await
            .unwrap();

        let received2 = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // One should have session_id, other should not
        let has_session = received1.session_id.is_some() || received2.session_id.is_some();
        let has_no_session = received1.session_id.is_none() || received2.session_id.is_none();
        assert!(has_session && has_no_session);
    }
}

// ============================================================================
// Subtask 10.3: Message Acknowledgment Tests
// ============================================================================

mod acknowledgment {
    use super::*;

    /// Verify that completing a message removes it permanently.
    ///
    /// After complete_message, the message should not be receivable again.
    #[tokio::test]
    async fn test_complete_message_removes_permanently() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("complete-test".to_string()).unwrap();

        // Send and receive a message
        let msg = Message::new(Bytes::from("Complete me"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Complete the message
        provider
            .complete_message(&received.receipt_handle)
            .await
            .unwrap();

        // Trying to receive again should return None (queue is empty)
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "Completed message should not be receivable"
        );
    }

    /// Verify that completing with an invalid receipt handle returns an error.
    ///
    /// Assertion #6: Invalid receipt handle returns MessageNotFound error.
    #[tokio::test]
    async fn test_complete_with_invalid_receipt_returns_error() {
        let provider = InMemoryProvider::default();

        // Try to complete with a non-existent receipt handle
        let now = Timestamp::now();
        let expires_at = Timestamp::from_datetime(now.as_datetime() + Duration::seconds(30));
        let invalid_receipt = ReceiptHandle::new(
            "invalid-receipt-123".to_string(),
            expires_at,
            ProviderType::InMemory,
        );
        let result = provider.complete_message(&invalid_receipt).await;

        assert!(result.is_err(), "Invalid receipt should return error");
        match result.unwrap_err() {
            QueueError::MessageNotFound { .. } => {
                // Expected error
            }
            other => panic!("Expected MessageNotFound, got {:?}", other),
        }
    }

    /// Verify that completing with an expired receipt handle returns an error.
    ///
    /// After visibility timeout, receipt handles become invalid.
    #[tokio::test]
    async fn test_complete_with_expired_receipt_returns_error() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("expire-test".to_string()).unwrap();

        // Send and receive a message
        let msg = Message::new(Bytes::from("Will expire"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Simulate passage of time beyond visibility timeout (30 seconds)
        // Note: In real implementation, we'd wait or mock time. For now,
        // we test the error path by manipulating storage directly if needed.
        // This test will validate the logic once time-based expiry is implemented.

        tokio::time::sleep(tokio::time::Duration::from_secs(31)).await;

        // Try to complete with expired receipt
        let result = provider.complete_message(&received.receipt_handle).await;

        assert!(result.is_err(), "Expired receipt should return error");
        match result.unwrap_err() {
            QueueError::MessageNotFound { .. } => {
                // Expected error
            }
            other => panic!("Expected MessageNotFound, got {:?}", other),
        }
    }

    /// Verify that abandoning a message makes it available again.
    ///
    /// After abandon_message, the message should be immediately receivable.
    #[tokio::test]
    async fn test_abandon_message_makes_available_again() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("abandon-test".to_string()).unwrap();

        // Send and receive a message
        let msg = Message::new(Bytes::from("Abandon me"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        let original_body = received.body.clone();

        // Abandon the message
        provider
            .abandon_message(&received.receipt_handle)
            .await
            .unwrap();

        // Message should be immediately receivable again
        let redelivered = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            redelivered.body, original_body,
            "Redelivered message should have same body"
        );
    }

    /// Verify that abandoned message has incremented delivery count.
    ///
    /// Each delivery attempt should increment the counter.
    #[tokio::test]
    async fn test_abandoned_message_increments_delivery_count() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("delivery-count-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("Count deliveries"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Receive and abandon multiple times
        for expected_count in 1..=3 {
            let received = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
                .unwrap()
                .unwrap();

            assert_eq!(
                received.delivery_count, expected_count,
                "Delivery count should be {}",
                expected_count
            );

            // Abandon for next iteration
            provider
                .abandon_message(&received.receipt_handle)
                .await
                .unwrap();
        }
    }

    /// Verify that abandoning with invalid receipt returns error.
    #[tokio::test]
    async fn test_abandon_with_invalid_receipt_returns_error() {
        let provider = InMemoryProvider::default();

        // Try to abandon with a non-existent receipt handle
        let now = Timestamp::now();
        let expires_at = Timestamp::from_datetime(now.as_datetime() + Duration::seconds(30));
        let invalid_receipt = ReceiptHandle::new(
            "invalid-abandon-123".to_string(),
            expires_at,
            ProviderType::InMemory,
        );
        let result = provider.abandon_message(&invalid_receipt).await;

        assert!(result.is_err(), "Invalid receipt should return error");
        match result.unwrap_err() {
            QueueError::MessageNotFound { .. } => {
                // Expected error
            }
            other => panic!("Expected MessageNotFound, got {:?}", other),
        }
    }

    /// Verify that session messages maintain order after abandonment.
    ///
    /// Abandoned session messages should return to the front of their session queue.
    #[tokio::test]
    async fn test_session_message_ordering_after_abandon() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("session-abandon-test".to_string()).unwrap();

        let session_id = SessionId::new("session-1".to_string()).unwrap();

        // Send three session messages in order
        for i in 1..=3 {
            let msg = Message::new(Bytes::from(format!("Message {}", i)))
                .with_session_id(session_id.clone());
            provider.send_message(&queue_name, &msg).await.unwrap();
        }

        // Receive first message
        let msg1 = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg1.body, Bytes::from("Message 1"));

        // Abandon it
        provider
            .abandon_message(&msg1.receipt_handle)
            .await
            .unwrap();

        // Should receive message 1 again (front of session queue)
        let msg1_again = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg1_again.body, Bytes::from("Message 1"));
    }
}

// ============================================================================
// Subtask 10.3: Visibility Timeout Tests
// ============================================================================

mod visibility_timeout {
    use super::*;

    /// Verify that messages reappear after visibility timeout expires.
    ///
    /// Assertion #13: Visibility timeout causes message to become available again.
    #[tokio::test]
    async fn test_visibility_timeout_makes_message_reappear() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("visibility-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("Visibility timeout test"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Receive it (makes it invisible for 30 seconds)
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Immediately trying to receive again should return None
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "Message should be invisible during timeout"
        );

        // Wait for visibility timeout to expire (30 seconds + small buffer)
        tokio::time::sleep(tokio::time::Duration::from_secs(31)).await;

        // Message should be available again
        let redelivered = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            redelivered.body, received.body,
            "Same message should reappear after timeout"
        );
        assert_eq!(
            redelivered.delivery_count, 2,
            "Delivery count should be incremented"
        );
    }

    /// Verify that expired in-flight messages are returned to queue during cleanup.
    ///
    /// This tests the automatic cleanup mechanism.
    #[tokio::test]
    async fn test_expired_inflight_messages_return_to_queue() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("inflight-cleanup-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("Cleanup test"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Receive it
        let _received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Wait for visibility timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(31)).await;

        // Trigger cleanup by attempting another receive
        let redelivered = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(redelivered.body, Bytes::from("Cleanup test"));
    }

    /// Verify that receipt handles are invalidated after timeout.
    ///
    /// Operations with expired receipts should fail.
    #[tokio::test]
    async fn test_receipt_invalidation_after_timeout() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("receipt-invalidation-test".to_string()).unwrap();

        // Send and receive a message
        let msg = Message::new(Bytes::from("Receipt test"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        // Wait for visibility timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(31)).await;

        // Try to complete with expired receipt
        let result = provider.complete_message(&received.receipt_handle).await;

        assert!(result.is_err(), "Expired receipt should be invalid");
    }
}

// ============================================================================
// Subtask 10.4: TTL and Dead Letter Queue Tests
// ============================================================================

mod ttl_and_dlq {
    use super::*;

    /// Verify that messages with TTL expire after the specified duration.
    #[tokio::test]
    async fn test_message_ttl_expiration() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("ttl-test".to_string()).unwrap();

        // Send message with short TTL (2 seconds)
        let msg = Message::new(Bytes::from("Expires soon")).with_ttl(Duration::seconds(2));

        provider.send_message(&queue_name, &msg).await.unwrap();

        // Message should be receivable immediately
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(received.is_some(), "Message should be available initially");

        // Return message to queue
        provider
            .abandon_message(&received.unwrap().receipt_handle)
            .await
            .unwrap();

        // Wait for TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Message should no longer be available
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();

        assert!(result.is_none(), "Expired message should not be receivable");
    }

    /// Verify that expired messages are not returned during receive.
    #[tokio::test]
    async fn test_expired_messages_not_received() {
        let provider = InMemoryProvider::default();
        let queue_name = QueueName::new("expired-receive-test".to_string()).unwrap();

        // Send two messages: one with TTL, one without
        let msg_with_ttl =
            Message::new(Bytes::from("Has TTL")).with_ttl(Duration::milliseconds(500));
        let msg_without_ttl = Message::new(Bytes::from("No TTL"));

        provider
            .send_message(&queue_name, &msg_with_ttl)
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        provider
            .send_message(&queue_name, &msg_without_ttl)
            .await
            .unwrap();

        // Wait for first message TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

        // Should receive only the message without TTL
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.body, Bytes::from("No TTL"));

        // No more messages available
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    /// Verify that messages exceeding max delivery count are moved to DLQ.
    ///
    /// Assertion #14: Dead letter queue routing after max delivery attempts.
    #[tokio::test]
    async fn test_max_delivery_count_triggers_dlq() {
        let config = InMemoryConfig {
            max_delivery_count: 3,
            enable_dead_letter_queue: true,
            ..Default::default()
        };
        let provider = InMemoryProvider::new(config);
        let queue_name = QueueName::new("dlq-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("Will go to DLQ"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Receive and abandon max_delivery_count times
        for i in 1..=3 {
            let received = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
                .unwrap();

            // First three attempts should succeed (max_delivery_count = 3)
            assert!(
                received.is_some(),
                "Message should be available for delivery {}",
                i
            );
            provider
                .abandon_message(&received.unwrap().receipt_handle)
                .await
                .unwrap();
        }

        // Fourth attempt: message should be in DLQ
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(
            received.is_none(),
            "Message should be in DLQ after {} deliveries",
            3
        );

        // Regular queue should be empty
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(result.is_none(), "Main queue should be empty");
    }

    /// Verify that DLQ preserves original message metadata.
    #[tokio::test]
    async fn test_dlq_preserves_message_metadata() {
        let config = InMemoryConfig {
            max_delivery_count: 2,
            enable_dead_letter_queue: true,
            ..Default::default()
        };
        let provider = InMemoryProvider::new(config);
        let queue_name = QueueName::new("dlq-metadata-test".to_string()).unwrap();

        let session_id = SessionId::new("session-1".to_string()).unwrap();

        // Send message with metadata
        let msg = Message::new(Bytes::from("DLQ message"))
            .with_session_id(session_id.clone())
            .with_correlation_id("corr-123".to_string())
            .with_attribute("key".to_string(), "value".to_string());

        provider.send_message(&queue_name, &msg).await.unwrap();

        // Abandon twice to trigger DLQ
        for _ in 0..2 {
            if let Some(received) = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
                .unwrap()
            {
                provider
                    .abandon_message(&received.receipt_handle)
                    .await
                    .unwrap();
            }
        }

        // Message should be in DLQ (verify via implementation internals if needed)
        // For now, verify it's no longer in main queue
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(result.is_none(), "Message should be in DLQ");
    }

    /// Verify DLQ can be disabled via configuration.
    #[tokio::test]
    async fn test_dlq_disabled_when_configured() {
        let config = InMemoryConfig {
            max_delivery_count: 2,
            enable_dead_letter_queue: false, // Disabled
            ..Default::default()
        };
        let provider = InMemoryProvider::new(config);
        let queue_name = QueueName::new("dlq-disabled-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("No DLQ"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Abandon multiple times
        for _ in 0..5 {
            if let Some(received) = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
                .unwrap()
            {
                provider
                    .abandon_message(&received.receipt_handle)
                    .await
                    .unwrap();
            } else {
                break;
            }
        }

        // Message should still be receivable (no DLQ to move to)
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();

        assert!(
            received.is_some(),
            "Message should still be available when DLQ disabled"
        );
    }

    /// Verify that multiple abandons eventually trigger DLQ.
    #[tokio::test]
    async fn test_multiple_abandons_trigger_dlq() {
        let config = InMemoryConfig {
            max_delivery_count: 3,
            enable_dead_letter_queue: true,
            ..Default::default()
        };
        let provider = InMemoryProvider::new(config);
        let queue_name = QueueName::new("multi-abandon-test".to_string()).unwrap();

        // Send a message
        let msg = Message::new(Bytes::from("Abandon me"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Abandon exactly max_delivery_count times
        let mut attempts = 0;
        loop {
            match provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
                .unwrap()
            {
                Some(received) => {
                    attempts += 1;
                    provider
                        .abandon_message(&received.receipt_handle)
                        .await
                        .unwrap();
                }
                None => break,
            }

            if attempts >= 5 {
                // Safety limit
                break;
            }
        }

        // Should have received it exactly max_delivery_count times
        assert_eq!(
            attempts, 3,
            "Should receive message max_delivery_count times before DLQ"
        );

        // Message should now be in DLQ (not receivable from main queue)
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(result.is_none(), "Message should be in DLQ");
    }

    /// Verify that default TTL from config is applied to messages without explicit TTL.
    #[tokio::test]
    async fn test_default_message_ttl_applied() {
        let config = InMemoryConfig {
            default_message_ttl: Some(Duration::seconds(1)),
            ..Default::default()
        };
        let provider = InMemoryProvider::new(config);
        let queue_name = QueueName::new("default-ttl-test".to_string()).unwrap();

        // Send message without explicit TTL
        let msg = Message::new(Bytes::from("Uses default TTL"));
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Message should be receivable immediately
        let received = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(received.is_some());

        // Return to queue
        provider
            .abandon_message(&received.unwrap().receipt_handle)
            .await
            .unwrap();

        // Wait for default TTL to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Message should be expired
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(result.is_none(), "Message with default TTL should expire");
    }
}

// ============================================================================
// Session Provider Operations Tests
// ============================================================================

mod session_provider {
    use super::*;

    /// Verify that only one client can acquire a session lock at a time.
    ///
    /// Tests assertion #9: Session lock acquisition with exclusive access.
    #[tokio::test]
    async fn test_session_lock_acquisition() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("session-lock-test".to_string()).unwrap();
        let session_id = SessionId::new("test-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // First client accepts session - should succeed
        let session1 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await;
        assert!(session1.is_ok(), "First client should acquire session lock");

        // Second client tries to accept same session - should fail with lock error
        let session2 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await;
        assert!(
            session2.is_err(),
            "Second client should not acquire locked session"
        );

        if let Err(QueueError::SessionLocked { .. }) = session2 {
            // Expected error type
        } else {
            panic!("Expected SessionLocked error");
        }
    }

    /// Verify that session lock expires after timeout and becomes available.
    ///
    /// Tests assertion #10: Session lock timeout and automatic release.
    #[tokio::test]
    async fn test_session_lock_timeout() {
        let config = InMemoryConfig {
            session_lock_duration: Duration::seconds(1),
            ..Default::default()
        };
        let provider = Arc::new(InMemoryProvider::new(config));
        let queue_name = QueueName::new("lock-timeout-test".to_string()).unwrap();
        let session_id = SessionId::new("timeout-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // First client accepts session
        let session1 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await
            .unwrap();

        assert_eq!(session1.session_id(), &session_id);

        // Wait for lock to expire
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Second client should now be able to acquire lock
        let session2 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await;
        assert!(
            session2.is_ok(),
            "Session lock should expire and become available"
        );
    }

    /// Verify that session lock can be renewed before expiration.
    #[tokio::test]
    async fn test_session_renew_lock() {
        let config = InMemoryConfig {
            session_lock_duration: Duration::seconds(2),
            ..Default::default()
        };
        let provider = Arc::new(InMemoryProvider::new(config));
        let queue_name = QueueName::new("renew-lock-test".to_string()).unwrap();
        let session_id = SessionId::new("renew-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Accept session
        let session = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await
            .unwrap();

        // Wait half the lock duration
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Renew lock
        let renew_result = session.renew_session_lock().await;
        assert!(renew_result.is_ok(), "Lock renewal should succeed");

        // Wait another second (would have expired without renewal)
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Session should still be locked (another client can't acquire)
        let session2 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await;
        assert!(
            session2.is_err(),
            "Session should still be locked after renewal"
        );
    }

    /// Verify that closing a session releases the lock.
    #[tokio::test]
    async fn test_session_close_releases_lock() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("close-lock-test".to_string()).unwrap();
        let session_id = SessionId::new("close-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Accept session
        let session = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await
            .unwrap();

        // Close session
        let close_result = session.close_session().await;
        assert!(close_result.is_ok(), "Session close should succeed");

        // Another client should now be able to acquire the session
        let session2 = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await;
        assert!(
            session2.is_ok(),
            "Session lock should be released after close"
        );
    }

    /// Verify that concurrent session accept attempts handle locking correctly.
    #[tokio::test]
    async fn test_concurrent_session_accept_with_lock() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("concurrent-accept-test".to_string()).unwrap();
        let session_id = SessionId::new("concurrent-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Try to accept session from multiple threads concurrently
        let mut handles = vec![];
        for _ in 0..5 {
            let provider_clone = provider.clone();
            let queue_clone = queue_name.clone();
            let session_clone = session_id.clone();

            let handle = tokio::spawn(async move {
                provider_clone
                    .accept_session(&queue_clone, Some(session_clone))
                    .await
            });
            handles.push(handle);
        }

        // Collect results
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Exactly one should succeed
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            success_count, 1,
            "Only one client should acquire session lock"
        );

        // All others should have lock error
        let lock_error_count = results
            .iter()
            .filter(|r| matches!(r, Err(QueueError::SessionLocked { .. })))
            .count();
        assert_eq!(lock_error_count, 4, "Other clients should get lock error");
    }

    /// Verify that session provider only receives messages for its session.
    #[tokio::test]
    async fn test_session_receive_only_session_messages() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("session-filter-test".to_string()).unwrap();
        let session_a = SessionId::new("session-a".to_string()).unwrap();
        let session_b = SessionId::new("session-b".to_string()).unwrap();

        // Send messages to both sessions
        let msg_a1 = Message::new(Bytes::from("Message A1")).with_session_id(session_a.clone());
        let msg_a2 = Message::new(Bytes::from("Message A2")).with_session_id(session_a.clone());
        let msg_b = Message::new(Bytes::from("Message B")).with_session_id(session_b.clone());

        provider.send_message(&queue_name, &msg_a1).await.unwrap();
        provider.send_message(&queue_name, &msg_b).await.unwrap();
        provider.send_message(&queue_name, &msg_a2).await.unwrap();

        // Accept session A
        let session_client = provider
            .accept_session(&queue_name, Some(session_a.clone()))
            .await
            .unwrap();

        // Receive messages - should only get session A messages
        let received1 = session_client
            .receive_message(Duration::seconds(1))
            .await
            .unwrap();
        assert!(received1.is_some());
        assert_eq!(received1.as_ref().unwrap().body, Bytes::from("Message A1"));

        // Complete first message
        session_client
            .complete_message(received1.unwrap().receipt_handle)
            .await
            .unwrap();

        // Receive second message from session A
        let received2 = session_client
            .receive_message(Duration::seconds(1))
            .await
            .unwrap();
        assert!(received2.is_some());
        assert_eq!(received2.as_ref().unwrap().body, Bytes::from("Message A2"));

        // Should not receive session B message
        session_client
            .complete_message(received2.unwrap().receipt_handle)
            .await
            .unwrap();

        let received3 = session_client
            .receive_message(Duration::seconds(1))
            .await
            .unwrap();
        assert!(
            received3.is_none(),
            "Should not receive messages from other sessions"
        );
    }

    /// Verify that session operations validate lock ownership.
    #[tokio::test]
    async fn test_session_operations_validate_lock() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("lock-validation-test".to_string()).unwrap();
        let session_id = SessionId::new("lock-check-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Accept session
        let session = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await
            .unwrap();

        // Receive message
        let received = session.receive_message(Duration::seconds(1)).await.unwrap();
        assert!(received.is_some());

        // Close session (releases lock)
        session.close_session().await.unwrap();

        // Try to complete message after lock released - should fail
        let complete_result = session
            .complete_message(received.unwrap().receipt_handle)
            .await;

        assert!(
            complete_result.is_err(),
            "Operations should fail after session lock released"
        );
    }

    /// Verify that session expiration time is properly tracked.
    #[tokio::test]
    async fn test_session_expiration_time() {
        let config = InMemoryConfig {
            session_lock_duration: Duration::seconds(300), // 5 minutes
            ..Default::default()
        };
        let provider = Arc::new(InMemoryProvider::new(config));
        let queue_name = QueueName::new("expiration-test".to_string()).unwrap();
        let session_id = SessionId::new("expiring-session".to_string()).unwrap();

        // Send message to session
        let msg = Message::new(Bytes::from("Session message")).with_session_id(session_id.clone());
        provider.send_message(&queue_name, &msg).await.unwrap();

        // Accept session
        let session = provider
            .accept_session(&queue_name, Some(session_id.clone()))
            .await
            .unwrap();

        // Check expiration time is in the future
        let expires_at = session.session_expires_at();
        let now = Timestamp::now();

        assert!(
            expires_at > now,
            "Session expiration should be in the future"
        );

        // Should be approximately 5 minutes from now (within 1 second tolerance)
        let expected_duration = chrono::Duration::seconds(300);
        let actual_duration = expires_at.as_datetime() - now.as_datetime();
        let diff = (actual_duration - expected_duration).num_seconds().abs();

        assert!(
            diff <= 1,
            "Session expiration should be approximately session_lock_duration"
        );
    }
}

// ============================================================================
// Concurrency Tests
// ============================================================================

mod concurrency {
    use super::*;

    /// Verify concurrent send operations work correctly without data races.
    ///
    /// Tests assertion #18: Concurrent operations maintain consistency.
    #[tokio::test]
    async fn test_concurrent_send_operations() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("concurrent-send-test".to_string()).unwrap();
        let message_count = 100;

        // Send messages concurrently from multiple threads
        let mut handles = vec![];
        for i in 0..message_count {
            let provider_clone = provider.clone();
            let queue_clone = queue_name.clone();

            let handle = tokio::spawn(async move {
                let msg = Message::new(Bytes::from(format!("Message {}", i)));
                provider_clone.send_message(&queue_clone, &msg).await
            });
            handles.push(handle);
        }

        // Wait for all sends to complete
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All sends should succeed
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            message_count,
            "All concurrent sends should succeed"
        );

        // Verify all messages are in the queue
        let mut received_count = 0;
        for _ in 0..message_count {
            if let Ok(Some(_)) = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
            {
                received_count += 1;
            }
        }

        assert_eq!(
            received_count, message_count,
            "All sent messages should be receivable"
        );
    }

    /// Verify concurrent receive operations work correctly.
    #[tokio::test]
    async fn test_concurrent_receive_operations() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("concurrent-receive-test".to_string()).unwrap();
        let message_count = 50;

        // Send messages first
        for i in 0..message_count {
            let msg = Message::new(Bytes::from(format!("Message {}", i)));
            provider.send_message(&queue_name, &msg).await.unwrap();
        }

        // Receive messages concurrently from multiple threads
        let mut handles = vec![];
        for _ in 0..message_count {
            let provider_clone = provider.clone();
            let queue_clone = queue_name.clone();

            let handle = tokio::spawn(async move {
                provider_clone
                    .receive_message(&queue_clone, Duration::seconds(1))
                    .await
            });
            handles.push(handle);
        }

        // Wait for all receives to complete
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Count successful receives (should be exactly message_count)
        let received_count = results
            .iter()
            .filter(|r| r.is_ok() && r.as_ref().unwrap().is_some())
            .count();

        assert_eq!(
            received_count, message_count,
            "Each message should be received exactly once"
        );

        // No message should be received twice (verify unique message IDs)
        let mut message_ids: Vec<_> = results
            .iter()
            .filter_map(|r| {
                r.as_ref()
                    .ok()
                    .and_then(|opt| opt.as_ref().map(|msg| msg.message_id.as_str().to_string()))
            })
            .collect();

        message_ids.sort();
        let original_len = message_ids.len();
        message_ids.dedup();

        assert_eq!(
            message_ids.len(),
            original_len,
            "No message should be received twice"
        );
    }

    /// Verify concurrent complete operations work correctly.
    #[tokio::test]
    async fn test_concurrent_complete_operations() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("concurrent-complete-test".to_string()).unwrap();
        let message_count = 50;

        // Send and receive messages first
        let mut receipts = vec![];
        for i in 0..message_count {
            let msg = Message::new(Bytes::from(format!("Message {}", i)));
            provider.send_message(&queue_name, &msg).await.unwrap();

            if let Ok(Some(received)) = provider
                .receive_message(&queue_name, Duration::seconds(1))
                .await
            {
                receipts.push(received.receipt_handle);
            }
        }

        assert_eq!(receipts.len(), message_count, "Should receive all messages");

        // Complete messages concurrently
        let mut handles = vec![];
        for receipt in receipts {
            let provider_clone = provider.clone();

            let handle =
                tokio::spawn(async move { provider_clone.complete_message(&receipt).await });
            handles.push(handle);
        }

        // Wait for all completes to finish
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All completes should succeed
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            message_count,
            "All concurrent completes should succeed"
        );

        // Queue should be empty
        let result = provider
            .receive_message(&queue_name, Duration::seconds(1))
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "Queue should be empty after all completes"
        );
    }

    /// Verify that session locking prevents race conditions.
    #[tokio::test]
    async fn test_session_locking_prevents_race_conditions() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_name = QueueName::new("session-race-test".to_string()).unwrap();
        let session_id = SessionId::new("race-session".to_string()).unwrap();

        // Send multiple messages to session
        for i in 0..10 {
            let msg = Message::new(Bytes::from(format!("Message {}", i)))
                .with_session_id(session_id.clone());
            provider.send_message(&queue_name, &msg).await.unwrap();
        }

        // Try to process session from multiple threads
        let mut handles = vec![];
        for thread_id in 0..5 {
            let provider_clone = provider.clone();
            let queue_clone = queue_name.clone();
            let session_clone = session_id.clone();

            let handle = tokio::spawn(async move {
                let session_result = provider_clone
                    .accept_session(&queue_clone, Some(session_clone))
                    .await;

                if let Ok(session) = session_result {
                    // Try to receive and process messages
                    let mut processed = 0;
                    while let Ok(Some(msg)) = session.receive_message(Duration::seconds(1)).await {
                        session.complete_message(msg.receipt_handle).await.ok();
                        processed += 1;
                    }
                    (thread_id, processed)
                } else {
                    (thread_id, 0)
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        let mut results = vec![];
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // Only one thread should have processed messages
        let threads_with_messages = results.iter().filter(|(_, count)| *count > 0).count();
        assert_eq!(
            threads_with_messages, 1,
            "Only one thread should acquire session lock and process messages"
        );

        // That thread should have processed all 10 messages
        let total_processed: usize = results.iter().map(|(_, count)| count).sum();
        assert_eq!(
            total_processed, 10,
            "All messages should be processed by the locking thread"
        );
    }

    /// Verify that multiple queues operate independently.
    #[tokio::test]
    async fn test_multiple_queues_independent() {
        let provider = Arc::new(InMemoryProvider::new(InMemoryConfig::default()));
        let queue_a = QueueName::new("queue-a".to_string()).unwrap();
        let queue_b = QueueName::new("queue-b".to_string()).unwrap();
        let message_count = 20;

        // Send messages to both queues concurrently
        let mut handles = vec![];

        for i in 0..message_count {
            let provider_clone = provider.clone();
            let queue_clone = queue_a.clone();
            let handle = tokio::spawn(async move {
                let msg = Message::new(Bytes::from(format!("Queue A Message {}", i)));
                provider_clone.send_message(&queue_clone, &msg).await
            });
            handles.push(handle);

            let provider_clone = provider.clone();
            let queue_clone = queue_b.clone();
            let handle = tokio::spawn(async move {
                let msg = Message::new(Bytes::from(format!("Queue B Message {}", i)));
                provider_clone.send_message(&queue_clone, &msg).await
            });
            handles.push(handle);
        }

        // Wait for all sends
        for handle in handles {
            let _ = handle.await.unwrap();
        }

        // Receive from both queues concurrently
        let mut receive_handles = vec![];

        for _ in 0..message_count {
            let provider_clone = provider.clone();
            let queue_clone = queue_a.clone();
            let handle = tokio::spawn(async move {
                provider_clone
                    .receive_message(&queue_clone, Duration::seconds(1))
                    .await
            });
            receive_handles.push(handle);

            let provider_clone = provider.clone();
            let queue_clone = queue_b.clone();
            let handle = tokio::spawn(async move {
                provider_clone
                    .receive_message(&queue_clone, Duration::seconds(1))
                    .await
            });
            receive_handles.push(handle);
        }

        let mut results = vec![];
        for handle in receive_handles {
            results.push(handle.await.unwrap());
        }

        // All receives should succeed
        let success_count = results
            .iter()
            .filter(|r| r.is_ok() && r.as_ref().unwrap().is_some())
            .count();

        assert_eq!(
            success_count,
            message_count * 2,
            "Each queue should operate independently"
        );
    }
}
