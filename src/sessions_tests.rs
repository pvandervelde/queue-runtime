//! Tests for session management and key generation strategies.

use super::*;
use std::collections::HashMap;

// ============================================================================
// Test Message Implementation
// ============================================================================

/// Generic test message with arbitrary metadata fields
struct TestMessage {
    metadata: HashMap<String, String>,
}

impl TestMessage {
    fn new() -> Self {
        Self {
            metadata: HashMap::new(),
        }
    }

    fn with_field(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

impl SessionKeyExtractor for TestMessage {
    fn get_metadata(&self, key: &str) -> Option<String> {
        self.metadata.get(key).cloned()
    }

    fn list_metadata_keys(&self) -> Vec<String> {
        self.metadata.keys().cloned().collect()
    }
}

// ============================================================================
// SessionKeyExtractor Tests
// ============================================================================

mod session_key_extractor_tests {
    use super::*;

    #[test]
    fn test_get_metadata_returns_value_when_present() {
        let message = TestMessage::new()
            .with_field("user_id", "12345")
            .with_field("resource_id", "abc-def");

        assert_eq!(message.get_metadata("user_id"), Some("12345".to_string()));
        assert_eq!(
            message.get_metadata("resource_id"),
            Some("abc-def".to_string())
        );
    }

    #[test]
    fn test_get_metadata_returns_none_when_absent() {
        let message = TestMessage::new().with_field("user_id", "12345");

        assert_eq!(message.get_metadata("missing_field"), None);
    }

    #[test]
    fn test_list_metadata_keys() {
        let message = TestMessage::new()
            .with_field("field1", "value1")
            .with_field("field2", "value2")
            .with_field("field3", "value3");

        let keys = message.list_metadata_keys();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&"field1".to_string()));
        assert!(keys.contains(&"field2".to_string()));
        assert!(keys.contains(&"field3".to_string()));
    }

    #[test]
    fn test_get_all_metadata() {
        let message = TestMessage::new()
            .with_field("key1", "value1")
            .with_field("key2", "value2");

        let all_metadata = message.get_all_metadata();
        assert_eq!(all_metadata.len(), 2);
        assert_eq!(all_metadata.get("key1"), Some(&"value1".to_string()));
        assert_eq!(all_metadata.get("key2"), Some(&"value2".to_string()));
    }
}

// ============================================================================
// CompositeKeyStrategy Tests
// ============================================================================

mod composite_key_strategy_tests {
    use super::*;

    #[test]
    fn test_generate_key_combines_multiple_fields() {
        let strategy = CompositeKeyStrategy::new(
            vec!["tenant_id".to_string(), "resource_id".to_string()],
            "-",
        );

        let message = TestMessage::new()
            .with_field("tenant_id", "tenant123")
            .with_field("resource_id", "res456");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "tenant123-res456");
    }

    #[test]
    fn test_generate_key_returns_none_when_any_field_missing() {
        let strategy =
            CompositeKeyStrategy::new(vec!["field1".to_string(), "field2".to_string()], "-");

        let message = TestMessage::new().with_field("field1", "value1");
        // field2 is missing

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_generate_key_with_custom_separator() {
        let strategy =
            CompositeKeyStrategy::new(vec!["region".to_string(), "customer".to_string()], "::");

        let message = TestMessage::new()
            .with_field("region", "us-west")
            .with_field("customer", "acme");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "us-west::acme");
    }

    #[test]
    fn test_generate_key_with_single_field() {
        let strategy = CompositeKeyStrategy::new(vec!["order_id".to_string()], "-");

        let message = TestMessage::new().with_field("order_id", "12345");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "12345");
    }

    #[test]
    fn test_generate_key_with_empty_fields_returns_none() {
        let strategy = CompositeKeyStrategy::new(vec![], "-");

        let message = TestMessage::new().with_field("any_field", "value");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_different_field_values_produce_different_keys() {
        let strategy = CompositeKeyStrategy::new(vec!["user_id".to_string()], "-");

        let message1 = TestMessage::new().with_field("user_id", "user1");
        let message2 = TestMessage::new().with_field("user_id", "user2");

        let key1 = strategy.generate_key(&message1).unwrap();
        let key2 = strategy.generate_key(&message2).unwrap();

        assert_ne!(key1.as_str(), key2.as_str());
    }
}

// ============================================================================
// SingleFieldStrategy Tests
// ============================================================================

mod single_field_strategy_tests {
    use super::*;

    #[test]
    fn test_generate_key_from_field_with_prefix() {
        let strategy = SingleFieldStrategy::new("user_id", Some("user"));

        let message = TestMessage::new().with_field("user_id", "12345");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "user-12345");
    }

    #[test]
    fn test_generate_key_from_field_without_prefix() {
        let strategy = SingleFieldStrategy::new("order_id", None);

        let message = TestMessage::new().with_field("order_id", "ORD-999");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "ORD-999");
    }

    #[test]
    fn test_generate_key_returns_none_when_field_missing() {
        let strategy = SingleFieldStrategy::new("missing_field", Some("prefix"));

        let message = TestMessage::new().with_field("other_field", "value");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_different_field_values_produce_different_keys() {
        let strategy = SingleFieldStrategy::new("resource_id", Some("res"));

        let message1 = TestMessage::new().with_field("resource_id", "abc");
        let message2 = TestMessage::new().with_field("resource_id", "xyz");

        let key1 = strategy.generate_key(&message1).unwrap();
        let key2 = strategy.generate_key(&message2).unwrap();

        assert_ne!(key1.as_str(), key2.as_str());
    }

    #[test]
    fn test_same_field_value_produces_same_key() {
        let strategy = SingleFieldStrategy::new("tenant_id", Some("tenant"));

        let message1 = TestMessage::new().with_field("tenant_id", "abc123");
        let message2 = TestMessage::new().with_field("tenant_id", "abc123");

        let key1 = strategy.generate_key(&message1).unwrap();
        let key2 = strategy.generate_key(&message2).unwrap();

        assert_eq!(key1.as_str(), key2.as_str());
    }
}

// ============================================================================
// NoOrderingStrategy Tests
// ============================================================================

mod no_ordering_strategy_tests {
    use super::*;

    #[test]
    fn test_always_returns_none() {
        let strategy = NoOrderingStrategy;

        let message1 = TestMessage::new()
            .with_field("user_id", "123")
            .with_field("resource_id", "456");
        let message2 = TestMessage::new().with_field("order_id", "789");
        let message3 = TestMessage::new();

        assert!(strategy.generate_key(&message1).is_none());
        assert!(strategy.generate_key(&message2).is_none());
        assert!(strategy.generate_key(&message3).is_none());
    }
}

// ============================================================================
// FallbackStrategy Tests
// ============================================================================

mod fallback_strategy_tests {
    use super::*;

    #[test]
    fn test_uses_primary_when_available() {
        let primary = SingleFieldStrategy::new("entity_id", Some("entity"));
        let fallback = SingleFieldStrategy::new("tenant_id", Some("tenant"));

        let strategy = FallbackStrategy::new(vec![Box::new(primary), Box::new(fallback)]);

        let message = TestMessage::new()
            .with_field("entity_id", "ent123")
            .with_field("tenant_id", "ten456");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "entity-ent123");
    }

    #[test]
    fn test_falls_back_when_primary_unavailable() {
        let primary = SingleFieldStrategy::new("entity_id", Some("entity"));
        let fallback = SingleFieldStrategy::new("tenant_id", Some("tenant"));

        let strategy = FallbackStrategy::new(vec![Box::new(primary), Box::new(fallback)]);

        let message = TestMessage::new().with_field("tenant_id", "ten456");
        // entity_id is missing

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "tenant-ten456");
    }

    #[test]
    fn test_returns_none_when_all_strategies_fail() {
        let primary = SingleFieldStrategy::new("field1", None);
        let fallback = SingleFieldStrategy::new("field2", None);

        let strategy = FallbackStrategy::new(vec![Box::new(primary), Box::new(fallback)]);

        let message = TestMessage::new().with_field("field3", "value");
        // Neither field1 nor field2 present

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_none());
    }

    #[test]
    fn test_multiple_fallback_levels() {
        let level1 = SingleFieldStrategy::new("specific_id", Some("specific"));
        let level2 = SingleFieldStrategy::new("group_id", Some("group"));
        let level3 = SingleFieldStrategy::new("global_id", Some("global"));

        let strategy =
            FallbackStrategy::new(vec![Box::new(level1), Box::new(level2), Box::new(level3)]);

        // Test skipping to level 2
        let message = TestMessage::new()
            .with_field("group_id", "grp789")
            .with_field("global_id", "glb999");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_some());
        assert_eq!(session_id.unwrap().as_str(), "group-grp789");
    }

    #[test]
    fn test_with_no_ordering_as_ultimate_fallback() {
        let primary = SingleFieldStrategy::new("entity_id", Some("entity"));
        let ultimate = NoOrderingStrategy;

        let strategy = FallbackStrategy::new(vec![Box::new(primary), Box::new(ultimate)]);

        let message = TestMessage::new().with_field("other_field", "value");

        let session_id = strategy.generate_key(&message);
        assert!(session_id.is_none()); // NoOrderingStrategy returns None
    }
}

// ============================================================================
// SessionLock Tests
// ============================================================================

mod session_lock_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that a newly created lock is not expired.
    #[tokio::test]
    async fn test_new_lock_is_not_expired() {
        let session_id = SessionId::new("test-session".to_string()).unwrap();
        let lock = SessionLock::new(
            session_id,
            "consumer-1".to_string(),
            Duration::from_secs(30),
        );

        assert!(!lock.is_expired());
        assert_eq!(lock.owner(), "consumer-1");
    }

    /// Verify that lock tracks session ID and owner correctly.
    #[tokio::test]
    async fn test_lock_tracks_session_and_owner() {
        let session_id = SessionId::new("order-123".to_string()).unwrap();
        let lock = SessionLock::new(
            session_id.clone(),
            "worker-5".to_string(),
            Duration::from_secs(60),
        );

        assert_eq!(lock.session_id(), &session_id);
        assert_eq!(lock.owner(), "worker-5");
        assert_eq!(lock.lock_duration(), Duration::from_secs(60));
    }

    /// Verify that lock expires after the specified duration.
    #[tokio::test]
    async fn test_lock_expires_after_duration() {
        let session_id = SessionId::new("short-lived".to_string()).unwrap();
        let lock = SessionLock::new(
            session_id,
            "consumer-1".to_string(),
            Duration::from_millis(50),
        );

        assert!(!lock.is_expired());

        sleep(Duration::from_millis(60)).await;

        assert!(lock.is_expired());
    }

    /// Verify that time_remaining returns correct values.
    #[tokio::test]
    async fn test_time_remaining_calculation() {
        let session_id = SessionId::new("timed-session".to_string()).unwrap();
        let lock = SessionLock::new(
            session_id,
            "consumer-1".to_string(),
            Duration::from_millis(100),
        );

        let remaining = lock.time_remaining();
        assert!(remaining <= Duration::from_millis(100));
        assert!(remaining > Duration::from_millis(50)); // Should still have time

        sleep(Duration::from_millis(110)).await;

        assert_eq!(lock.time_remaining(), Duration::ZERO);
    }

    /// Verify that lock can be renewed to extend expiration.
    #[tokio::test]
    async fn test_lock_renewal() {
        let session_id = SessionId::new("renewable".to_string()).unwrap();
        let original_lock = SessionLock::new(
            session_id.clone(),
            "consumer-1".to_string(),
            Duration::from_millis(50),
        );

        sleep(Duration::from_millis(30)).await;

        let renewed_lock = original_lock.renew(Duration::from_millis(100));

        assert_eq!(renewed_lock.session_id(), &session_id);
        assert_eq!(renewed_lock.owner(), "consumer-1");
        assert!(!renewed_lock.is_expired());

        // Original lock should still expire on schedule
        sleep(Duration::from_millis(30)).await;
        assert!(original_lock.is_expired());

        // Renewed lock should still be valid
        assert!(!renewed_lock.is_expired());
    }
}

// ============================================================================
// SessionLockManager Tests
// ============================================================================

mod session_lock_manager_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that a session can be locked successfully.
    #[tokio::test]
    async fn test_acquire_lock_succeeds() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("session-1".to_string()).unwrap();

        let result = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await;

        assert!(result.is_ok());
        let lock = result.unwrap();
        assert_eq!(lock.session_id(), &session_id);
        assert_eq!(lock.owner(), "consumer-1");
    }

    /// Verify that locking same session twice by different consumers fails.
    #[tokio::test]
    async fn test_acquire_locked_session_fails() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("contested-session".to_string()).unwrap();

        // First consumer acquires lock
        let _lock1 = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        // Second consumer tries to acquire same session
        let result = manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionLocked { .. }
        ));
    }

    /// Verify that same consumer can acquire lock again (idempotent).
    #[tokio::test]
    async fn test_same_consumer_can_reacquire_lock() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("idempotent-session".to_string()).unwrap();

        let _lock1 = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        // Same consumer tries again - should succeed
        let result = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await;

        assert!(result.is_ok());
    }

    /// Verify that expired locks can be acquired by new consumers.
    #[tokio::test]
    async fn test_expired_lock_can_be_reacquired() {
        let manager = SessionLockManager::new(Duration::from_millis(50));
        let session_id = SessionId::new("expiring-session".to_string()).unwrap();

        // First consumer acquires lock
        let _lock1 = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        // Wait for lock to expire
        sleep(Duration::from_millis(60)).await;

        // Second consumer can now acquire the session
        let result = manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await;

        assert!(result.is_ok());
        let lock = result.unwrap();
        assert_eq!(lock.owner(), "consumer-2");
    }

    /// Verify that locks can be renewed successfully.
    #[tokio::test]
    async fn test_renew_lock_succeeds() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("renewable-session".to_string()).unwrap();

        let _lock = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        let result = manager
            .renew_lock(&session_id, "consumer-1", Some(Duration::from_secs(60)))
            .await;

        assert!(result.is_ok());
        let renewed = result.unwrap();
        assert_eq!(renewed.lock_duration(), Duration::from_secs(60));
    }

    /// Verify that renewing lock for wrong owner fails.
    #[tokio::test]
    async fn test_renew_lock_wrong_owner_fails() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("owned-session".to_string()).unwrap();

        let _lock = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        let result = manager.renew_lock(&session_id, "consumer-2", None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionLocked { .. }
        ));
    }

    /// Verify that renewing non-existent lock fails.
    #[tokio::test]
    async fn test_renew_nonexistent_lock_fails() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("nonexistent".to_string()).unwrap();

        let result = manager.renew_lock(&session_id, "consumer-1", None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionNotFound { .. }
        ));
    }

    /// Verify that locks can be released successfully.
    #[tokio::test]
    async fn test_release_lock_succeeds() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("releasable-session".to_string()).unwrap();

        let _lock = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        let result = manager.release_lock(&session_id, "consumer-1").await;
        assert!(result.is_ok());

        // Session should no longer be locked
        assert!(!manager.is_locked(&session_id).await);
    }

    /// Verify that releasing lock for wrong owner fails.
    #[tokio::test]
    async fn test_release_lock_wrong_owner_fails() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("protected-session".to_string()).unwrap();

        let _lock = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        let result = manager.release_lock(&session_id, "consumer-2").await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionLocked { .. }
        ));
    }

    /// Verify that is_locked returns correct status.
    #[tokio::test]
    async fn test_is_locked_status() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("status-check".to_string()).unwrap();

        assert!(!manager.is_locked(&session_id).await);

        let _lock = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        assert!(manager.is_locked(&session_id).await);

        manager
            .release_lock(&session_id, "consumer-1")
            .await
            .unwrap();

        assert!(!manager.is_locked(&session_id).await);
    }

    /// Verify that get_lock returns lock information.
    #[tokio::test]
    async fn test_get_lock_returns_info() {
        let manager = SessionLockManager::new(Duration::from_secs(30));
        let session_id = SessionId::new("info-session".to_string()).unwrap();

        assert!(manager.get_lock(&session_id).await.is_none());

        let _original = manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        let lock_info = manager.get_lock(&session_id).await;
        assert!(lock_info.is_some());
        assert_eq!(lock_info.unwrap().owner(), "consumer-1");
    }

    /// Verify that expired locks are cleaned up.
    #[tokio::test]
    async fn test_cleanup_expired_locks() {
        let manager = SessionLockManager::new(Duration::from_millis(50));

        // Create several locks
        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        manager
            .try_acquire_lock(session1.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        manager
            .try_acquire_lock(session2.clone(), "consumer-2".to_string())
            .await
            .unwrap();

        assert_eq!(manager.lock_count().await, 2);

        // Wait for locks to expire
        sleep(Duration::from_millis(60)).await;

        let cleaned = manager.cleanup_expired_locks().await;
        assert_eq!(cleaned, 2);
        assert_eq!(manager.lock_count().await, 0);
    }

    /// Verify lock count tracking.
    #[tokio::test]
    async fn test_lock_count_tracking() {
        let manager = SessionLockManager::new(Duration::from_secs(30));

        assert_eq!(manager.lock_count().await, 0);
        assert_eq!(manager.active_lock_count().await, 0);

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        manager
            .try_acquire_lock(session1.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        manager
            .try_acquire_lock(session2.clone(), "consumer-2".to_string())
            .await
            .unwrap();

        assert_eq!(manager.lock_count().await, 2);
        assert_eq!(manager.active_lock_count().await, 2);

        manager.release_lock(&session1, "consumer-1").await.unwrap();

        assert_eq!(manager.lock_count().await, 1);
        assert_eq!(manager.active_lock_count().await, 1);
    }

    /// Verify that active lock count excludes expired locks.
    #[tokio::test]
    async fn test_active_lock_count_excludes_expired() {
        let manager = SessionLockManager::new(Duration::from_millis(50));

        let session1 = SessionId::new("active".to_string()).unwrap();
        let session2 = SessionId::new("expired".to_string()).unwrap();

        manager
            .try_acquire_lock(session1.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        sleep(Duration::from_millis(30)).await;

        manager
            .try_acquire_lock(session2.clone(), "consumer-2".to_string())
            .await
            .unwrap();

        assert_eq!(manager.lock_count().await, 2);

        // Wait for first lock to expire
        sleep(Duration::from_millis(30)).await;

        assert_eq!(manager.lock_count().await, 2); // Still stored
        assert_eq!(manager.active_lock_count().await, 1); // Only one active
    }
}

// ============================================================================
// SessionAffinity Tests
// ============================================================================

mod session_affinity_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that a newly created affinity is not expired.
    #[tokio::test]
    async fn test_new_affinity_is_not_expired() {
        let session_id = SessionId::new("session-1".to_string()).unwrap();
        let affinity = SessionAffinity::new(
            session_id.clone(),
            "worker-1".to_string(),
            Duration::from_secs(60),
        );

        assert!(!affinity.is_expired());
        assert_eq!(affinity.consumer_id(), "worker-1");
        assert_eq!(affinity.session_id(), &session_id);
    }

    /// Verify that affinity tracks session, consumer, and duration.
    #[tokio::test]
    async fn test_affinity_tracks_details() {
        let session_id = SessionId::new("order-456".to_string()).unwrap();
        let affinity = SessionAffinity::new(
            session_id.clone(),
            "processor-3".to_string(),
            Duration::from_secs(300),
        );

        assert_eq!(affinity.session_id(), &session_id);
        assert_eq!(affinity.consumer_id(), "processor-3");
        assert_eq!(affinity.affinity_duration(), Duration::from_secs(300));
    }

    /// Verify that affinity expires after the specified duration.
    #[tokio::test]
    async fn test_affinity_expires_after_duration() {
        let session_id = SessionId::new("short-affinity".to_string()).unwrap();
        let affinity = SessionAffinity::new(
            session_id,
            "worker-1".to_string(),
            Duration::from_millis(50),
        );

        assert!(!affinity.is_expired());

        sleep(Duration::from_millis(60)).await;

        assert!(affinity.is_expired());
    }

    /// Verify that time_remaining returns correct values.
    #[tokio::test]
    async fn test_affinity_time_remaining() {
        let session_id = SessionId::new("timed-affinity".to_string()).unwrap();
        let affinity = SessionAffinity::new(
            session_id,
            "worker-1".to_string(),
            Duration::from_millis(100),
        );

        let remaining = affinity.time_remaining();
        assert!(remaining <= Duration::from_millis(100));
        assert!(remaining > Duration::from_millis(50));

        sleep(Duration::from_millis(110)).await;

        assert_eq!(affinity.time_remaining(), Duration::ZERO);
    }

    /// Verify that touch updates last activity time.
    #[tokio::test]
    async fn test_affinity_touch_updates_activity() {
        let session_id = SessionId::new("active-session".to_string()).unwrap();
        let mut affinity =
            SessionAffinity::new(session_id, "worker-1".to_string(), Duration::from_secs(60));

        sleep(Duration::from_millis(50)).await;
        let idle_before = affinity.idle_time();

        affinity.touch();

        let idle_after = affinity.idle_time();
        assert!(idle_after < idle_before);
    }

    /// Verify that affinity can be extended.
    #[tokio::test]
    async fn test_affinity_extend() {
        let session_id = SessionId::new("extendable".to_string()).unwrap();
        let original = SessionAffinity::new(
            session_id.clone(),
            "worker-1".to_string(),
            Duration::from_millis(50),
        );

        sleep(Duration::from_millis(30)).await;

        let extended = original.extend(Duration::from_millis(100));

        assert_eq!(extended.session_id(), &session_id);
        assert_eq!(extended.consumer_id(), "worker-1");
        assert!(!extended.is_expired());

        // Original should still expire on schedule
        sleep(Duration::from_millis(30)).await;
        assert!(original.is_expired());
        assert!(!extended.is_expired());
    }
}

// ============================================================================
// SessionAffinityTracker Tests
// ============================================================================

mod session_affinity_tracker_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that a session can be assigned successfully.
    #[tokio::test]
    async fn test_assign_session_succeeds() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("session-1".to_string()).unwrap();

        let result = tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await;

        assert!(result.is_ok());
        let affinity = result.unwrap();
        assert_eq!(affinity.session_id(), &session_id);
        assert_eq!(affinity.consumer_id(), "worker-1");
    }

    /// Verify that assigning same session twice to different consumers fails.
    #[tokio::test]
    async fn test_assign_session_twice_fails() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("contested".to_string()).unwrap();

        // First assignment succeeds
        let _affinity1 = tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Second assignment to different consumer fails
        let result = tracker
            .assign_session(session_id.clone(), "worker-2".to_string())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionLocked { .. }
        ));
    }

    /// Verify that same consumer can reacquire session (idempotent).
    #[tokio::test]
    async fn test_assign_session_same_consumer_idempotent() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("idempotent".to_string()).unwrap();

        let affinity1 = tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        let affinity2 = tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert_eq!(affinity1.consumer_id(), affinity2.consumer_id());
    }

    /// Verify that expired affinity can be reassigned.
    #[tokio::test]
    async fn test_expired_affinity_can_be_reassigned() {
        let tracker = SessionAffinityTracker::new(Duration::from_millis(50));
        let session_id = SessionId::new("expiring".to_string()).unwrap();

        // First assignment
        let _affinity1 = tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(60)).await;

        // Can now assign to different consumer
        let result = tracker
            .assign_session(session_id.clone(), "worker-2".to_string())
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().consumer_id(), "worker-2");
    }

    /// Verify that get_consumer returns correct consumer.
    #[tokio::test]
    async fn test_get_consumer() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("tracked".to_string()).unwrap();

        // No consumer initially
        assert_eq!(tracker.get_consumer(&session_id).await, None);

        // Assign consumer
        tracker
            .assign_session(session_id.clone(), "worker-5".to_string())
            .await
            .unwrap();

        // Now returns consumer
        assert_eq!(
            tracker.get_consumer(&session_id).await,
            Some("worker-5".to_string())
        );
    }

    /// Verify that has_affinity returns correct status.
    #[tokio::test]
    async fn test_has_affinity() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("check".to_string()).unwrap();

        assert!(!tracker.has_affinity(&session_id).await);

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert!(tracker.has_affinity(&session_id).await);
    }

    /// Verify that touch_session updates activity.
    #[tokio::test]
    async fn test_touch_session() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("active".to_string()).unwrap();

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        let result = tracker.touch_session(&session_id).await;
        assert!(result.is_ok());
    }

    /// Verify that touching nonexistent session fails.
    #[tokio::test]
    async fn test_touch_nonexistent_session_fails() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("nonexistent".to_string()).unwrap();

        let result = tracker.touch_session(&session_id).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionNotFound { .. }
        ));
    }

    /// Verify that release_session removes affinity.
    #[tokio::test]
    async fn test_release_session() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("releasable".to_string()).unwrap();

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert!(tracker.has_affinity(&session_id).await);

        let result = tracker.release_session(&session_id, "worker-1").await;
        assert!(result.is_ok());

        assert!(!tracker.has_affinity(&session_id).await);
    }

    /// Verify that wrong consumer cannot release session.
    #[tokio::test]
    async fn test_release_session_wrong_consumer_fails() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("protected".to_string()).unwrap();

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        let result = tracker.release_session(&session_id, "worker-2").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::ValidationError(_)
        ));

        // Affinity still exists
        assert!(tracker.has_affinity(&session_id).await);
    }

    /// Verify that extend_affinity extends expiration.
    #[tokio::test]
    async fn test_extend_affinity() {
        let tracker = SessionAffinityTracker::new(Duration::from_millis(100));
        let session_id = SessionId::new("extendable".to_string()).unwrap();

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        sleep(Duration::from_millis(50)).await;

        let result = tracker
            .extend_affinity(&session_id, "worker-1", Duration::from_millis(200))
            .await;

        assert!(result.is_ok());

        // Original would have expired by now
        sleep(Duration::from_millis(60)).await;

        // But extended version is still active
        assert!(tracker.has_affinity(&session_id).await);
    }

    /// Verify that wrong consumer cannot extend affinity.
    #[tokio::test]
    async fn test_extend_affinity_wrong_consumer_fails() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session_id = SessionId::new("owned".to_string()).unwrap();

        tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        let result = tracker
            .extend_affinity(&session_id, "worker-2", Duration::from_secs(30))
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::ValidationError(_)
        ));
    }

    /// Verify that get_consumer_sessions returns correct sessions.
    #[tokio::test]
    async fn test_get_consumer_sessions() {
        let tracker = SessionAffinityTracker::new(Duration::from_secs(60));
        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();
        let session3 = SessionId::new("session-3".to_string()).unwrap();

        tracker
            .assign_session(session1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        tracker
            .assign_session(session2.clone(), "worker-1".to_string())
            .await
            .unwrap();
        tracker
            .assign_session(session3.clone(), "worker-2".to_string())
            .await
            .unwrap();

        let worker1_sessions = tracker.get_consumer_sessions("worker-1").await;
        assert_eq!(worker1_sessions.len(), 2);
        assert!(worker1_sessions.contains(&session1));
        assert!(worker1_sessions.contains(&session2));

        let worker2_sessions = tracker.get_consumer_sessions("worker-2").await;
        assert_eq!(worker2_sessions.len(), 1);
        assert!(worker2_sessions.contains(&session3));
    }

    /// Verify that cleanup_expired removes expired affinities.
    #[tokio::test]
    async fn test_cleanup_expired() {
        let tracker = SessionAffinityTracker::new(Duration::from_millis(20));
        let active = SessionId::new("active".to_string()).unwrap();
        let expired1 = SessionId::new("expired1".to_string()).unwrap();
        let expired2 = SessionId::new("expired2".to_string()).unwrap();

        // Assign expired sessions
        tracker
            .assign_session(expired1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        tracker
            .assign_session(expired2.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(30)).await;

        // Assign active session
        tracker
            .assign_session(active.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert_eq!(tracker.affinity_count().await, 3);

        let removed = tracker.cleanup_expired().await;
        assert_eq!(removed, 2);

        assert_eq!(tracker.affinity_count().await, 1);
        assert!(tracker.has_affinity(&active).await);
        assert!(!tracker.has_affinity(&expired1).await);
        assert!(!tracker.has_affinity(&expired2).await);
    }

    /// Verify that affinity_count and active_affinity_count work correctly.
    #[tokio::test]
    async fn test_affinity_counts() {
        let tracker = SessionAffinityTracker::new(Duration::from_millis(20));
        let active = SessionId::new("active".to_string()).unwrap();
        let expired = SessionId::new("expired".to_string()).unwrap();

        // Assign expired session
        tracker
            .assign_session(expired.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(30)).await;

        // Assign active session
        tracker
            .assign_session(active.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert_eq!(tracker.affinity_count().await, 2); // Both stored
        assert_eq!(tracker.active_affinity_count().await, 1); // Only one active
    }

    /// Verify concurrent affinity assignments to different sessions.
    #[tokio::test]
    async fn test_concurrent_affinity_assignments() {
        let tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));
        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        let tracker1 = Arc::clone(&tracker);
        let session1_clone = session1.clone();
        let handle1 = tokio::spawn(async move {
            tracker1
                .assign_session(session1_clone, "worker-1".to_string())
                .await
        });

        let tracker2 = Arc::clone(&tracker);
        let session2_clone = session2.clone();
        let handle2 = tokio::spawn(async move {
            tracker2
                .assign_session(session2_clone, "worker-2".to_string())
                .await
        });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        assert_eq!(
            tracker.get_consumer(&session1).await,
            Some("worker-1".to_string())
        );
        assert_eq!(
            tracker.get_consumer(&session2).await,
            Some("worker-2".to_string())
        );
    }
}

// ============================================================================
// SessionInfo Tests
// ============================================================================

mod session_info_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that SessionInfo tracks basic details correctly.
    #[tokio::test]
    async fn test_session_info_tracks_details() {
        let session_id = SessionId::new("order-789".to_string()).unwrap();
        let info = SessionInfo::new(session_id.clone(), "worker-1".to_string());

        assert_eq!(info.session_id(), &session_id);
        assert_eq!(info.consumer_id(), "worker-1");
        assert_eq!(info.message_count(), 0);
    }

    /// Verify that message count increments correctly.
    #[tokio::test]
    async fn test_session_info_message_count() {
        let session_id = SessionId::new("order-123".to_string()).unwrap();
        let mut info = SessionInfo::new(session_id.clone(), "worker-1".to_string());

        assert_eq!(info.message_count(), 0);

        info.increment_message_count();
        assert_eq!(info.message_count(), 1);

        info.increment_message_count();
        info.increment_message_count();
        assert_eq!(info.message_count(), 3);
    }

    /// Verify that duration is calculated correctly.
    #[tokio::test]
    async fn test_session_info_duration() {
        let session_id = SessionId::new("timed".to_string()).unwrap();
        let info = SessionInfo::new(session_id, "worker-1".to_string());

        let duration1 = info.duration();
        sleep(Duration::from_millis(50)).await;
        let duration2 = info.duration();

        assert!(duration2 > duration1);
        assert!(duration2 >= Duration::from_millis(50));
    }

    /// Verify that idle time is calculated correctly.
    #[tokio::test]
    async fn test_session_info_idle_time() {
        let session_id = SessionId::new("idle-check".to_string()).unwrap();
        let mut info = SessionInfo::new(session_id, "worker-1".to_string());

        sleep(Duration::from_millis(50)).await;
        let idle1 = info.idle_time();
        assert!(idle1 >= Duration::from_millis(50));

        // Activity resets idle time
        info.increment_message_count();
        let idle2 = info.idle_time();
        assert!(idle2 < idle1);
    }

    /// Verify that touch updates last activity.
    #[tokio::test]
    async fn test_session_info_touch() {
        let session_id = SessionId::new("touched".to_string()).unwrap();
        let mut info = SessionInfo::new(session_id, "worker-1".to_string());

        sleep(Duration::from_millis(50)).await;
        let idle_before = info.idle_time();

        info.touch();
        let idle_after = info.idle_time();

        assert!(idle_after < idle_before);
        assert_eq!(info.message_count(), 0); // Touch doesn't increment count
    }
}

// ============================================================================
// SessionLifecycleConfig Tests
// ============================================================================

mod session_lifecycle_config_tests {
    use super::*;
    use std::time::Duration;

    /// Verify default configuration values are reasonable.
    #[test]
    fn test_default_config() {
        let config = SessionLifecycleConfig::default();

        assert_eq!(
            config.max_session_duration,
            Duration::from_secs(2 * 60 * 60)
        ); // 2 hours
        assert_eq!(config.max_messages_per_session, 1000);
        assert_eq!(config.session_timeout, Duration::from_secs(30 * 60)); // 30 minutes
    }

    /// Verify custom configuration can be created.
    #[test]
    fn test_custom_config() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_secs(60 * 60), // 1 hour
            max_messages_per_session: 500,
            session_timeout: Duration::from_secs(15 * 60), // 15 minutes
        };

        assert_eq!(config.max_session_duration, Duration::from_secs(60 * 60));
        assert_eq!(config.max_messages_per_session, 500);
        assert_eq!(config.session_timeout, Duration::from_secs(15 * 60));
    }
}

// ============================================================================
// SessionLifecycleManager Tests
// ============================================================================

mod session_lifecycle_manager_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that sessions can be started and tracked.
    #[tokio::test]
    async fn test_start_session() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("session-1".to_string()).unwrap();

        let result = manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await;

        assert!(result.is_ok());

        let info = manager.get_session_info(&session_id).await;
        assert!(info.is_some());
        assert_eq!(info.unwrap().consumer_id(), "worker-1");
    }

    /// Verify that starting same session twice fails.
    #[tokio::test]
    async fn test_start_session_twice_fails() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("duplicate".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        let result = manager
            .start_session(session_id.clone(), "worker-2".to_string())
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::ValidationError(_)
        ));
    }

    /// Verify that sessions can be stopped.
    #[tokio::test]
    async fn test_stop_session() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("stoppable".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert_eq!(manager.session_count().await, 1);

        let result = manager.stop_session(&session_id).await;
        assert!(result.is_ok());

        assert_eq!(manager.session_count().await, 0);
    }

    /// Verify that stopping nonexistent session fails.
    #[tokio::test]
    async fn test_stop_nonexistent_session_fails() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("nonexistent".to_string()).unwrap();

        let result = manager.stop_session(&session_id).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionNotFound { .. }
        ));
    }

    /// Verify that message processing is recorded.
    #[tokio::test]
    async fn test_record_message() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("active".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        manager.record_message(&session_id).await.unwrap();
        manager.record_message(&session_id).await.unwrap();

        let info = manager.get_session_info(&session_id).await.unwrap();
        assert_eq!(info.message_count(), 2);
    }

    /// Verify that recording message for nonexistent session fails.
    #[tokio::test]
    async fn test_record_message_nonexistent_fails() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("nonexistent".to_string()).unwrap();

        let result = manager.record_message(&session_id).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            QueueError::SessionNotFound { .. }
        ));
    }

    /// Verify that touch_session updates activity.
    #[tokio::test]
    async fn test_touch_session() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("touched".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        sleep(Duration::from_millis(50)).await;
        let info_before = manager.get_session_info(&session_id).await.unwrap();
        let idle_before = info_before.idle_time();

        manager.touch_session(&session_id).await.unwrap();

        let info_after = manager.get_session_info(&session_id).await.unwrap();
        let idle_after = info_after.idle_time();

        assert!(idle_after < idle_before);
        assert_eq!(info_after.message_count(), 0); // Touch doesn't increment count
    }

    /// Verify that session exceeding duration limit should be closed.
    #[tokio::test]
    async fn test_should_close_session_duration_limit() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_millis(50),
            max_messages_per_session: 1000,
            session_timeout: Duration::from_secs(60),
        };
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("long-running".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert!(!manager.should_close_session(&session_id).await);

        sleep(Duration::from_millis(60)).await;

        assert!(manager.should_close_session(&session_id).await);
    }

    /// Verify that session exceeding message count limit should be closed.
    #[tokio::test]
    async fn test_should_close_session_message_limit() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_secs(60),
            max_messages_per_session: 3,
            session_timeout: Duration::from_secs(60),
        };
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("busy".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Process messages up to limit
        manager.record_message(&session_id).await.unwrap();
        manager.record_message(&session_id).await.unwrap();
        manager.record_message(&session_id).await.unwrap();

        assert!(!manager.should_close_session(&session_id).await);

        // One more exceeds limit
        manager.record_message(&session_id).await.unwrap();

        assert!(manager.should_close_session(&session_id).await);
    }

    /// Verify that session exceeding timeout should be closed.
    #[tokio::test]
    async fn test_should_close_session_timeout() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_secs(60),
            max_messages_per_session: 1000,
            session_timeout: Duration::from_millis(50),
        };
        let manager = SessionLifecycleManager::new(config);

        let session_id = SessionId::new("idle".to_string()).unwrap();

        manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert!(!manager.should_close_session(&session_id).await);

        sleep(Duration::from_millis(60)).await;

        assert!(manager.should_close_session(&session_id).await);
    }

    /// Verify that get_sessions_to_close returns sessions exceeding limits.
    #[tokio::test]
    async fn test_get_sessions_to_close() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_millis(50),
            max_messages_per_session: 2,
            session_timeout: Duration::from_millis(50),
        };
        let manager = SessionLifecycleManager::new(config);

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();
        let session3 = SessionId::new("session-3".to_string()).unwrap();

        // Session 1: will exceed duration
        manager
            .start_session(session1.clone(), "worker-1".to_string())
            .await
            .unwrap();

        sleep(Duration::from_millis(30)).await;

        // Session 2: will exceed message count
        manager
            .start_session(session2.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager.record_message(&session2).await.unwrap();
        manager.record_message(&session2).await.unwrap();
        manager.record_message(&session2).await.unwrap();

        // Session 3: stays healthy
        manager
            .start_session(session3.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager.record_message(&session3).await.unwrap();

        sleep(Duration::from_millis(30)).await;

        let to_close = manager.get_sessions_to_close().await;

        assert_eq!(to_close.len(), 2);
        assert!(to_close.contains(&session1)); // Exceeded duration
        assert!(to_close.contains(&session2)); // Exceeded message count
        assert!(!to_close.contains(&session3)); // Still healthy
    }

    /// Verify that cleanup_expired_sessions removes sessions exceeding limits.
    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let config = SessionLifecycleConfig {
            max_session_duration: Duration::from_millis(50),
            max_messages_per_session: 1000,
            session_timeout: Duration::from_millis(50),
        };
        let manager = SessionLifecycleManager::new(config);

        let expired1 = SessionId::new("expired-1".to_string()).unwrap();
        let expired2 = SessionId::new("expired-2".to_string()).unwrap();
        let active = SessionId::new("active".to_string()).unwrap();

        // Create sessions
        manager
            .start_session(expired1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager
            .start_session(expired2.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Wait for expiration
        sleep(Duration::from_millis(60)).await;

        // Create active session
        manager
            .start_session(active.clone(), "worker-1".to_string())
            .await
            .unwrap();

        assert_eq!(manager.session_count().await, 3);

        let cleaned = manager.cleanup_expired_sessions().await;

        assert_eq!(cleaned.len(), 2);
        assert!(cleaned.contains(&expired1));
        assert!(cleaned.contains(&expired2));
        assert!(!cleaned.contains(&active));

        assert_eq!(manager.session_count().await, 1);
    }

    /// Verify that session_count returns correct count.
    #[tokio::test]
    async fn test_session_count() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        assert_eq!(manager.session_count().await, 0);

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        manager
            .start_session(session1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager
            .start_session(session2.clone(), "worker-2".to_string())
            .await
            .unwrap();

        assert_eq!(manager.session_count().await, 2);

        manager.stop_session(&session1).await.unwrap();

        assert_eq!(manager.session_count().await, 1);
    }

    /// Verify that get_active_sessions returns all session IDs.
    #[tokio::test]
    async fn test_get_active_sessions() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();

        manager
            .start_session(session1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager
            .start_session(session2.clone(), "worker-2".to_string())
            .await
            .unwrap();

        let active = manager.get_active_sessions().await;

        assert_eq!(active.len(), 2);
        assert!(active.contains(&session1));
        assert!(active.contains(&session2));
    }

    /// Verify that get_consumer_sessions returns sessions for specific consumer.
    #[tokio::test]
    async fn test_get_consumer_sessions() {
        let config = SessionLifecycleConfig::default();
        let manager = SessionLifecycleManager::new(config);

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();
        let session3 = SessionId::new("session-3".to_string()).unwrap();

        manager
            .start_session(session1.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager
            .start_session(session2.clone(), "worker-1".to_string())
            .await
            .unwrap();
        manager
            .start_session(session3.clone(), "worker-2".to_string())
            .await
            .unwrap();

        let worker1_sessions = manager.get_consumer_sessions("worker-1").await;
        assert_eq!(worker1_sessions.len(), 2);
        assert!(worker1_sessions.contains(&session1));
        assert!(worker1_sessions.contains(&session2));

        let worker2_sessions = manager.get_consumer_sessions("worker-2").await;
        assert_eq!(worker2_sessions.len(), 1);
        assert!(worker2_sessions.contains(&session3));
    }
}

// ============================================================================
// Integration Tests: Concurrent Session Access and Ordering
// ============================================================================

mod integration_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    /// Verify that lock and affinity work together for session exclusivity.
    #[tokio::test]
    async fn test_lock_and_affinity_integration() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));
        let session_id = SessionId::new("integrated-session".to_string()).unwrap();

        // Consumer 1 acquires lock
        let lock1 = lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        assert!(!lock1.is_expired());

        // Consumer 1 establishes affinity
        let affinity1 = affinity_tracker
            .assign_session(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        assert_eq!(affinity1.consumer_id(), "consumer-1");

        // Consumer 2 cannot acquire lock (locked by consumer 1)
        let result = lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(result.is_err());

        // Consumer 2 cannot establish affinity (already assigned to consumer 1)
        let result = affinity_tracker
            .assign_session(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(result.is_err());

        // Release lock and affinity
        lock_manager
            .release_lock(&session_id, "consumer-1")
            .await
            .unwrap();
        affinity_tracker
            .release_session(&session_id, "consumer-1")
            .await
            .unwrap();

        // Now consumer 2 can acquire both
        let lock2 = lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await
            .unwrap();
        assert!(!lock2.is_expired());

        let affinity2 = affinity_tracker
            .assign_session(session_id.clone(), "consumer-2".to_string())
            .await
            .unwrap();
        assert_eq!(affinity2.consumer_id(), "consumer-2");
    }

    /// Verify concurrent access to different sessions.
    #[tokio::test]
    async fn test_concurrent_access_different_sessions() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));

        let session1 = SessionId::new("session-1".to_string()).unwrap();
        let session2 = SessionId::new("session-2".to_string()).unwrap();
        let session3 = SessionId::new("session-3".to_string()).unwrap();

        // Spawn concurrent tasks for different sessions
        let lock_mgr1 = Arc::clone(&lock_manager);
        let affinity1 = Arc::clone(&affinity_tracker);
        let s1 = session1.clone();
        let handle1 = tokio::spawn(async move {
            lock_mgr1
                .try_acquire_lock(s1.clone(), "worker-1".to_string())
                .await
                .unwrap();
            affinity1
                .assign_session(s1, "worker-1".to_string())
                .await
                .unwrap();
        });

        let lock_mgr2 = Arc::clone(&lock_manager);
        let affinity2 = Arc::clone(&affinity_tracker);
        let s2 = session2.clone();
        let handle2 = tokio::spawn(async move {
            lock_mgr2
                .try_acquire_lock(s2.clone(), "worker-2".to_string())
                .await
                .unwrap();
            affinity2
                .assign_session(s2, "worker-2".to_string())
                .await
                .unwrap();
        });

        let lock_mgr3 = Arc::clone(&lock_manager);
        let affinity3 = Arc::clone(&affinity_tracker);
        let s3 = session3.clone();
        let handle3 = tokio::spawn(async move {
            lock_mgr3
                .try_acquire_lock(s3.clone(), "worker-3".to_string())
                .await
                .unwrap();
            affinity3
                .assign_session(s3, "worker-3".to_string())
                .await
                .unwrap();
        });

        // All should succeed
        handle1.await.unwrap();
        handle2.await.unwrap();
        handle3.await.unwrap();

        // Verify all sessions are locked and have affinity
        assert!(lock_manager.is_locked(&session1).await);
        assert!(lock_manager.is_locked(&session2).await);
        assert!(lock_manager.is_locked(&session3).await);

        assert_eq!(
            affinity_tracker.get_consumer(&session1).await,
            Some("worker-1".to_string())
        );
        assert_eq!(
            affinity_tracker.get_consumer(&session2).await,
            Some("worker-2".to_string())
        );
        assert_eq!(
            affinity_tracker.get_consumer(&session3).await,
            Some("worker-3".to_string())
        );
    }

    /// Verify lifecycle management with locks and affinity.
    #[tokio::test]
    async fn test_lifecycle_with_locks_and_affinity() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));
        let lifecycle_config = SessionLifecycleConfig {
            max_session_duration: Duration::from_secs(60),
            max_messages_per_session: 10,
            session_timeout: Duration::from_secs(30),
        };
        let lifecycle_manager = Arc::new(SessionLifecycleManager::new(lifecycle_config));

        let session_id = SessionId::new("managed-session".to_string()).unwrap();

        // Start session lifecycle
        lifecycle_manager
            .start_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Acquire lock and affinity
        lock_manager
            .try_acquire_lock(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();
        affinity_tracker
            .assign_session(session_id.clone(), "worker-1".to_string())
            .await
            .unwrap();

        // Process messages
        for _ in 0..5 {
            lifecycle_manager.record_message(&session_id).await.unwrap();
            lock_manager
                .renew_lock(&session_id, "worker-1", None)
                .await
                .unwrap();
            affinity_tracker.touch_session(&session_id).await.unwrap();
        }

        // Verify session is active
        assert!(!lifecycle_manager.should_close_session(&session_id).await);
        assert!(lock_manager.is_locked(&session_id).await);
        assert!(affinity_tracker.has_affinity(&session_id).await);

        // Clean up
        lock_manager
            .release_lock(&session_id, "worker-1")
            .await
            .unwrap();
        affinity_tracker
            .release_session(&session_id, "worker-1")
            .await
            .unwrap();
        lifecycle_manager.stop_session(&session_id).await.unwrap();
    }

    /// Verify session recovery after lock expiration.
    #[tokio::test]
    async fn test_session_recovery_after_lock_expiration() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_millis(50)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_millis(100)));
        let session_id = SessionId::new("recovery-session".to_string()).unwrap();

        // Consumer 1 acquires lock and affinity
        lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        affinity_tracker
            .assign_session(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        // Wait for lock to expire (but not affinity)
        sleep(Duration::from_millis(60)).await;

        // Lock expired, so consumer 2 can acquire it
        let lock = lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(lock.is_ok());

        // But affinity still belongs to consumer 1
        assert_eq!(
            affinity_tracker.get_consumer(&session_id).await,
            Some("consumer-1".to_string())
        );

        // Consumer 2 cannot reassign affinity (still active for consumer 1)
        let result = affinity_tracker
            .assign_session(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(result.is_err());

        // Wait for affinity to expire too
        sleep(Duration::from_millis(50)).await;

        // Now consumer 2 can establish affinity
        let affinity = affinity_tracker
            .assign_session(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(affinity.is_ok());
        assert_eq!(affinity.unwrap().consumer_id(), "consumer-2");
    }

    /// Verify ordered processing with session locks.
    #[tokio::test]
    async fn test_ordered_processing_with_locks() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let session_id = SessionId::new("ordered-session".to_string()).unwrap();
        let processed_order = Arc::new(tokio::sync::Mutex::new(Vec::new()));

        // Consumer 1 processes messages in order
        let lock_mgr1 = Arc::clone(&lock_manager);
        let session1 = session_id.clone();
        let order1 = Arc::clone(&processed_order);
        let handle1 = tokio::spawn(async move {
            // Acquire lock
            lock_mgr1
                .try_acquire_lock(session1.clone(), "consumer-1".to_string())
                .await
                .unwrap();

            // Process messages 1-3
            for i in 1..=3 {
                order1.lock().await.push(format!("consumer-1-msg-{}", i));
                sleep(Duration::from_millis(10)).await;
            }

            // Release lock
            lock_mgr1
                .release_lock(&session1, "consumer-1")
                .await
                .unwrap();
        });

        // Wait for consumer 1 to start
        sleep(Duration::from_millis(5)).await;

        // Consumer 2 tries to process but must wait for lock
        let lock_mgr2 = Arc::clone(&lock_manager);
        let session2 = session_id.clone();
        let order2 = Arc::clone(&processed_order);
        let handle2 = tokio::spawn(async move {
            // Try to acquire lock (will fail initially)
            while lock_mgr2
                .try_acquire_lock(session2.clone(), "consumer-2".to_string())
                .await
                .is_err()
            {
                sleep(Duration::from_millis(5)).await;
            }

            // Process messages 4-6
            for i in 4..=6 {
                order2.lock().await.push(format!("consumer-2-msg-{}", i));
                sleep(Duration::from_millis(10)).await;
            }

            lock_mgr2
                .release_lock(&session2, "consumer-2")
                .await
                .unwrap();
        });

        // Wait for both to complete
        handle1.await.unwrap();
        handle2.await.unwrap();

        // Verify processing order: consumer 1 completed all before consumer 2 started
        let order = processed_order.lock().await;
        assert_eq!(order.len(), 6);

        // First 3 should be from consumer 1
        assert_eq!(order[0], "consumer-1-msg-1");
        assert_eq!(order[1], "consumer-1-msg-2");
        assert_eq!(order[2], "consumer-1-msg-3");

        // Next 3 should be from consumer 2
        assert_eq!(order[3], "consumer-2-msg-4");
        assert_eq!(order[4], "consumer-2-msg-5");
        assert_eq!(order[5], "consumer-2-msg-6");
    }

    /// Verify high concurrency stress test with multiple sessions and consumers.
    #[tokio::test]
    async fn test_high_concurrency_multiple_sessions() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));

        let num_sessions = 20;
        let num_consumers = 5;

        let mut handles = vec![];

        // Create concurrent tasks for multiple sessions
        for session_num in 0..num_sessions {
            let consumer_id = format!("worker-{}", session_num % num_consumers);
            let session_id = SessionId::new(format!("session-{}", session_num)).unwrap();

            let lock_mgr = Arc::clone(&lock_manager);
            let affinity = Arc::clone(&affinity_tracker);

            let handle = tokio::spawn(async move {
                // Try to acquire lock
                let lock_result = lock_mgr
                    .try_acquire_lock(session_id.clone(), consumer_id.clone())
                    .await;

                if lock_result.is_ok() {
                    // Try to establish affinity
                    let affinity_result = affinity
                        .assign_session(session_id.clone(), consumer_id.clone())
                        .await;

                    if affinity_result.is_ok() {
                        // Simulate some work
                        sleep(Duration::from_millis(5)).await;

                        // Release
                        let _ = affinity.release_session(&session_id, &consumer_id).await;
                        let _ = lock_mgr.release_lock(&session_id, &consumer_id).await;

                        return true;
                    }
                }
                false
            });

            handles.push(handle);
        }

        // Wait for all to complete
        let mut successes = 0;
        for handle in handles {
            if handle.await.unwrap() {
                successes += 1;
            }
        }

        // All should succeed since they're different sessions
        assert_eq!(successes, num_sessions);

        // Verify all were cleaned up
        assert_eq!(lock_manager.lock_count().await, 0);
        assert_eq!(affinity_tracker.affinity_count().await, 0);
    }

    /// Verify session cleanup with lifecycle, locks, and affinity.
    #[tokio::test]
    async fn test_integrated_cleanup() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_millis(50)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_millis(50)));
        let lifecycle_config = SessionLifecycleConfig {
            max_session_duration: Duration::from_millis(50),
            max_messages_per_session: 1000,
            session_timeout: Duration::from_millis(50),
        };
        let lifecycle_manager = Arc::new(SessionLifecycleManager::new(lifecycle_config));

        // Create multiple sessions
        for i in 0..5 {
            let session_id = SessionId::new(format!("cleanup-{}", i)).unwrap();

            lifecycle_manager
                .start_session(session_id.clone(), format!("worker-{}", i))
                .await
                .unwrap();

            lock_manager
                .try_acquire_lock(session_id.clone(), format!("worker-{}", i))
                .await
                .unwrap();

            affinity_tracker
                .assign_session(session_id.clone(), format!("worker-{}", i))
                .await
                .unwrap();
        }

        // Verify all are active
        assert_eq!(lifecycle_manager.session_count().await, 5);
        assert_eq!(lock_manager.lock_count().await, 5);
        assert_eq!(affinity_tracker.affinity_count().await, 5);

        // Wait for expiration
        sleep(Duration::from_millis(60)).await;

        // Cleanup all components
        let expired_sessions = lifecycle_manager.cleanup_expired_sessions().await;
        let expired_locks = lock_manager.cleanup_expired_locks().await;
        let expired_affinities = affinity_tracker.cleanup_expired().await;

        // All should be cleaned up
        assert_eq!(expired_sessions.len(), 5);
        assert_eq!(expired_locks, 5);
        assert_eq!(expired_affinities, 5);

        assert_eq!(lifecycle_manager.session_count().await, 0);
        assert_eq!(lock_manager.lock_count().await, 0);
        assert_eq!(affinity_tracker.affinity_count().await, 0);
    }

    /// Verify consumer can't bypass affinity even with valid lock.
    #[tokio::test]
    async fn test_affinity_enforcement() {
        let lock_manager = Arc::new(SessionLockManager::new(Duration::from_secs(30)));
        let affinity_tracker = Arc::new(SessionAffinityTracker::new(Duration::from_secs(60)));
        let session_id = SessionId::new("enforced-session".to_string()).unwrap();

        // Consumer 1 establishes lock and affinity
        lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();
        affinity_tracker
            .assign_session(session_id.clone(), "consumer-1".to_string())
            .await
            .unwrap();

        // Consumer 1 releases lock but keeps affinity
        lock_manager
            .release_lock(&session_id, "consumer-1")
            .await
            .unwrap();

        // Consumer 2 can acquire lock (it's free)
        let lock = lock_manager
            .try_acquire_lock(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(lock.is_ok());

        // But consumer 2 cannot establish affinity (still belongs to consumer 1)
        let affinity = affinity_tracker
            .assign_session(session_id.clone(), "consumer-2".to_string())
            .await;
        assert!(affinity.is_err());

        // Verify affinity still belongs to consumer 1
        assert_eq!(
            affinity_tracker.get_consumer(&session_id).await,
            Some("consumer-1".to_string())
        );
    }
}
