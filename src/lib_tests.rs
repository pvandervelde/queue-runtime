//! Tests for the queue-runtime library module.

use super::*;

#[test]
fn test_queue_name_validation() {
    // Valid names
    assert!(QueueName::new("test-queue".to_string()).is_ok());
    assert!(QueueName::new("queue_123".to_string()).is_ok());
    assert!(QueueName::new("a".to_string()).is_ok());

    // Invalid names
    assert!(QueueName::new("".to_string()).is_err());
    assert!(QueueName::new("-leading-hyphen".to_string()).is_err());
    assert!(QueueName::new("trailing-hyphen-".to_string()).is_err());
    assert!(QueueName::new("double--hyphen".to_string()).is_err());
    assert!(QueueName::new("special@chars".to_string()).is_err());
}

#[test]
fn test_session_id_validation() {
    // Valid session IDs
    assert!(SessionId::new("session-123".to_string()).is_ok());
    assert!(SessionId::new("owner/repo/pull_request/123".to_string()).is_ok());

    // Invalid session IDs
    assert!(SessionId::new("".to_string()).is_err());
    assert!(SessionId::new("a".repeat(129)).is_err());
    assert!(SessionId::new("control\x00char".to_string()).is_err());
}

#[test]
fn test_message_id_generation() {
    let id1 = MessageId::new();
    let id2 = MessageId::new();
    assert_ne!(id1, id2);
    assert!(!id1.as_str().is_empty());
}

#[test]
fn test_message_builder() {
    let session_id = SessionId::new("test-session".to_string()).unwrap();
    let message = Message::new("test body".into())
        .with_session_id(session_id.clone())
        .with_attribute("key".to_string(), "value".to_string())
        .with_correlation_id("corr-123".to_string())
        .with_ttl(Duration::minutes(30));

    assert_eq!(message.session_id, Some(session_id));
    assert_eq!(message.attributes.get("key"), Some(&"value".to_string()));
    assert_eq!(message.correlation_id, Some("corr-123".to_string()));
    assert_eq!(message.time_to_live, Some(Duration::minutes(30)));
}

#[test]
fn test_receipt_handle_expiry() {
    let expires_at = Timestamp::from_datetime(Utc::now() + Duration::minutes(5));
    let receipt = ReceiptHandle::new(
        "test-receipt".to_string(),
        expires_at,
        ProviderType::InMemory,
    );

    assert!(!receipt.is_expired());
    assert!(receipt.time_until_expiry() > Duration::minutes(4));
}

#[test]
fn test_provider_capabilities() {
    assert_eq!(
        ProviderType::AzureServiceBus.supports_sessions(),
        SessionSupport::Native
    );
    assert_eq!(
        ProviderType::AwsSqs.supports_sessions(),
        SessionSupport::Emulated
    );
    assert!(ProviderType::InMemory.supports_batching());
}

#[test]
fn test_error_transience() {
    assert!(QueueError::SessionLocked {
        session_id: "test".to_string(),
        locked_until: Timestamp::now(),
    }
    .is_transient());

    assert!(!QueueError::QueueNotFound {
        queue_name: "test".to_string(),
    }
    .is_transient());

    assert!(QueueError::ConnectionFailed {
        message: "network error".to_string(),
    }
    .is_transient());
}
