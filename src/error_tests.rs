//! Tests for error types.

use super::*;

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

    assert!(!QueueError::MessageTooLarge {
        size: 1000,
        max_size: 500
    }
    .is_transient());
}

#[test]
fn test_retry_suggestions() {
    let session_locked = QueueError::SessionLocked {
        session_id: "test".to_string(),
        locked_until: Timestamp::now(),
    };
    assert_eq!(session_locked.retry_after(), Some(Duration::seconds(5)));

    let not_found = QueueError::QueueNotFound {
        queue_name: "test".to_string(),
    };
    assert_eq!(not_found.retry_after(), None);
}
