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

// ============================================================================
// Complete variant coverage for is_transient()
// ============================================================================

mod transience_tests {
    use super::*;

    #[test]
    fn message_not_found_is_not_transient() {
        let err = QueueError::MessageNotFound {
            receipt: "receipt-123".to_string(),
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn invalid_receipt_is_not_transient() {
        let err = QueueError::InvalidReceipt {
            receipt: "stale-receipt".to_string(),
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn session_not_found_is_not_transient() {
        let err = QueueError::SessionNotFound {
            session_id: "session-xyz".to_string(),
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn timeout_is_transient() {
        let err = QueueError::Timeout {
            duration: Duration::seconds(30),
        };
        assert!(err.is_transient());
        assert!(err.should_retry());
    }

    #[test]
    fn authentication_failed_is_not_transient() {
        let err = QueueError::AuthenticationFailed {
            message: "invalid credentials".to_string(),
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn permission_denied_is_not_transient() {
        let err = QueueError::PermissionDenied {
            operation: "send_message".to_string(),
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn batch_too_large_is_not_transient() {
        let err = QueueError::BatchTooLarge {
            size: 200,
            max_size: 100,
        };
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn provider_error_is_transient() {
        // Provider errors are classified as transient because most cloud API
        // errors (throttling, 5xx) should be retried. Permanent provider
        // errors should be mapped to specific QueueError variants instead.
        let err = QueueError::ProviderError {
            provider: "TestProvider".to_string(),
            code: "THROTTLED".to_string(),
            message: "request throttled".to_string(),
        };
        assert!(err.is_transient());
        assert!(err.should_retry());
    }

    #[test]
    fn serialization_error_is_not_transient() {
        let err = QueueError::SerializationError(crate::error::SerializationError::InvalidUtf8);
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn configuration_error_is_not_transient() {
        let err = QueueError::ConfigurationError(crate::error::ConfigurationError::Invalid {
            message: "missing required field".to_string(),
        });
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }

    #[test]
    fn validation_error_is_not_transient() {
        let err = QueueError::ValidationError(crate::error::ValidationError::Required {
            field: "queue_name".to_string(),
        });
        assert!(!err.is_transient());
        assert!(!err.should_retry());
    }
}

// ============================================================================
// Complete retry_after() coverage
// ============================================================================

mod retry_after_tests {
    use super::*;

    #[test]
    fn timeout_suggests_one_second_delay() {
        let err = QueueError::Timeout {
            duration: Duration::seconds(30),
        };
        assert_eq!(err.retry_after(), Some(Duration::seconds(1)));
    }

    #[test]
    fn connection_failed_suggests_five_second_delay() {
        let err = QueueError::ConnectionFailed {
            message: "tcp reset".to_string(),
        };
        assert_eq!(err.retry_after(), Some(Duration::seconds(5)));
    }

    #[test]
    fn provider_error_has_no_suggested_delay() {
        let err = QueueError::ProviderError {
            provider: "TestProvider".to_string(),
            code: "500".to_string(),
            message: "internal server error".to_string(),
        };
        // Provider errors are transient but have no prescribed delay —
        // callers should apply their own backoff strategy.
        assert_eq!(err.retry_after(), None);
    }

    #[test]
    fn non_transient_errors_have_no_delay() {
        let cases: Vec<QueueError> = vec![
            QueueError::QueueNotFound {
                queue_name: "q".to_string(),
            },
            QueueError::MessageNotFound {
                receipt: "r".to_string(),
            },
            QueueError::InvalidReceipt {
                receipt: "r".to_string(),
            },
            QueueError::SessionNotFound {
                session_id: "s".to_string(),
            },
            QueueError::AuthenticationFailed {
                message: "m".to_string(),
            },
            QueueError::PermissionDenied {
                operation: "op".to_string(),
            },
            QueueError::MessageTooLarge {
                size: 10,
                max_size: 5,
            },
            QueueError::BatchTooLarge {
                size: 20,
                max_size: 10,
            },
        ];
        for err in cases {
            assert_eq!(
                err.retry_after(),
                None,
                "expected no retry delay for: {:?}",
                err
            );
        }
    }
}
