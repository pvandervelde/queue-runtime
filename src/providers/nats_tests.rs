//! Tests for the NATS queue provider.
//!
//! These tests verify configuration, naming logic, header encoding/decoding,
//! and error-handling paths that do not require a live NATS server.
//! Integration tests that need a server should live in a separate suite.

use super::*;
use crate::provider::NatsConfig;
use chrono::Duration;

// ============================================================================
// Configuration tests
// ============================================================================

mod config_tests {
    use super::*;

    /// Verify that the default configuration has sensible values.
    #[test]
    fn test_default_config_values() {
        let config = NatsConfig::default();
        assert_eq!(config.url, "nats://localhost:4222");
        assert_eq!(config.stream_prefix, "queue-runtime");
        assert_eq!(config.max_deliver, Some(3));
        assert_eq!(config.ack_wait, Duration::seconds(30));
        assert!(config.enable_dead_letter);
        assert_eq!(
            config.dead_letter_subject_prefix,
            Some("dlq".to_string())
        );
        assert!(config.credentials_path.is_none());
    }

    /// Verify that the default session lock duration is sensible.
    #[test]
    fn test_default_session_lock_duration() {
        let config = NatsConfig::default();
        assert_eq!(config.session_lock_duration, Duration::minutes(5));
    }

    /// Verify custom configuration can be constructed.
    #[test]
    fn test_custom_config() {
        let config = NatsConfig {
            url: "nats://user:pass@nats.example.com:4222".to_string(),
            stream_prefix: "myapp".to_string(),
            max_deliver: Some(5),
            ack_wait: Duration::seconds(60),
            session_lock_duration: Duration::minutes(10),
            enable_dead_letter: false,
            dead_letter_subject_prefix: None,
            credentials_path: Some("/etc/nats/app.creds".to_string()),
        };

        assert_eq!(config.stream_prefix, "myapp");
        assert_eq!(config.max_deliver, Some(5));
        assert!(!config.enable_dead_letter);
    }

    /// Verify that the provider type is correct.
    #[test]
    fn test_provider_type() {
        assert_eq!(ProviderType::Nats.max_message_size(), 1024 * 1024);
        assert!(ProviderType::Nats.supports_batching());
        assert_eq!(
            ProviderType::Nats.supports_sessions(),
            crate::provider::SessionSupport::Emulated
        );
    }
}

// ============================================================================
// Naming helper tests
// ============================================================================

mod naming_tests {
    use super::*;

    fn default_config() -> NatsConfig {
        NatsConfig::default()
    }

    /// Verify that queue subjects use the expected format.
    #[test]
    fn test_queue_subject_format() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let subject = queue_subject(&config, &queue);
        assert_eq!(subject, "queue_runtime.my_queue");
    }

    /// Verify that session subjects use the expected format.
    #[test]
    fn test_session_subject_format() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let session = SessionId::new("session-123".to_string()).unwrap();
        let subject = session_subject(&config, &queue, &session);
        assert_eq!(subject, "queue_runtime.my_queue.session.session_123");
    }

    /// Verify that session subjects with slashes are sanitised.
    #[test]
    fn test_session_subject_sanitises_slashes() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let session = SessionId::new("owner/repo/pr/42".to_string()).unwrap();
        let subject = session_subject(&config, &queue, &session);
        assert!(!subject.contains('/'));
        assert!(subject.contains("session."));
    }

    /// Verify that stream names use the expected format.
    #[test]
    fn test_stream_name_format() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let name = stream_name(&config, &queue);
        assert_eq!(name, "queue_runtime-my_queue");
        // Stream names must not contain dots
        assert!(!name.contains('.'));
    }

    /// Verify that dead letter subject uses the expected format.
    #[test]
    fn test_dead_letter_subject_format() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let subject = dead_letter_subject(&config, &queue);
        assert_eq!(subject, Some("dlq.my_queue".to_string()));
    }

    /// Verify that dead letter subject is None when DLQ is disabled.
    #[test]
    fn test_dead_letter_subject_disabled() {
        let config = NatsConfig {
            enable_dead_letter: false,
            ..NatsConfig::default()
        };
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let subject = dead_letter_subject(&config, &queue);
        assert!(subject.is_none());
    }

    /// Verify that dead letter subject is None when prefix is not set.
    #[test]
    fn test_dead_letter_subject_no_prefix() {
        let config = NatsConfig {
            enable_dead_letter: true,
            dead_letter_subject_prefix: None,
            ..NatsConfig::default()
        };
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let subject = dead_letter_subject(&config, &queue);
        assert!(subject.is_none());
    }

    /// Verify that NATS-safe name transformation works correctly.
    #[test]
    fn test_nats_safe_transformation() {
        assert_eq!(nats_safe("my-name"), "my_name");
        assert_eq!(nats_safe("my name"), "my_name");
        assert_eq!(nats_safe("already_safe"), "already_safe");
        assert_eq!(nats_safe("multi-word-name"), "multi_word_name");
    }

    /// Verify that different queues produce different stream names.
    #[test]
    fn test_different_queues_different_streams() {
        let config = default_config();
        let q1 = QueueName::new("queue-one".to_string()).unwrap();
        let q2 = QueueName::new("queue-two".to_string()).unwrap();
        assert_ne!(stream_name(&config, &q1), stream_name(&config, &q2));
    }

    /// Verify that different sessions produce different subjects.
    #[test]
    fn test_different_sessions_different_subjects() {
        let config = default_config();
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let s1 = SessionId::new("session-1".to_string()).unwrap();
        let s2 = SessionId::new("session-2".to_string()).unwrap();
        assert_ne!(
            session_subject(&config, &queue, &s1),
            session_subject(&config, &queue, &s2)
        );
    }
}

// ============================================================================
// Header encode/decode tests
// ============================================================================

mod header_tests {
    use super::*;

    /// Verify that attributes are encoded into NATS headers and decoded back.
    #[test]
    fn test_attribute_roundtrip() {
        let mut message = Message::new(bytes::Bytes::from("test body"));
        message = message.with_attribute("color".to_string(), "blue".to_string());
        message = message.with_attribute("size".to_string(), "large".to_string());

        let headers = NatsProvider::build_headers(&message);

        // Re-wrap in Option as the extract functions expect
        let opt_headers = Some(headers);
        let attrs = NatsProvider::extract_attributes(&opt_headers);

        assert_eq!(attrs.get("color").map(String::as_str), Some("blue"));
        assert_eq!(attrs.get("size").map(String::as_str), Some("large"));
    }

    /// Verify that session ID is encoded and decoded correctly.
    #[test]
    fn test_session_id_header_roundtrip() {
        let session = SessionId::new("test-session".to_string()).unwrap();
        let message = Message::new(bytes::Bytes::from("body"))
            .with_session_id(session.clone());

        let headers = NatsProvider::build_headers(&message);
        let opt_headers = Some(headers);
        let extracted = NatsProvider::extract_session_id(&opt_headers);

        assert_eq!(extracted, Some(session));
    }

    /// Verify that session ID is absent when not set.
    #[test]
    fn test_no_session_id_when_none() {
        let message = Message::new(bytes::Bytes::from("body"));
        let headers = NatsProvider::build_headers(&message);
        let opt_headers = Some(headers);
        let extracted = NatsProvider::extract_session_id(&opt_headers);
        assert!(extracted.is_none());
    }

    /// Verify that correlation ID is encoded and decoded correctly.
    #[test]
    fn test_correlation_id_header_roundtrip() {
        let message = Message::new(bytes::Bytes::from("body"))
            .with_correlation_id("corr-xyz".to_string());

        let headers = NatsProvider::build_headers(&message);
        let opt_headers = Some(headers);
        let extracted = NatsProvider::extract_correlation_id(&opt_headers);

        assert_eq!(extracted, Some("corr-xyz".to_string()));
    }

    /// Verify that correlation ID is None when not set.
    #[test]
    fn test_no_correlation_id_when_none() {
        let message = Message::new(bytes::Bytes::from("body"));
        let headers = NatsProvider::build_headers(&message);
        let opt_headers = Some(headers);
        let extracted = NatsProvider::extract_correlation_id(&opt_headers);
        assert!(extracted.is_none());
    }

    /// Verify that provider headers are not returned as user attributes.
    #[test]
    fn test_provider_headers_not_in_attributes() {
        let session = SessionId::new("s1".to_string()).unwrap();
        let message = Message::new(bytes::Bytes::from("body"))
            .with_session_id(session)
            .with_correlation_id("corr-1".to_string())
            .with_attribute("my-key".to_string(), "my-value".to_string());

        let headers = NatsProvider::build_headers(&message);
        let opt_headers = Some(headers);
        let attrs = NatsProvider::extract_attributes(&opt_headers);

        // Provider headers must not appear as user attributes
        assert!(!attrs.contains_key("x-session-id"));
        assert!(!attrs.contains_key("x-correlation-id"));
        // User attribute prefixed with x-attr- must be accessible without prefix
        assert_eq!(attrs.get("my-key").map(String::as_str), Some("my-value"));
    }

    /// Verify extraction from None headers returns empty map / None.
    #[test]
    fn test_extract_from_none_headers() {
        let attrs = NatsProvider::extract_attributes(&None);
        assert!(attrs.is_empty());

        let session = NatsProvider::extract_session_id(&None);
        assert!(session.is_none());

        let corr = NatsProvider::extract_correlation_id(&None);
        assert!(corr.is_none());
    }
}

// ============================================================================
// Error conversion tests
// ============================================================================

mod error_tests {
    use super::*;

    /// Verify that NatsError converts to a provider QueueError.
    #[test]
    fn test_error_conversion() {
        let err = NatsError::new("connection refused");
        let queue_err = err.to_queue_error();

        match queue_err {
            QueueError::ProviderError { provider, code, message } => {
                assert_eq!(provider, "nats");
                assert_eq!(code, "NATS_ERROR");
                assert!(message.contains("connection refused"));
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    /// Verify that NatsError implements Display.
    #[test]
    fn test_error_display() {
        let err = NatsError::new("test error");
        let display = format!("{}", err);
        assert!(display.contains("test error"));
    }
}
