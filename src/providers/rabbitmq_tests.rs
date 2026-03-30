//! Tests for the RabbitMQ queue provider.
//!
//! These tests verify configuration, naming logic, and error-handling paths
//! that do not require a live RabbitMQ broker.  Integration tests that need a
//! broker should live in a separate integration-test suite.

use super::*;
use crate::provider::RabbitMqConfig;
use chrono::Duration;

// ============================================================================
// Configuration tests
// ============================================================================

mod config_tests {
    use super::*;

    /// Verify that the default configuration has sensible values.
    #[test]
    fn test_default_config_values() {
        let config = RabbitMqConfig::default();
        assert_eq!(config.url, "amqp://guest:guest@localhost:5672");
        assert_eq!(config.virtual_host, "/");
        assert_eq!(config.prefetch_count, 10);
        assert!(config.enable_dead_letter);
        assert_eq!(config.dead_letter_exchange, Some("dlx".to_string()));
        assert!(config.message_ttl.is_none());
    }

    /// Verify that the default session lock duration is sensible.
    #[test]
    fn test_default_session_lock_duration() {
        let config = RabbitMqConfig::default();
        assert_eq!(config.session_lock_duration, Duration::minutes(5));
    }

    /// Verify custom configuration can be constructed.
    #[test]
    fn test_custom_config() {
        let config = RabbitMqConfig {
            url: "amqp://user:pass@rabbitmq.example.com:5672".to_string(),
            virtual_host: "/myapp".to_string(),
            prefetch_count: 20,
            session_lock_duration: Duration::minutes(10),
            message_ttl: Some(Duration::hours(24)),
            enable_dead_letter: false,
            dead_letter_exchange: None,
        };

        assert_eq!(config.url, "amqp://user:pass@rabbitmq.example.com:5672");
        assert_eq!(config.virtual_host, "/myapp");
        assert_eq!(config.prefetch_count, 20);
        assert!(!config.enable_dead_letter);
        assert!(config.dead_letter_exchange.is_none());
    }

    /// Verify that the provider type is correct.
    #[test]
    fn test_provider_type() {
        assert_eq!(
            ProviderType::RabbitMq.max_message_size(),
            128 * 1024 * 1024
        );
        assert!(ProviderType::RabbitMq.supports_batching());
        assert_eq!(
            ProviderType::RabbitMq.supports_sessions(),
            crate::provider::SessionSupport::Emulated
        );
    }
}

// ============================================================================
// Naming helper tests
// ============================================================================

mod naming_tests {
    use super::*;

    /// Verify that session queue names use the expected format.
    #[test]
    fn test_session_queue_name_format() {
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let session = SessionId::new("session-abc".to_string()).unwrap();
        let name = session_queue_name(&queue, &session);
        assert_eq!(name, "my-queue.session.session-abc");
    }

    /// Verify that session IDs with slashes are sanitised.
    #[test]
    fn test_session_queue_name_sanitises_slashes() {
        let queue = QueueName::new("my-queue".to_string()).unwrap();
        let session = SessionId::new("owner/repo/pr/42".to_string()).unwrap();
        let name = session_queue_name(&queue, &session);
        // Slashes replaced with underscores
        assert!(!name.contains('/'));
        assert!(name.starts_with("my-queue.session."));
    }

    /// Verify that session IDs with spaces are sanitised.
    #[test]
    fn test_session_queue_name_sanitises_spaces() {
        let queue = QueueName::new("test-queue".to_string()).unwrap();
        let session = SessionId::new("session with spaces".to_string()).unwrap();
        let name = session_queue_name(&queue, &session);
        assert!(!name.contains(' '));
    }
}

// ============================================================================
// Header encode/decode tests
// ============================================================================

mod header_tests {
    use super::*;

    /// Verify that attributes are encoded into AMQP headers and decoded back.
    #[test]
    fn test_attribute_roundtrip() {
        let mut message = Message::new(bytes::Bytes::from("test body"));
        message = message.with_attribute("key1".to_string(), "value1".to_string());
        message = message.with_attribute("key2".to_string(), "value2".to_string());

        let props = RabbitMqProvider::build_properties(&message);
        let headers = props.headers().clone();

        let attrs = RabbitMqProvider::extract_attributes(&headers);
        assert_eq!(attrs.get("key1").map(String::as_str), Some("value1"));
        assert_eq!(attrs.get("key2").map(String::as_str), Some("value2"));
    }

    /// Verify that session ID is encoded and decoded correctly.
    #[test]
    fn test_session_id_header_roundtrip() {
        let session = SessionId::new("my-session-123".to_string()).unwrap();
        let message = Message::new(bytes::Bytes::from("body"))
            .with_session_id(session.clone());

        let props = RabbitMqProvider::build_properties(&message);
        let headers = props.headers().clone();

        let extracted = RabbitMqProvider::extract_session_id(&headers);
        assert_eq!(extracted, Some(session));
    }

    /// Verify that the session ID header is absent when no session is set.
    #[test]
    fn test_no_session_id_when_none() {
        let message = Message::new(bytes::Bytes::from("body"));
        let props = RabbitMqProvider::build_properties(&message);
        let headers = props.headers().clone();

        let extracted = RabbitMqProvider::extract_session_id(&headers);
        assert!(extracted.is_none());
    }

    /// Verify that correlation ID is preserved in properties.
    #[test]
    fn test_correlation_id_in_properties() {
        let message = Message::new(bytes::Bytes::from("body"))
            .with_correlation_id("corr-001".to_string());

        let props = RabbitMqProvider::build_properties(&message);
        let corr = props.correlation_id().as_ref().map(|s| s.to_string());
        assert_eq!(corr, Some("corr-001".to_string()));
    }

    /// Verify that TTL is encoded as expiration property.
    #[test]
    fn test_ttl_encoded_as_expiration() {
        let message = Message::new(bytes::Bytes::from("body"))
            .with_ttl(Duration::seconds(60));

        let props = RabbitMqProvider::build_properties(&message);
        let expiration = props.expiration().as_ref().map(|s| s.to_string());
        assert_eq!(expiration, Some("60000".to_string())); // 60 seconds in ms
    }

    /// Verify that delivery mode is always set to persistent (2).
    #[test]
    fn test_delivery_mode_is_persistent() {
        let message = Message::new(bytes::Bytes::from("body"));
        let props = RabbitMqProvider::build_properties(&message);
        // delivery_mode() returns &Option<u8>; deref to compare
        assert_eq!(*props.delivery_mode(), Some(2u8));
    }

    /// Verify that internal x-* attributes are not returned as user attributes.
    #[test]
    fn test_internal_headers_not_in_attributes() {
        let session = SessionId::new("s1".to_string()).unwrap();
        let message = Message::new(bytes::Bytes::from("body"))
            .with_session_id(session)
            .with_attribute("my-key".to_string(), "my-value".to_string());

        let props = RabbitMqProvider::build_properties(&message);
        let headers = props.headers().clone();
        let attrs = RabbitMqProvider::extract_attributes(&headers);

        // x-session-id must not appear in user attributes
        assert!(!attrs.contains_key("x-session-id"));
        // x-delivery-count must not appear either
        assert!(!attrs.contains_key("x-delivery-count"));
        // User attribute must be present
        assert_eq!(attrs.get("my-key").map(String::as_str), Some("my-value"));
    }

    /// Verify that delivery count defaults to 1 when no header is present.
    #[test]
    fn test_delivery_count_defaults_to_one() {
        let count = RabbitMqProvider::extract_delivery_count(&None);
        assert_eq!(count, 1);
    }
}

// ============================================================================
// Error conversion tests
// ============================================================================

mod error_tests {
    use super::*;

    /// Verify that RabbitMqError converts to a provider QueueError.
    #[test]
    fn test_error_conversion() {
        let err = RabbitMqError::new("connection refused");
        let queue_err = err.to_queue_error();

        match queue_err {
            QueueError::ProviderError { provider, code, message } => {
                assert_eq!(provider, "rabbitmq");
                assert_eq!(code, "AMQP_ERROR");
                assert!(message.contains("connection refused"));
            }
            other => panic!("unexpected error variant: {:?}", other),
        }
    }

    /// Verify that RabbitMqError implements Display.
    #[test]
    fn test_error_display() {
        let err = RabbitMqError::new("test error");
        let display = format!("{}", err);
        assert!(display.contains("test error"));
    }
}
