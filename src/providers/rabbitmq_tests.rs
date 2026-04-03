//! Tests for the RabbitMQ queue provider.
//!
//! These tests verify configuration, naming logic, and error-handling paths
//! that do not require a live RabbitMQ broker.  Integration tests that need a
//! broker should live in a separate integration-test suite.

use super::*;
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
        assert_eq!(ProviderType::RabbitMq.max_message_size(), 128 * 1024 * 1024);
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
        let message = Message::new(bytes::Bytes::from("body")).with_session_id(session.clone());

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
        let message =
            Message::new(bytes::Bytes::from("body")).with_correlation_id("corr-001".to_string());

        let props = RabbitMqProvider::build_properties(&message);
        let corr = props.correlation_id().as_ref().map(|s| s.to_string());
        assert_eq!(corr, Some("corr-001".to_string()));
    }

    /// Verify that TTL is encoded as expiration property.
    #[test]
    fn test_ttl_encoded_as_expiration() {
        let message = Message::new(bytes::Bytes::from("body")).with_ttl(Duration::seconds(60));

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

    /// Verify that raw broker/extension x- headers are NOT returned as user
    /// attributes, and that the x-attr- prefix scheme lets user attributes
    /// with any key (including x-prefixed ones) round-trip correctly.
    #[test]
    fn test_x_prefix_headers_excluded() {
        let mut headers = FieldTable::default();
        // Raw broker/extension headers must NOT appear as user attributes.
        for key in &[
            "x-session-id",
            "x-delivery-count",
            "x-death",
            "x-custom-provider-header",
        ] {
            headers.insert(
                lapin::types::ShortString::from(*key),
                lapin::types::AMQPValue::LongString(lapin::types::LongString::from(
                    b"ignored".as_ref(),
                )),
            );
        }
        // A user attribute encoded correctly via the x-attr- prefix.
        headers.insert(
            lapin::types::ShortString::from("x-attr-my-attr"),
            lapin::types::AMQPValue::LongString(lapin::types::LongString::from(
                b"visible".as_ref(),
            )),
        );
        // A plain key without the x-attr- prefix must NOT be returned.
        headers.insert(
            lapin::types::ShortString::from("plain-attr"),
            lapin::types::AMQPValue::LongString(lapin::types::LongString::from(
                b"invisible".as_ref(),
            )),
        );

        let attrs = RabbitMqProvider::extract_attributes(&Some(headers));

        // Broker/extension headers are not returned.
        assert!(!attrs.contains_key("x-session-id"));
        assert!(!attrs.contains_key("x-delivery-count"));
        assert!(!attrs.contains_key("x-death"));
        assert!(!attrs.contains_key("x-custom-provider-header"));
        // Plain key without the prefix is not returned.
        assert!(!attrs.contains_key("plain-attr"));
        // User attribute stored with x-attr- prefix is returned with prefix stripped.
        assert_eq!(attrs.get("my-attr").map(String::as_str), Some("visible"));
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

    /// Verify that a user attribute whose key starts with "x-" roundtrips correctly.
    ///
    /// This is the regression test for the bug where build_properties stored raw
    /// keys and extract_attributes silently dropped all x-* headers, meaning that
    /// an attribute like "x-custom-meta" was always lost.
    #[test]
    fn test_x_prefixed_user_attribute_roundtrip() {
        let mut message = Message::new(bytes::Bytes::from("body"));
        message = message.with_attribute("x-custom-meta".to_string(), "hello".to_string());
        message = message.with_attribute("plain-key".to_string(), "world".to_string());

        let props = RabbitMqProvider::build_properties(&message);
        let headers = props.headers().clone();
        let attrs = RabbitMqProvider::extract_attributes(&headers);

        // x-prefixed user attribute must survive the roundtrip.
        assert_eq!(
            attrs.get("x-custom-meta").map(String::as_str),
            Some("hello"),
            "x-prefixed user attribute must roundtrip"
        );
        // Regular user attribute must survive too.
        assert_eq!(
            attrs.get("plain-key").map(String::as_str),
            Some("world"),
            "plain user attribute must roundtrip"
        );
        // Provider-managed headers must not bleed into user attributes.
        assert!(!attrs.contains_key("x-session-id"));
    }

    /// Verify that delivery count is extracted from x-delivery-count header.
    #[test]
    fn test_delivery_count_from_header() {
        let mut headers = FieldTable::default();
        headers.insert(
            lapin::types::ShortString::from("x-delivery-count"),
            lapin::types::AMQPValue::LongLongInt(4),
        );
        let count = RabbitMqProvider::extract_delivery_count(&Some(headers));
        // 4 in header + 1 = 5
        assert_eq!(count, 5);
    }

    /// Verify that TTL of zero does not set an expiration property.
    #[test]
    fn test_zero_ttl_not_encoded() {
        let message = Message::new(bytes::Bytes::from("body")).with_ttl(Duration::seconds(0));
        let props = RabbitMqProvider::build_properties(&message);
        let expiration = props.expiration().as_ref().map(|s| s.to_string());
        assert!(expiration.is_none(), "Zero TTL should not set expiration");
    }

    /// Verify that a message without correlation ID has no correlation_id property.
    #[test]
    fn test_no_correlation_id() {
        let message = Message::new(bytes::Bytes::from("body"));
        let props = RabbitMqProvider::build_properties(&message);
        assert!(props.correlation_id().is_none());
    }

    /// Verify that attributes with values of non-LongString AMQP type are ignored.
    #[test]
    fn test_extract_attributes_ignores_non_string() {
        let mut headers = FieldTable::default();
        // Non-LongString value under the x-attr- prefix must be ignored.
        headers.insert(
            lapin::types::ShortString::from("x-attr-int-field"),
            lapin::types::AMQPValue::LongLongInt(42),
        );
        // LongString value under the x-attr- prefix must be returned.
        headers.insert(
            lapin::types::ShortString::from("x-attr-str-field"),
            lapin::types::AMQPValue::LongString(lapin::types::LongString::from(b"hello".as_ref())),
        );
        let attrs = RabbitMqProvider::extract_attributes(&Some(headers));
        // Non-LongString field must be skipped.
        assert!(!attrs.contains_key("int-field"));
        // LongString field must be present with the prefix stripped.
        assert_eq!(attrs.get("str-field").map(String::as_str), Some("hello"));
    }

    /// Verify that extract_attributes returns empty map for None headers.
    #[test]
    fn test_extract_attributes_none_headers() {
        let attrs = RabbitMqProvider::extract_attributes(&None);
        assert!(attrs.is_empty());
    }

    /// Verify that extract_session_id returns None for None headers.
    #[test]
    fn test_extract_session_id_none_headers() {
        let result = RabbitMqProvider::extract_session_id(&None);
        assert!(result.is_none());
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
            QueueError::ProviderError {
                provider,
                code,
                message,
            } => {
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

// ============================================================================
// Session lock tests
// ============================================================================

mod session_lock_tests {
    use super::*;

    /// Verify that session_lock_duration is used for the default lock duration.
    #[test]
    fn test_session_lock_duration_default() {
        let config = RabbitMqConfig::default();
        assert_eq!(config.session_lock_duration, Duration::minutes(5));
    }

    /// Verify that a custom session lock duration is respected.
    #[test]
    fn test_session_lock_duration_custom() {
        let config = RabbitMqConfig {
            session_lock_duration: Duration::minutes(30),
            ..RabbitMqConfig::default()
        };
        assert_eq!(config.session_lock_duration, Duration::minutes(30));
    }
}

// ============================================================================
// URL redaction tests
// ============================================================================

mod url_redaction_tests {
    use super::*;

    /// Verify that credentials embedded in an AMQP URL are replaced with `***`.
    #[test]
    fn test_redact_url_with_credentials() {
        let redacted = redact_url("amqp://user:pass@localhost:5672");
        assert!(
            !redacted.contains("user"),
            "Username must be redacted: {redacted}"
        );
        assert!(
            !redacted.contains("pass"),
            "Password must be redacted: {redacted}"
        );
        assert!(
            redacted.contains("localhost"),
            "Host must be preserved: {redacted}"
        );
        assert!(
            redacted.contains("5672"),
            "Port must be preserved: {redacted}"
        );
        assert!(
            redacted.contains("***"),
            "Redaction marker must appear: {redacted}"
        );
    }

    /// Verify that a URL without credentials is returned unchanged.
    #[test]
    fn test_redact_url_without_credentials() {
        let url = "amqp://localhost:5672";
        let redacted = redact_url(url);
        assert_eq!(redacted.trim_end_matches('/'), url.trim_end_matches('/'));
    }

    /// Verify that an invalid URL returns the sentinel string.
    #[test]
    fn test_redact_url_invalid_url() {
        let redacted = redact_url("not a url !!!");
        assert_eq!(redacted, "<invalid-url>");
    }

    /// Verify that the default config URL has its credentials redacted.
    #[test]
    fn test_redact_url_default_config_url() {
        let config = RabbitMqConfig::default();
        let redacted = redact_url(&config.url);
        // Default URL contains "guest:guest" – these must not appear after redaction.
        assert!(
            !redacted.contains("guest"),
            "Default credentials must be redacted: {redacted}"
        );
    }
}

// ============================================================================
// Session lock helper tests (require no live RabbitMQ broker)
// ============================================================================

mod session_lock_tests_helpers {
    use super::*;
    use std::sync::Mutex;

    fn lock_expiring_in(minutes: i64) -> Mutex<Timestamp> {
        let ts =
            Timestamp::from_datetime(Timestamp::now().as_datetime() + Duration::minutes(minutes));
        Mutex::new(ts)
    }

    fn lock_expired_since(minutes: i64) -> Mutex<Timestamp> {
        let ts =
            Timestamp::from_datetime(Timestamp::now().as_datetime() - Duration::minutes(minutes));
        Mutex::new(ts)
    }

    /// A valid (non-expired) lock returns Ok.
    #[test]
    fn test_check_session_lock_valid() {
        let lock = lock_expiring_in(5);
        let session = SessionId::new("test-session".to_string()).unwrap();
        assert!(check_session_lock(&lock, &session).is_ok());
    }

    /// An expired lock returns SessionLocked with the correct session ID.
    #[test]
    fn test_check_session_lock_expired() {
        let lock = lock_expired_since(1);
        let session = SessionId::new("expired-session".to_string()).unwrap();

        let result = check_session_lock(&lock, &session);

        assert!(result.is_err());
        match result.unwrap_err() {
            QueueError::SessionLocked { session_id, .. } => {
                assert_eq!(session_id, "expired-session");
            }
            other => panic!("expected SessionLocked, got: {:?}", other),
        }
    }

    /// Renewing an expired lock makes it valid again.
    #[test]
    fn test_advance_session_lock_from_expired() {
        let lock = lock_expired_since(1); // already expired
        let session = SessionId::new("test-session".to_string()).unwrap();

        // Confirm it's expired before renewal.
        assert!(check_session_lock(&lock, &session).is_err());

        // Renew for 5 minutes.
        let new_expiry = advance_session_lock(&lock, Duration::minutes(5))
            .expect("advance_session_lock should succeed");

        // New expiry is in the future.
        assert!(
            new_expiry.as_datetime() > Timestamp::now().as_datetime(),
            "new expiry must be in the future"
        );

        // Lock is now valid.
        assert!(check_session_lock(&lock, &session).is_ok());
    }

    /// Renewing an already-valid lock extends it further into the future.
    #[test]
    fn test_advance_session_lock_extends_valid_lock() {
        let lock = lock_expiring_in(1); // valid but close to expiry

        let before = { *lock.lock().unwrap() };

        advance_session_lock(&lock, Duration::minutes(5))
            .expect("advance_session_lock should succeed");

        let after = { *lock.lock().unwrap() };

        assert!(
            after.as_datetime() > before.as_datetime(),
            "renewal must extend the expiry"
        );
    }
}
