//! Tests for message types.

use super::*;
use chrono::{TimeZone, Utc};

#[test]
fn test_message_builder() {
    let session_id = SessionId::new("test-session".to_string()).unwrap();
    let message = Message::new("test body".into())
        .with_session_id(session_id.clone())
        .with_attribute("key".to_string(), "value".to_string())
        .with_correlation_id("corr-123".to_string())
        .with_time_to_live(Duration::minutes(30));

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
fn test_received_message_to_message() {
    let session_id = SessionId::new("test".to_string()).unwrap();
    let received = ReceivedMessage {
        message_id: MessageId::new(),
        body: "test".into(),
        attributes: HashMap::new(),
        session_id: Some(session_id.clone()),
        correlation_id: Some("corr-123".to_string()),
        receipt_handle: ReceiptHandle::new(
            "receipt".to_string(),
            Timestamp::now(),
            ProviderType::InMemory,
        ),
        delivery_count: 1,
        first_delivered_at: Timestamp::now(),
        delivered_at: Timestamp::now(),
    };

    let message = received.message();
    assert_eq!(message.session_id, Some(session_id));
    assert_eq!(message.correlation_id, Some("corr-123".to_string()));
    assert_eq!(message.time_to_live, None); // TTL not preserved
}

// ============================================================================
// SendOptions Tests
// ============================================================================

#[test]
fn test_send_options_default() {
    let options = SendOptions::new();
    assert!(options.session_id.is_none());
    assert!(options.correlation_id.is_none());
    assert!(options.scheduled_enqueue_time.is_none());
    assert!(options.time_to_live.is_none());
    assert!(options.properties.is_empty());
    assert!(options.content_type.is_none());
    assert!(options.duplicate_detection_id.is_none());
}

#[test]
fn test_send_options_builder() {
    let session_id = SessionId::new("session-123".to_string()).unwrap();
    let options = SendOptions::new()
        .with_session_id(session_id.clone())
        .with_correlation_id("corr-456".to_string())
        .with_time_to_live(Duration::hours(1))
        .with_property("priority".to_string(), "high".to_string())
        .with_content_type("application/json".to_string())
        .with_duplicate_detection_id("dedup-789".to_string());

    assert_eq!(options.session_id, Some(session_id));
    assert_eq!(options.correlation_id, Some("corr-456".to_string()));
    assert_eq!(options.time_to_live, Some(Duration::hours(1)));
    assert_eq!(
        options.properties.get("priority"),
        Some(&"high".to_string())
    );
    assert_eq!(options.content_type, Some("application/json".to_string()));
    assert_eq!(
        options.duplicate_detection_id,
        Some("dedup-789".to_string())
    );
}

#[test]
fn test_send_options_with_scheduled_time() {
    let scheduled_time = Timestamp::from_datetime(Utc::now() + Duration::hours(2));
    let options = SendOptions::new().with_scheduled_enqueue_time(scheduled_time);

    assert_eq!(options.scheduled_enqueue_time, Some(scheduled_time));
}

#[test]
fn test_send_options_with_delay() {
    let before = Utc::now();
    let options = SendOptions::new().with_delay(Duration::minutes(30));
    let after = Utc::now();

    assert!(options.scheduled_enqueue_time.is_some());
    let scheduled = options.scheduled_enqueue_time.unwrap().as_datetime();
    let expected_min = before + Duration::minutes(30);
    let expected_max = after + Duration::minutes(30);

    assert!(scheduled >= expected_min);
    assert!(scheduled <= expected_max);
}

#[test]
fn test_send_options_multiple_properties() {
    let options = SendOptions::new()
        .with_property("key1".to_string(), "value1".to_string())
        .with_property("key2".to_string(), "value2".to_string())
        .with_property("key3".to_string(), "value3".to_string());

    assert_eq!(options.properties.len(), 3);
    assert_eq!(options.properties.get("key1"), Some(&"value1".to_string()));
    assert_eq!(options.properties.get("key2"), Some(&"value2".to_string()));
    assert_eq!(options.properties.get("key3"), Some(&"value3".to_string()));
}

// ============================================================================
// ReceiveOptions Tests
// ============================================================================

#[test]
fn test_receive_options_default() {
    let options = ReceiveOptions::new();
    assert_eq!(options.max_messages, 1);
    assert_eq!(options.timeout, Duration::seconds(30));
    assert!(options.session_id.is_none());
    assert!(!options.accept_any_session);
    assert!(options.lock_duration.is_none());
    assert!(!options.peek_only);
    assert!(options.from_sequence_number.is_none());
}

#[test]
fn test_receive_options_builder() {
    let session_id = SessionId::new("session-abc".to_string()).unwrap();
    let options = ReceiveOptions::new()
        .with_max_messages(10)
        .with_timeout(Duration::seconds(60))
        .with_session_id(session_id.clone())
        .with_lock_duration(Duration::minutes(5));

    assert_eq!(options.max_messages, 10);
    assert_eq!(options.timeout, Duration::seconds(60));
    assert_eq!(options.session_id, Some(session_id));
    assert!(!options.accept_any_session);
    assert_eq!(options.lock_duration, Some(Duration::minutes(5)));
}

#[test]
fn test_receive_options_accept_any_session() {
    let options = ReceiveOptions::new().accept_any_session();

    assert!(options.accept_any_session);
    assert!(options.session_id.is_none());
}

#[test]
fn test_receive_options_session_id_overrides_accept_any() {
    let session_id = SessionId::new("specific-session".to_string()).unwrap();
    let options = ReceiveOptions::new()
        .accept_any_session()
        .with_session_id(session_id.clone());

    assert_eq!(options.session_id, Some(session_id));
    assert!(!options.accept_any_session);
}

#[test]
fn test_receive_options_accept_any_clears_session_id() {
    let session_id = SessionId::new("session-xyz".to_string()).unwrap();
    let options = ReceiveOptions::new()
        .with_session_id(session_id)
        .accept_any_session();

    assert!(options.session_id.is_none());
    assert!(options.accept_any_session);
}

#[test]
fn test_receive_options_peek_only() {
    let options = ReceiveOptions::new().peek_only();

    assert!(options.peek_only);
}

#[test]
fn test_receive_options_with_sequence_number() {
    let options = ReceiveOptions::new().from_sequence_number(12345);

    assert_eq!(options.from_sequence_number, Some(12345));
}

#[test]
fn test_receive_options_batch_configuration() {
    let options = ReceiveOptions::new()
        .with_max_messages(50)
        .with_timeout(Duration::seconds(120));

    assert_eq!(options.max_messages, 50);
    assert_eq!(options.timeout, Duration::seconds(120));
}

// ============================================================================
// Domain Identifier Tests
// ============================================================================

#[test]
fn test_queue_name_valid() {
    let name = QueueName::new("valid-queue_name".to_string()).unwrap();
    assert_eq!(name.as_str(), "valid-queue_name");
}

#[test]
fn test_queue_name_with_prefix() {
    let name = QueueName::with_prefix("prod", "events").unwrap();
    assert_eq!(name.as_str(), "prod-events");
}

#[test]
fn test_queue_name_empty_rejected() {
    let result = QueueName::new("".to_string());
    assert!(result.is_err());
}

#[test]
fn test_queue_name_too_long_rejected() {
    let long_name = "a".repeat(261);
    let result = QueueName::new(long_name);
    assert!(result.is_err());
}

#[test]
fn test_queue_name_invalid_characters_rejected() {
    let result = QueueName::new("queue@name".to_string());
    assert!(result.is_err());
}

#[test]
fn test_queue_name_leading_hyphen_rejected() {
    let result = QueueName::new("-queue".to_string());
    assert!(result.is_err());
}

#[test]
fn test_queue_name_trailing_hyphen_rejected() {
    let result = QueueName::new("queue-".to_string());
    assert!(result.is_err());
}

#[test]
fn test_queue_name_consecutive_hyphens_rejected() {
    let result = QueueName::new("queue--name".to_string());
    assert!(result.is_err());
}

#[test]
fn test_queue_name_from_str() {
    let name: QueueName = "test-queue".parse().unwrap();
    assert_eq!(name.as_str(), "test-queue");
}

#[test]
fn test_queue_name_display() {
    let name = QueueName::new("test-queue".to_string()).unwrap();
    assert_eq!(format!("{}", name), "test-queue");
}

#[test]
fn test_message_id_generation() {
    let id1 = MessageId::new();
    let id2 = MessageId::new();

    assert_ne!(id1, id2); // Each ID should be unique
    assert!(!id1.as_str().is_empty());
}

#[test]
fn test_message_id_default() {
    let id = MessageId::default();
    assert!(!id.as_str().is_empty());
}

#[test]
fn test_message_id_from_str() {
    let id: MessageId = "test-message-id".parse().unwrap();
    assert_eq!(id.as_str(), "test-message-id");
}

#[test]
fn test_message_id_empty_rejected() {
    let result: Result<MessageId, _> = "".parse();
    assert!(result.is_err());
}

#[test]
fn test_message_id_display() {
    let id: MessageId = "test-id".parse().unwrap();
    assert_eq!(format!("{}", id), "test-id");
}

#[test]
fn test_session_id_valid() {
    let id = SessionId::new("valid-session".to_string()).unwrap();
    assert_eq!(id.as_str(), "valid-session");
}

#[test]
fn test_session_id_from_parts() {
    let id = SessionId::from_parts("owner", "repo", "pull_request", "123");
    assert_eq!(id.as_str(), "owner/repo/pull_request/123");
}

#[test]
fn test_session_id_empty_rejected() {
    let result = SessionId::new("".to_string());
    assert!(result.is_err());
}

#[test]
fn test_session_id_too_long_rejected() {
    let long_id = "a".repeat(129);
    let result = SessionId::new(long_id);
    assert!(result.is_err());
}

#[test]
fn test_session_id_non_ascii_rejected() {
    let result = SessionId::new("session-💡".to_string());
    assert!(result.is_err());
}

#[test]
fn test_session_id_control_characters_rejected() {
    let result = SessionId::new("session\x00id".to_string());
    assert!(result.is_err());
}

#[test]
fn test_session_id_from_str() {
    let id: SessionId = "test-session".parse().unwrap();
    assert_eq!(id.as_str(), "test-session");
}

#[test]
fn test_session_id_display() {
    let id = SessionId::new("test-session".to_string()).unwrap();
    assert_eq!(format!("{}", id), "test-session");
}

#[test]
fn test_timestamp_now() {
    let ts1 = Timestamp::now();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let ts2 = Timestamp::now();

    assert!(ts2 > ts1); // Time should advance
}

#[test]
fn test_timestamp_from_datetime() {
    let dt = Utc::now();
    let ts = Timestamp::from_datetime(dt);
    assert_eq!(ts.as_datetime(), dt);
}

#[test]
fn test_timestamp_ordering() {
    let ts1 = Timestamp::now();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let ts2 = Timestamp::now();

    assert!(ts1 < ts2);
    assert!(ts2 > ts1);
    assert_eq!(ts1, ts1.clone());
}

#[test]
fn test_timestamp_display() {
    let dt = Utc.with_ymd_and_hms(2025, 1, 15, 10, 30, 45).unwrap();
    let ts = Timestamp::from_datetime(dt);
    let display = format!("{}", ts);

    assert!(display.contains("2025-01-15"));
    assert!(display.contains("10:30:45"));
    assert!(display.contains("UTC"));
}

// ============================================================================
// Property-Based Tests
// ============================================================================

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Any string longer than 260 characters is always rejected by QueueName.
        #[test]
        fn queue_name_rejects_strings_over_260_chars(
            base in "[a-zA-Z0-9]{1,50}",
            extra in "[a-zA-Z0-9]{211,500}",
        ) {
            let long = format!("{}{}", base, extra);
            prop_assume!(long.len() > 260);
            let result = QueueName::new(long);
            prop_assert!(result.is_err(), "strings > 260 chars must be rejected");
        }

        /// Any non-ASCII character anywhere in the string causes rejection.
        #[test]
        fn queue_name_rejects_non_ascii(
            prefix in "[a-zA-Z0-9]{1,10}",
            // Unicode scalar > 127
            non_ascii in proptest::char::range('\u{0080}', '\u{07FF}'),
            suffix in "[a-zA-Z0-9]{0,10}",
        ) {
            let s = format!("{}{}{}", prefix, non_ascii, suffix);
            let result = QueueName::new(s);
            prop_assert!(result.is_err(), "non-ASCII chars must be rejected");
        }

        /// Alphanumeric-only strings of length 1-260 are always accepted.
        #[test]
        fn queue_name_accepts_alphanumeric_strings(
            s in "[a-zA-Z0-9]{1,260}",
        ) {
            let result = QueueName::new(s);
            prop_assert!(result.is_ok(), "pure alphanumeric strings must be accepted");
        }

        /// Any string longer than 128 characters must be rejected by SessionId.
        #[test]
        fn session_id_rejects_strings_over_128_chars(
            base in "[a-zA-Z0-9 ]{1,50}",
            extra in "[a-zA-Z0-9]{79,200}",
        ) {
            let long = format!("{}{}", base, extra);
            prop_assume!(long.len() > 128);
            let result = SessionId::new(long);
            prop_assert!(result.is_err(), "strings > 128 chars must be rejected");
        }

        /// ASCII control characters (0x00-0x1F) anywhere in the string cause rejection.
        #[test]
        fn session_id_rejects_control_characters(
            prefix in "[a-zA-Z0-9]{1,10}",
            ctrl in 0u8..=31u8,
            suffix in "[a-zA-Z0-9]{0,10}",
        ) {
            let s = format!("{}{}{}", prefix, ctrl as char, suffix);
            let result = SessionId::new(s);
            prop_assert!(result.is_err(), "control chars must be rejected");
        }

        /// Any non-ASCII character causes SessionId rejection.
        #[test]
        fn session_id_rejects_non_ascii(
            prefix in "[a-zA-Z0-9]{1,10}",
            non_ascii in proptest::char::range('\u{0080}', '\u{07FF}'),
            suffix in "[a-zA-Z0-9]{0,10}",
        ) {
            let s = format!("{}{}{}", prefix, non_ascii, suffix);
            let result = SessionId::new(s);
            prop_assert!(result.is_err(), "non-ASCII chars must be rejected");
        }

        /// ASCII printable strings of length 1-128 are always accepted by SessionId.
        #[test]
        fn session_id_accepts_printable_ascii(
            s in "[\\x20-\\x7E]{1,128}",
        ) {
            let result = SessionId::new(s);
            prop_assert!(result.is_ok(), "printable ASCII strings (1-128 chars) must be accepted");
        }

        /// MessageId::new() always produces a non-empty, distinct value.
        #[test]
        fn message_id_is_always_non_empty(_dummy in 0u32..1000u32) {
            let id = MessageId::new();
            prop_assert!(!id.as_str().is_empty(), "generated MessageId must not be empty");
        }

        /// Two MessageId::new() calls always produce distinct values (UUID v4).
        #[test]
        fn message_id_is_unique(_dummy in 0u32..100u32) {
            let id1 = MessageId::new();
            let id2 = MessageId::new();
            prop_assert_ne!(id1.as_str(), id2.as_str(), "consecutive MessageIds must be distinct");
        }

        /// QueueName round-trips through Display and FromStr correctly.
        #[test]
        fn queue_name_display_round_trips(s in "[a-zA-Z0-9]{1,50}") {
            let original = QueueName::new(s.clone()).expect("valid input");
            let displayed = format!("{}", original);
            let reparsed: QueueName = displayed.parse().expect("should re-parse");
            prop_assert_eq!(original, reparsed);
        }
    }
}
