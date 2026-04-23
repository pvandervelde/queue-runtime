//! Provider contract tests: behavioural assertions against InMemoryProvider.
//!
//! These tests verify that every assertion from `docs/spec/assertions.md` is
//! satisfied end-to-end without requiring any external infrastructure.  The
//! `InMemoryProvider` acts as the reference implementation that all cloud
//! provider adapters must match.

use bytes::Bytes;
use chrono::Duration;
use queue_runtime::{
    client::QueueProvider,
    message::{Message, QueueName, SessionId},
    provider::InMemoryConfig,
    providers::InMemoryProvider,
    QueueError,
};

// ============================================================================
// Helpers
// ============================================================================

fn provider() -> InMemoryProvider {
    InMemoryProvider::default()
}

fn named_provider(max_delivery_count: u32) -> InMemoryProvider {
    InMemoryProvider::new(InMemoryConfig {
        max_delivery_count,
        ..InMemoryConfig::default()
    })
}

fn queue(name: &str) -> QueueName {
    QueueName::new(name.to_string()).expect("valid queue name in test")
}

fn msg(body: &str) -> Message {
    Message::new(Bytes::from(body.to_string()))
}

fn msg_with_session(body: &str, session: &str) -> Message {
    let sid = SessionId::new(session.to_string()).expect("valid session id");
    Message::new(Bytes::from(body.to_string())).with_session_id(sid)
}

// ============================================================================
// Assertion 1 + 3: Send succeeds and payload survives intact
// ============================================================================

#[tokio::test]
async fn send_message_returns_nonempty_id() {
    let p = provider();
    let q = queue("send-test");

    let id = p.send_message(&q, &msg("hello")).await.unwrap();

    assert!(!id.as_str().is_empty(), "MessageId must not be empty");
}

#[tokio::test]
async fn sent_payload_matches_received_payload() {
    let p = provider();
    let q = queue("payload-integrity");

    let body = "exact bytes must survive";
    p.send_message(&q, &msg(body)).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("should have a message");

    assert_eq!(
        received.body,
        Bytes::from(body),
        "payload must match exactly"
    );
}

#[tokio::test]
async fn attributes_survive_round_trip() {
    let p = provider();
    let q = queue("attr-round-trip");

    let mut message = msg("body");
    message
        .attributes
        .insert("event-type".to_string(), "push".to_string());
    message
        .attributes
        .insert("repo".to_string(), "owner/repo".to_string());

    p.send_message(&q, &message).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("should have a message");

    assert_eq!(
        received.attributes.get("event-type"),
        Some(&"push".to_string())
    );
    assert_eq!(
        received.attributes.get("repo"),
        Some(&"owner/repo".to_string())
    );
}

#[tokio::test]
async fn correlation_id_survives_round_trip() {
    let p = provider();
    let q = queue("corr-round-trip");

    let mut message = msg("body");
    message.correlation_id = Some("corr-abc-123".to_string());

    p.send_message(&q, &message).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("should have a message");

    assert_eq!(
        received.correlation_id,
        Some("corr-abc-123".to_string()),
        "correlation ID must survive round trip"
    );
}

// ============================================================================
// Assertion 2: Send to non-existent queue — InMemoryProvider auto-creates queues
// so this assertion does not apply; instead verify unique IDs across messages.
// ============================================================================

#[tokio::test]
async fn each_sent_message_gets_unique_id() {
    let p = provider();
    let q = queue("unique-ids");

    let id1 = p.send_message(&q, &msg("a")).await.unwrap();
    let id2 = p.send_message(&q, &msg("b")).await.unwrap();
    let id3 = p.send_message(&q, &msg("c")).await.unwrap();

    assert_ne!(id1.as_str(), id2.as_str());
    assert_ne!(id2.as_str(), id3.as_str());
    assert_ne!(id1.as_str(), id3.as_str());
}

// ============================================================================
// Assertion 4: Receive from empty queue returns None
// ============================================================================

#[tokio::test]
async fn receive_from_empty_queue_returns_none() {
    let p = provider();
    let q = queue("empty-queue");

    let result = p
        .receive_message(&q, Duration::milliseconds(100))
        .await
        .unwrap();

    assert!(result.is_none(), "empty queue must return None");
}

// ============================================================================
// Assertion 5: Complete removes message permanently
// ============================================================================

#[tokio::test]
async fn completed_message_is_not_re_delivered() {
    let p = provider();
    let q = queue("complete-removes");

    p.send_message(&q, &msg("ephemeral")).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("should receive sent message");

    p.complete_message(&received.receipt_handle)
        .await
        .expect("complete must succeed");

    // After completion the queue must be empty.
    let recheck = p
        .receive_message(&q, Duration::milliseconds(100))
        .await
        .unwrap();
    assert!(
        recheck.is_none(),
        "completed message must not be re-delivered"
    );
}

// ============================================================================
// Assertion 6: Complete with invalid receipt returns InvalidReceipt
// ============================================================================

#[tokio::test]
async fn complete_with_unknown_receipt_returns_invalid_receipt() {
    use queue_runtime::message::{ReceiptHandle, Timestamp};
    use queue_runtime::provider::ProviderType;

    let p = provider();
    let stale = ReceiptHandle::new(
        "totally-unknown-receipt".to_string(),
        Timestamp::now(),
        ProviderType::InMemory,
    );

    let result = p.complete_message(&stale).await;

    assert!(
        matches!(result, Err(QueueError::InvalidReceipt { .. })),
        "unknown receipt must produce InvalidReceipt; got: {:?}",
        result
    );
}

// ============================================================================
// Assertion 5 + 13: Abandon re-queues message
// ============================================================================

#[tokio::test]
async fn abandoned_message_is_redelivered() {
    let p = provider();
    let q = queue("abandon-requeue");

    p.send_message(&q, &msg("retry-me")).await.unwrap();

    let first_receipt = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("first receive");

    // Abandon returns the message to the queue.
    p.abandon_message(&first_receipt.receipt_handle)
        .await
        .expect("abandon must succeed");

    let second_receipt = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("message must be available again after abandon");

    assert_eq!(
        second_receipt.body, first_receipt.body,
        "redelivered body must match original"
    );
    assert_eq!(
        second_receipt.delivery_count, 2,
        "delivery_count must increment on re-delivery"
    );
}

// ============================================================================
// Assertion 14: Dead-letter moves message out of the main queue
// ============================================================================

#[tokio::test]
async fn dead_lettered_message_is_removed_from_main_queue() {
    let p = provider();
    let q = queue("dlq-test");

    p.send_message(&q, &msg("bad-message")).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("receive before dead-lettering");

    p.dead_letter_message(&received.receipt_handle, "poison message")
        .await
        .expect("dead_letter_message must succeed");

    // Main queue must now be empty.
    let recheck = p
        .receive_message(&q, Duration::milliseconds(100))
        .await
        .unwrap();
    assert!(
        recheck.is_none(),
        "dead-lettered message must not appear in main queue"
    );
}

#[tokio::test]
async fn max_delivery_count_routes_to_dlq_automatically() {
    // max_delivery_count = 2: third abandon triggers auto-DLQ.
    let p = named_provider(2);
    let q = queue("auto-dlq");

    p.send_message(&q, &msg("will-fail")).await.unwrap();

    // First delivery + abandon.
    let r1 = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("1st delivery");
    p.abandon_message(&r1.receipt_handle).await.unwrap();

    // Second delivery + abandon → exceeds max_delivery_count → DLQ.
    let r2 = p
        .receive_message(&q, Duration::seconds(5))
        .await
        .unwrap()
        .expect("2nd delivery");
    p.abandon_message(&r2.receipt_handle).await.unwrap();

    // Main queue must now be empty (message moved to DLQ).
    let recheck = p
        .receive_message(&q, Duration::milliseconds(100))
        .await
        .unwrap();
    assert!(
        recheck.is_none(),
        "message must be in DLQ after exceeding max delivery count"
    );
}

// ============================================================================
// Assertion 7: Session FIFO ordering
// ============================================================================

#[tokio::test]
async fn session_messages_are_delivered_in_fifo_order() {
    let p = provider();
    let q = queue("session-fifo");
    let sid = "session-ordering-test";

    // Send A, B, C with the same session ID.
    p.send_message(&q, &msg_with_session("A", sid))
        .await
        .unwrap();
    p.send_message(&q, &msg_with_session("B", sid))
        .await
        .unwrap();
    p.send_message(&q, &msg_with_session("C", sid))
        .await
        .unwrap();

    let session = p
        .create_session_client(&q, Some(SessionId::new(sid.to_string()).unwrap()))
        .await
        .expect("create_session_client must succeed");

    let r1 = session
        .receive_message(Duration::seconds(5))
        .await
        .unwrap()
        .expect("must receive A");
    let r2 = session
        .receive_message(Duration::seconds(5))
        .await
        .unwrap()
        .expect("must receive B");
    let r3 = session
        .receive_message(Duration::seconds(5))
        .await
        .unwrap()
        .expect("must receive C");

    assert_eq!(r1.body, Bytes::from("A"), "first message must be A");
    assert_eq!(r2.body, Bytes::from("B"), "second message must be B");
    assert_eq!(r3.body, Bytes::from("C"), "third message must be C");
}

// ============================================================================
// Assertion 9: Exclusive session lock
// ============================================================================

#[tokio::test]
async fn second_accept_on_same_session_returns_session_locked() {
    let p = provider();
    let q = queue("session-lock");
    let sid = SessionId::new("exclusive-session".to_string()).unwrap();

    p.send_message(&q, &msg_with_session("x", "exclusive-session"))
        .await
        .unwrap();

    // First acceptance acquires the lock.
    let _session1 = p
        .create_session_client(&q, Some(sid.clone()))
        .await
        .expect("first accept must succeed");

    // Second acceptance must fail with SessionLocked.
    let result = p.create_session_client(&q, Some(sid)).await;

    assert!(
        matches!(result, Err(QueueError::SessionLocked { .. })),
        "second accept on same session must return SessionLocked"
    );
}

// ============================================================================
// Assertion 18: Thread safety / concurrent operations
// ============================================================================

#[tokio::test]
async fn concurrent_sends_all_succeed() {
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let p = Arc::new(provider());
    let q = queue("concurrent-send");

    let mut tasks = JoinSet::new();
    for i in 0..20 {
        let p_clone = Arc::clone(&p);
        let q_clone = q.clone();
        tasks.spawn(async move {
            p_clone
                .send_message(&q_clone, &msg(&format!("msg-{}", i)))
                .await
                .expect("concurrent send must succeed")
        });
    }

    let mut ids = Vec::new();
    while let Some(id) = tasks.join_next().await {
        ids.push(id.expect("task must not panic"));
    }

    assert_eq!(ids.len(), 20, "all 20 concurrent sends must succeed");

    // All IDs must be unique.
    let mut id_strs: Vec<_> = ids.iter().map(|id| id.as_str().to_string()).collect();
    id_strs.sort();
    id_strs.dedup();
    assert_eq!(id_strs.len(), 20, "all message IDs must be distinct");
}

// ============================================================================
// Batch operations (supports_batching = true for InMemoryProvider)
// ============================================================================

#[tokio::test]
async fn send_messages_batch_returns_one_id_per_message() {
    let p = provider();
    let q = queue("batch-send");

    let messages = vec![msg("alpha"), msg("beta"), msg("gamma")];
    let ids = p
        .send_messages(&q, &messages)
        .await
        .expect("batch send must succeed");

    assert_eq!(ids.len(), 3, "must return one ID per message");

    // IDs must be distinct.
    let mut strs: Vec<_> = ids.iter().map(|id| id.as_str()).collect();
    strs.sort();
    strs.dedup();
    assert_eq!(strs.len(), 3, "batch IDs must all be distinct");
}

#[tokio::test]
async fn receive_messages_respects_max_count() {
    let p = provider();
    let q = queue("batch-receive");

    for i in 0..10 {
        p.send_message(&q, &msg(&format!("msg-{}", i)))
            .await
            .unwrap();
    }

    let received = p
        .receive_messages(&q, 4, Duration::seconds(5))
        .await
        .expect("batch receive must succeed");

    assert_eq!(
        received.len(),
        4,
        "must return exactly the requested number of messages when sufficient messages are queued"
    );
}
