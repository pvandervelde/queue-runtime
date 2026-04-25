//! Integration tests for the RabbitMQ provider using a real broker via testcontainers.
//!
//! These tests require Docker.  Run with:
//!
//! ```bash
//! cargo test --test rabbitmq_integration --features integration-tests
//! ```

use bytes::Bytes;
use chrono::Duration;
use queue_runtime::{
    client::QueueProvider,
    message::{Message, QueueName, SessionId},
    providers::RabbitMqProvider,
    RabbitMqConfig,
};
use testcontainers::runners::AsyncRunner;
use testcontainers_modules::rabbitmq::RabbitMq;
use tokio::sync::OnceCell;

// ============================================================================
// Shared container — started once for the whole test binary
// ============================================================================

/// Returns the host port of the single RabbitMQ container shared across all tests.
///
/// [`OnceCell`] provides async-safe one-time initialization.  Because every
/// test is already running inside a `#[tokio::test]` runtime, we cannot use
/// `std::sync::OnceLock` + `block_on` — that would panic with "Cannot start a
/// runtime from within a runtime".  The [`ContainerAsync`] handle is
/// intentionally leaked so the broker stays alive for the whole process.
static RABBITMQ_PORT: OnceCell<u16> = OnceCell::const_new();

async fn rabbitmq_port() -> u16 {
    *RABBITMQ_PORT
        .get_or_init(|| async {
            let container = RabbitMq::default()
                .start()
                .await
                .expect("start RabbitMQ container");
            let port = container.get_host_port_ipv4(5672).await.unwrap();
            Box::leak(Box::new(container));
            port
        })
        .await
}

// ============================================================================
// Helpers
// ============================================================================

fn queue(name: &str) -> QueueName {
    QueueName::new(name.to_string()).expect("valid queue name")
}

fn msg(body: &str) -> Message {
    Message::new(Bytes::from(body.to_string()))
}

fn msg_with_attrs(body: &str, key: &str, value: &str) -> Message {
    let mut m = msg(body);
    m.attributes.insert(key.to_string(), value.to_string());
    m
}

fn msg_with_session(body: &str, session: &str) -> Message {
    let sid = SessionId::new(session.to_string()).expect("valid session id");
    Message::new(Bytes::from(body.to_string())).with_session_id(sid)
}

async fn rabbitmq_provider(port: u16) -> RabbitMqProvider {
    let config = RabbitMqConfig {
        url: format!("amqp://guest:guest@localhost:{}", port),
        virtual_host: "/".to_string(),
        prefetch_count: 10,
        session_lock_duration: Duration::minutes(5),
        message_ttl: None,
        // Disable DLX for integration tests to keep setup simple.
        enable_dead_letter: false,
        dead_letter_exchange: None,
    };
    RabbitMqProvider::new(config)
        .await
        .expect("connect to RabbitMQ test container")
}

// ============================================================================
// Assertion 1 + 3: Send succeeds; payload arrives intact
// ============================================================================

#[tokio::test]
async fn rabbitmq_send_and_receive_single_message() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-send-receive");

    let body = "rabbitmq integration payload";
    p.send_message(&q, &msg(body))
        .await
        .expect("send must succeed");

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .expect("receive must not error")
        .expect("must receive sent message");

    assert_eq!(received.body, Bytes::from(body));
}

// ============================================================================
// Payload attributes survive round-trip
// ============================================================================

#[tokio::test]
async fn rabbitmq_attributes_survive_round_trip() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-attr-rt");

    p.send_message(&q, &msg_with_attrs("body", "event-type", "pull-request"))
        .await
        .expect("send");

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        received.attributes.get("event-type"),
        Some(&"pull-request".to_string())
    );
}

// ============================================================================
// Correlation ID survives round-trip
// ============================================================================

#[tokio::test]
async fn rabbitmq_correlation_id_survives_round_trip() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-corr-id");

    let mut message = msg("body");
    message.correlation_id = Some("trace-abc-456".to_string());

    p.send_message(&q, &message).await.expect("send");

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        received.correlation_id,
        Some("trace-abc-456".to_string()),
        "correlation ID must survive round trip"
    );
}

// ============================================================================
// Assertion 4: Empty queue returns None
// ============================================================================

#[tokio::test]
async fn rabbitmq_receive_from_empty_queue_returns_none() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-empty");

    let result = p
        .receive_message(&q, Duration::seconds(2))
        .await
        .expect("must not error on empty queue");

    assert!(result.is_none(), "empty queue must return None");
}

// ============================================================================
// Assertion 5: Complete removes message permanently
// ============================================================================

#[tokio::test]
async fn rabbitmq_complete_removes_message() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-complete");

    p.send_message(&q, &msg("ack-me")).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .expect("must receive message");

    p.complete_message(&received.receipt_handle)
        .await
        .expect("complete must succeed");

    let recheck = p.receive_message(&q, Duration::seconds(2)).await.unwrap();
    assert!(recheck.is_none(), "acked message must not reappear");
}

// ============================================================================
// Abandon re-queues message
// ============================================================================

#[tokio::test]
async fn rabbitmq_abandon_requeues_message() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-abandon");

    p.send_message(&q, &msg("nack-me")).await.unwrap();

    let first = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .expect("first delivery");

    p.abandon_message(&first.receipt_handle)
        .await
        .expect("abandon must succeed");

    let second = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .expect("message must be redelivered after abandon");

    assert_eq!(second.body, first.body, "redelivered body must match");
    assert_eq!(
        second.delivery_count, 2,
        "delivery_count must increment to 2 on redeliver"
    );
}

#[tokio::test]
async fn rabbitmq_session_delivers_in_fifo_order() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-session-fifo");
    let sid = "order-session";

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
        .expect("create session client");

    let r1 = session
        .receive_message(Duration::seconds(10))
        .await
        .unwrap()
        .expect("A");
    let r2 = session
        .receive_message(Duration::seconds(10))
        .await
        .unwrap()
        .expect("B");
    let r3 = session
        .receive_message(Duration::seconds(10))
        .await
        .unwrap()
        .expect("C");

    assert_eq!(r1.body, Bytes::from("A"));
    assert_eq!(r2.body, Bytes::from("B"));
    assert_eq!(r3.body, Bytes::from("C"));
}

// ============================================================================
// Batch operations
// ============================================================================

#[tokio::test]
async fn rabbitmq_batch_send_returns_one_id_per_message() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-batch");

    let messages = vec![msg("x"), msg("y"), msg("z")];
    let ids = p
        .send_messages(&q, &messages)
        .await
        .expect("batch send must succeed");

    assert_eq!(ids.len(), 3);

    let mut strs: Vec<_> = ids.iter().map(|id| id.as_str()).collect();
    strs.sort();
    strs.dedup();
    assert_eq!(strs.len(), 3, "all batch IDs must be distinct");
}

#[tokio::test]
async fn rabbitmq_receive_messages_respects_max_count() {
    let p = rabbitmq_provider(rabbitmq_port().await).await;
    let q = queue("rmq-batch-receive");

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
