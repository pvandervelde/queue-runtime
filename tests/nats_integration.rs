//! Integration tests for the NATS provider using a real broker via testcontainers.
//!
//! These tests require Docker.  Run with:
//!
//! ```bash
//! cargo test --test nats_integration --features integration-tests
//! ```

use bytes::Bytes;
use chrono::Duration;
use queue_runtime::{
    client::{QueueProvider, SessionProvider},
    message::{Message, QueueName, SessionId},
    providers::NatsProvider,
    NatsConfig,
};
use std::sync::OnceLock;
use testcontainers::runners::AsyncRunner;
use testcontainers::ImageExt;
use testcontainers_modules::nats::Nats;

// ============================================================================
// Shared container — started once for the whole test binary
// ============================================================================

/// Returns the host port of the single NATS container shared across all tests.
///
/// [`OnceLock`] ensures the container is started at most once even when
/// `cargo test` runs tests across multiple threads.  A dedicated
/// single-threaded Tokio runtime handles the async startup so we do not
/// re-enter the per-test runtime.  The [`ContainerAsync`] handle is
/// intentionally leaked: the container must remain running for the entire
/// process lifetime.
static NATS_PORT: OnceLock<u16> = OnceLock::new();

fn nats_port() -> u16 {
    *NATS_PORT.get_or_init(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build temp runtime for NATS container startup");
        rt.block_on(async {
            let container = Nats::default()
                .with_cmd(["-js"]) // enable JetStream
                .start()
                .await
                .expect("start NATS container");
            let port = container.get_host_port_ipv4(4222).await.unwrap();
            Box::leak(Box::new(container));
            port
        })
    })
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

async fn nats_provider(port: u16) -> NatsProvider {
    let config = NatsConfig {
        url: format!("nats://localhost:{}", port),
        stream_prefix: "test".to_string(),
        max_deliver: Some(5),
        ack_wait: Duration::seconds(30),
        session_lock_duration: Duration::minutes(5),
        enable_dead_letter: true,
        dead_letter_subject_prefix: Some("test-dlq".to_string()),
        credentials_path: None,
    };
    NatsProvider::new(config)
        .await
        .expect("connect to NATS test container")
}

// ============================================================================
// Assertion 1 + 3: Send succeeds; payload arrives intact
// ============================================================================

#[tokio::test]
async fn nats_send_and_receive_single_message() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-send-receive");

    let body = "nats integration payload";
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
async fn nats_attributes_survive_round_trip() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-attr-rt");

    p.send_message(&q, &msg_with_attrs("body", "event-type", "push"))
        .await
        .expect("send");

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        received.attributes.get("event-type"),
        Some(&"push".to_string())
    );
}

// ============================================================================
// Assertion 4: Empty queue returns None
// ============================================================================

#[tokio::test]
async fn nats_receive_from_empty_queue_returns_none() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-empty");

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
async fn nats_complete_removes_message() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-complete");

    p.send_message(&q, &msg("complete-me")).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .expect("must receive message");

    p.complete_message(&received.receipt_handle)
        .await
        .expect("complete must succeed");

    let recheck = p.receive_message(&q, Duration::seconds(2)).await.unwrap();
    assert!(recheck.is_none(), "completed message must not reappear");
}

// ============================================================================
// Abandon re-queues message
// ============================================================================

#[tokio::test]
async fn nats_abandon_requeues_message() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-abandon");

    p.send_message(&q, &msg("retry-me")).await.unwrap();

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

// ============================================================================
// Assertion 7: Session FIFO ordering
// ============================================================================

#[tokio::test]
async fn nats_session_delivers_in_fifo_order() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-session-fifo");
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
async fn nats_batch_send_returns_one_id_per_message() {
    let p = nats_provider(nats_port()).await;
    let q = queue("nats-batch");

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

async fn nats_provider(port: u16) -> NatsProvider {
    let config = NatsConfig {
        url: format!("nats://localhost:{}", port),
        stream_prefix: "test".to_string(),
        max_deliver: Some(5),
        ack_wait: Duration::seconds(30),
        session_lock_duration: Duration::minutes(5),
        enable_dead_letter: true,
        dead_letter_subject_prefix: Some("test-dlq".to_string()),
        credentials_path: None,
    };
    NatsProvider::new(config)
        .await
        .expect("connect to NATS test container")
}

// ============================================================================
// Assertion 1 + 3: Send succeeds; payload arrives intact
// ============================================================================

#[tokio::test]
async fn nats_send_and_receive_single_message() {
    let container = Nats::default()
        .with_cmd(["-js"]) // enable JetStream
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-send-receive");

    let body = "nats integration payload";
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
async fn nats_attributes_survive_round_trip() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-attr-rt");

    p.send_message(&q, &msg_with_attrs("body", "event-type", "push"))
        .await
        .expect("send");

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        received.attributes.get("event-type"),
        Some(&"push".to_string())
    );
}

// ============================================================================
// Assertion 4: Empty queue returns None
// ============================================================================

#[tokio::test]
async fn nats_receive_from_empty_queue_returns_none() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-empty");

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
async fn nats_complete_removes_message() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-complete");

    p.send_message(&q, &msg("complete-me")).await.unwrap();

    let received = p
        .receive_message(&q, Duration::seconds(10))
        .await
        .unwrap()
        .expect("must receive message");

    p.complete_message(&received.receipt_handle)
        .await
        .expect("complete must succeed");

    let recheck = p.receive_message(&q, Duration::seconds(2)).await.unwrap();
    assert!(recheck.is_none(), "completed message must not reappear");
}

// ============================================================================
// Abandon re-queues message
// ============================================================================

#[tokio::test]
async fn nats_abandon_requeues_message() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-abandon");

    p.send_message(&q, &msg("retry-me")).await.unwrap();

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

// ============================================================================
// Assertion 7: Session FIFO ordering
// ============================================================================

#[tokio::test]
async fn nats_session_delivers_in_fifo_order() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-session-fifo");
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
async fn nats_batch_send_returns_one_id_per_message() {
    let container = Nats::default()
        .with_cmd(["-js"])
        .start()
        .await
        .expect("start NATS container");

    let port = container.get_host_port_ipv4(4222).await.unwrap();
    let p = nats_provider(port).await;
    let q = queue("nats-batch");

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
