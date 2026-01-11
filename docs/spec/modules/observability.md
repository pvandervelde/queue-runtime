# Observability and Monitoring

This document defines the observability features for the Queue Runtime, including metrics, tracing, logging, and health monitoring.

## Overview

Comprehensive observability enables monitoring queue operations, diagnosing performance issues, tracking message flows, and maintaining system reliability across different cloud providers.

## Metrics Collection

### Core Queue Metrics

```rust
use prometheus::{
    Counter, Histogram, Gauge, IntCounter, IntGauge,
    register_counter, register_histogram, register_gauge,
    register_int_counter, register_int_gauge,
};

pub struct QueueMetrics {
    // Message throughput
    pub messages_sent_total: IntCounter,
    pub messages_received_total: IntCounter,
    pub messages_acknowledged_total: IntCounter,
    pub messages_rejected_total: IntCounter,
    pub messages_dead_lettered_total: IntCounter,

    // Processing latency
    pub message_processing_duration: Histogram,
    pub queue_send_duration: Histogram,
    pub queue_receive_duration: Histogram,

    // Queue depth and utilization
    pub queue_depth: IntGauge,
    pub active_sessions: IntGauge,
    pub processing_messages: IntGauge,

    // Error rates
    pub send_errors_total: IntCounter,
    pub receive_errors_total: IntCounter,
    pub processing_errors_total: IntCounter,

    // Session metrics
    pub session_created_total: IntCounter,
    pub session_closed_total: IntCounter,
    pub session_duration: Histogram,

    // Dead letter queue metrics
    pub dlq_messages_total: IntCounter,
    pub dlq_recovery_attempts_total: IntCounter,
    pub dlq_recovery_successes_total: IntCounter,
}

impl QueueMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            messages_sent_total: register_int_counter!(
                "queue_messages_sent_total",
                "Total number of messages sent to queues"
            )?,
            messages_received_total: register_int_counter!(
                "queue_messages_received_total",
                "Total number of messages received from queues"
            )?,
            messages_acknowledged_total: register_int_counter!(
                "queue_messages_acknowledged_total",
                "Total number of messages acknowledged"
            )?,
            messages_rejected_total: register_int_counter!(
                "queue_messages_rejected_total",
                "Total number of messages rejected"
            )?,
            messages_dead_lettered_total: register_int_counter!(
                "queue_messages_dead_lettered_total",
                "Total number of messages sent to dead letter queues"
            )?,

            message_processing_duration: register_histogram!(
                "queue_message_processing_duration_seconds",
                "Time spent processing messages",
                vec![0.001, 0.01, 0.1, 1.0, 10.0, 60.0, 300.0]
            )?,
            queue_send_duration: register_histogram!(
                "queue_send_duration_seconds",
                "Time spent sending messages to queue",
                vec![0.001, 0.01, 0.1, 1.0, 5.0]
            )?,
            queue_receive_duration: register_histogram!(
                "queue_receive_duration_seconds",
                "Time spent receiving messages from queue",
                vec![0.001, 0.01, 0.1, 1.0, 20.0]
            )?,

            queue_depth: register_int_gauge!(
                "queue_depth",
                "Current number of messages in queue"
            )?,
            active_sessions: register_int_gauge!(
                "queue_active_sessions",
                "Current number of active sessions"
            )?,
            processing_messages: register_int_gauge!(
                "queue_processing_messages",
                "Current number of messages being processed"
            )?,

            send_errors_total: register_int_counter!(
                "queue_send_errors_total",
                "Total number of send operation errors"
            )?,
            receive_errors_total: register_int_counter!(
                "queue_receive_errors_total",
                "Total number of receive operation errors"
            )?,
            processing_errors_total: register_int_counter!(
                "queue_processing_errors_total",
                "Total number of message processing errors"
            )?,

            session_created_total: register_int_counter!(
                "queue_sessions_created_total",
                "Total number of sessions created"
            )?,
            session_closed_total: register_int_counter!(
                "queue_sessions_closed_total",
                "Total number of sessions closed"
            )?,
            session_duration: register_histogram!(
                "queue_session_duration_seconds",
                "Duration of queue sessions",
                vec![1.0, 10.0, 60.0, 300.0, 1800.0, 3600.0]
            )?,

            dlq_messages_total: register_int_counter!(
                "queue_dlq_messages_total",
                "Total number of messages in dead letter queues"
            )?,
            dlq_recovery_attempts_total: register_int_counter!(
                "queue_dlq_recovery_attempts_total",
                "Total number of DLQ recovery attempts"
            )?,
            dlq_recovery_successes_total: register_int_counter!(
                "queue_dlq_recovery_successes_total",
                "Total number of successful DLQ recoveries"
            )?,
        })
    }

    pub fn record_message_sent(&self, queue_name: &str, duration: Duration) {
        self.messages_sent_total.inc();
        self.queue_send_duration.observe(duration.as_secs_f64());
    }

    pub fn record_message_received(&self, queue_name: &str, batch_size: usize, duration: Duration) {
        self.messages_received_total.inc_by(batch_size as u64);
        self.queue_receive_duration.observe(duration.as_secs_f64());
    }

    pub fn record_message_processed(&self, queue_name: &str, duration: Duration, success: bool) {
        if success {
            self.messages_acknowledged_total.inc();
        } else {
            self.messages_rejected_total.inc();
        }
        self.message_processing_duration.observe(duration.as_secs_f64());
    }

    pub fn record_send_error(&self, queue_name: &str, error_type: &str) {
        self.send_errors_total.inc();
    }

    pub fn record_processing_error(&self, queue_name: &str, error_type: &str) {
        self.processing_errors_total.inc();
    }

    pub fn record_session_activity(&self, queue_name: &str, session_created: bool, session_closed: bool, duration: Option<Duration>) {
        if session_created {
            self.session_created_total.inc();
            self.active_sessions.inc();
        }
        if session_closed {
            self.session_closed_total.inc();
            self.active_sessions.dec();
            if let Some(d) = duration {
                self.session_duration.observe(d.as_secs_f64());
            }
        }
    }

    pub fn record_dead_letter(&self, queue_name: &str, reason: &str) {
        self.messages_dead_lettered_total.inc();
        self.dlq_messages_total.inc();
    }

    pub fn update_queue_depth(&self, queue_name: &str, depth: i64) {
        self.queue_depth.set(depth);
    }

    pub fn update_processing_count(&self, delta: i64) {
        if delta > 0 {
            self.processing_messages.add(delta);
        } else {
            self.processing_messages.sub(-delta);
        }
    }
}
```

### Provider-Specific Metrics

```rust
pub struct ProviderMetrics {
    // Azure Service Bus specific
    pub azure_lock_renewals_total: IntCounter,
    pub azure_session_timeouts_total: IntCounter,
    pub azure_quota_exceeded_total: IntCounter,

    // AWS SQS specific
    pub aws_visibility_timeout_extensions_total: IntCounter,
    pub aws_throttling_errors_total: IntCounter,
    pub aws_fifo_deduplication_total: IntCounter,
}

impl ProviderMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            azure_lock_renewals_total: register_int_counter!(
                "azure_servicebus_lock_renewals_total",
                "Total number of Azure Service Bus message lock renewals"
            )?,
            azure_session_timeouts_total: register_int_counter!(
                "azure_servicebus_session_timeouts_total",
                "Total number of Azure Service Bus session timeouts"
            )?,
            azure_quota_exceeded_total: register_int_counter!(
                "azure_servicebus_quota_exceeded_total",
                "Total number of Azure Service Bus quota exceeded errors"
            )?,

            aws_visibility_timeout_extensions_total: register_int_counter!(
                "aws_sqs_visibility_timeout_extensions_total",
                "Total number of AWS SQS visibility timeout extensions"
            )?,
            aws_throttling_errors_total: register_int_counter!(
                "aws_sqs_throttling_errors_total",
                "Total number of AWS SQS throttling errors"
            )?,
            aws_fifo_deduplication_total: register_int_counter!(
                "aws_sqs_fifo_deduplication_total",
                "Total number of AWS SQS FIFO message deduplication events"
            )?,
        })
    }
}
```

## Distributed Tracing

### OpenTelemetry Integration

```rust
use opentelemetry::{
    trace::{Tracer, TraceId, SpanId, SpanContext, SpanKind, Status, StatusCode},
    Context, KeyValue,
};
use opentelemetry_sdk::trace::TracerProvider;
use tracing::{instrument, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct QueueTracing {
    tracer: Box<dyn Tracer + Send + Sync>,
}

impl QueueTracing {
    pub fn new(tracer: Box<dyn Tracer + Send + Sync>) -> Self {
        Self { tracer }
    }

    pub fn create_send_span(&self, queue_name: &str, message_id: &str, session_id: Option<&str>) -> Span {
        let span = self.tracer
            .span_builder(format!("queue.send"))
            .with_kind(SpanKind::Producer)
            .with_attributes(vec![
                KeyValue::new("queue.name", queue_name.to_string()),
                KeyValue::new("message.id", message_id.to_string()),
                KeyValue::new("queue.operation", "send"),
            ])
            .start(&Context::current());

        if let Some(session_id) = session_id {
            span.set_attribute(KeyValue::new("queue.session_id", session_id.to_string()));
        }

        // Convert OpenTelemetry span to tracing span
        let tracing_span = tracing::info_span!(
            "queue.send",
            queue.name = queue_name,
            message.id = message_id,
            queue.session_id = session_id,
        );

        tracing_span.set_parent(Context::current().with_span(span));
        tracing_span
    }

    pub fn create_receive_span(&self, queue_name: &str, max_messages: u32) -> Span {
        let span = self.tracer
            .span_builder("queue.receive")
            .with_kind(SpanKind::Consumer)
            .with_attributes(vec![
                KeyValue::new("queue.name", queue_name.to_string()),
                KeyValue::new("queue.max_messages", max_messages as i64),
                KeyValue::new("queue.operation", "receive"),
            ])
            .start(&Context::current());

        let tracing_span = tracing::info_span!(
            "queue.receive",
            queue.name = queue_name,
            queue.max_messages = max_messages,
        );

        tracing_span.set_parent(Context::current().with_span(span));
        tracing_span
    }

    pub fn create_process_span(&self, queue_name: &str, message_id: &str, session_id: Option<&str>) -> Span {
        let span = self.tracer
            .span_builder("queue.process")
            .with_kind(SpanKind::Consumer)
            .with_attributes(vec![
                KeyValue::new("queue.name", queue_name.to_string()),
                KeyValue::new("message.id", message_id.to_string()),
                KeyValue::new("queue.operation", "process"),
            ])
            .start(&Context::current());

        if let Some(session_id) = session_id {
            span.set_attribute(KeyValue::new("queue.session_id", session_id.to_string()));
        }

        let tracing_span = tracing::info_span!(
            "queue.process",
            queue.name = queue_name,
            message.id = message_id,
            queue.session_id = session_id,
        );

        tracing_span.set_parent(Context::current().with_span(span));
        tracing_span
    }

    pub fn extract_trace_context(&self, message_attributes: &HashMap<String, String>) -> Option<SpanContext> {
        // Extract trace context from message attributes (W3C Trace Context format)
        let traceparent = message_attributes.get("traceparent")?;
        self.parse_traceparent(traceparent)
    }

    pub fn inject_trace_context(&self, span_context: &SpanContext) -> HashMap<String, String> {
        let mut attributes = HashMap::new();

        // Inject trace context as W3C Trace Context
        let traceparent = format!(
            "00-{:032x}-{:016x}-01",
            span_context.trace_id().to_u128(),
            span_context.span_id().to_u64()
        );

        attributes.insert("traceparent".to_string(), traceparent);
        attributes
    }

    fn parse_traceparent(&self, traceparent: &str) -> Option<SpanContext> {
        let parts: Vec<&str> = traceparent.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let trace_id = TraceId::from_hex(parts[1]).ok()?;
        let span_id = SpanId::from_hex(parts[2]).ok()?;

        Some(SpanContext::new(
            trace_id,
            span_id,
            opentelemetry::trace::TraceFlags::SAMPLED,
            false,
            Default::default(),
        ))
    }
}
```

### Instrumented Queue Client

```rust
pub struct InstrumentedQueueClient<T, C> {
    inner: C,
    metrics: Arc<QueueMetrics>,
    tracing: Arc<QueueTracing>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T, C> InstrumentedQueueClient<T, C>
where
    C: QueueClient<T>,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(inner: C, metrics: Arc<QueueMetrics>, tracing: Arc<QueueTracing>) -> Self {
        Self {
            inner,
            metrics,
            tracing,
            _phantom: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T, C> QueueClient<T> for InstrumentedQueueClient<T, C>
where
    C: QueueClient<T> + Send + Sync,
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type Receipt = C::Receipt;

    #[instrument(skip(self, message), fields(queue.name = queue_name, queue.session_id = session_id))]
    async fn send(&self, queue_name: &str, message: &T, session_id: Option<&str>) -> Result<MessageId, QueueError> {
        let start_time = Instant::now();
        let message_id = uuid::Uuid::new_v4().to_string();

        let _span = self.tracing.create_send_span(queue_name, &message_id, session_id);

        let result = self.inner.send(queue_name, message, session_id).await;
        let duration = start_time.elapsed();

        match &result {
            Ok(actual_message_id) => {
                self.metrics.record_message_sent(queue_name, duration);
                tracing::info!(
                    message.id = %actual_message_id,
                    duration_ms = duration.as_millis(),
                    "Message sent successfully"
                );
            }
            Err(error) => {
                self.metrics.record_send_error(queue_name, &format!("{:?}", error));
                tracing::error!(
                    error = %error,
                    duration_ms = duration.as_millis(),
                    "Failed to send message"
                );
            }
        }

        result
    }

    #[instrument(skip(self), fields(queue.name = queue_name, queue.max_messages = max_messages))]
    async fn receive(&self, queue_name: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError> {
        let start_time = Instant::now();

        let _span = self.tracing.create_receive_span(queue_name, max_messages);

        let result = self.inner.receive(queue_name, max_messages).await;
        let duration = start_time.elapsed();

        match &result {
            Ok(messages) => {
                self.metrics.record_message_received(queue_name, messages.len(), duration);
                tracing::info!(
                    messages_received = messages.len(),
                    duration_ms = duration.as_millis(),
                    "Messages received successfully"
                );

                // Update processing count
                self.metrics.update_processing_count(messages.len() as i64);

                // Log individual message details
                for message in messages {
                    tracing::debug!(
                        message.id = %message.message_id,
                        delivery_count = message.delivery_count,
                        session_id = message.session_id.as_deref(),
                        "Received message"
                    );
                }
            }
            Err(error) => {
                self.metrics.record_send_error(queue_name, &format!("{:?}", error));
                tracing::error!(
                    error = %error,
                    duration_ms = duration.as_millis(),
                    "Failed to receive messages"
                );
            }
        }

        result
    }

    #[instrument(skip(self, receipt), fields(message.id = receipt.message_id()))]
    async fn acknowledge(&self, receipt: &Self::Receipt) -> Result<(), QueueError> {
        let start_time = Instant::now();

        let result = self.inner.acknowledge(receipt).await;
        let duration = start_time.elapsed();

        match &result {
            Ok(_) => {
                self.metrics.messages_acknowledged_total.inc();
                self.metrics.update_processing_count(-1);
                tracing::debug!(
                    duration_ms = duration.as_millis(),
                    "Message acknowledged"
                );
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    duration_ms = duration.as_millis(),
                    "Failed to acknowledge message"
                );
            }
        }

        result
    }

    #[instrument(skip(self, receipt), fields(message.id = receipt.message_id()))]
    async fn reject(&self, receipt: &Self::Receipt) -> Result<(), QueueError> {
        let start_time = Instant::now();

        let result = self.inner.reject(receipt).await;
        let duration = start_time.elapsed();

        match &result {
            Ok(_) => {
                self.metrics.messages_rejected_total.inc();
                self.metrics.update_processing_count(-1);
                tracing::warn!(
                    duration_ms = duration.as_millis(),
                    "Message rejected"
                );
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    duration_ms = duration.as_millis(),
                    "Failed to reject message"
                );
            }
        }

        result
    }

    #[instrument(skip(self, receipt), fields(message.id = receipt.message_id(), reason = reason))]
    async fn dead_letter(&self, receipt: &Self::Receipt, reason: &str) -> Result<(), QueueError> {
        let start_time = Instant::now();

        let result = self.inner.dead_letter(receipt, reason).await;
        let duration = start_time.elapsed();

        match &result {
            Ok(_) => {
                self.metrics.record_dead_letter("unknown", reason); // Queue name not available here
                self.metrics.update_processing_count(-1);
                tracing::warn!(
                    reason = reason,
                    duration_ms = duration.as_millis(),
                    "Message dead lettered"
                );
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    reason = reason,
                    duration_ms = duration.as_millis(),
                    "Failed to dead letter message"
                );
            }
        }

        result
    }
}
```

## Health Monitoring

### Health Check Implementation

```rust
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub status: HealthState,
    pub timestamp: DateTime<Utc>,
    pub checks: HashMap<String, HealthCheckResult>,
    pub summary: HealthSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: HealthState,
    pub duration: Duration,
    pub message: Option<String>,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSummary {
    pub total_checks: u32,
    pub healthy_checks: u32,
    pub degraded_checks: u32,
    pub unhealthy_checks: u32,
    pub total_duration: Duration,
}

#[async_trait]
pub trait HealthCheck: Send + Sync {
    async fn check(&self) -> HealthCheckResult;
    fn name(&self) -> &str;
}

pub struct QueueHealthMonitor {
    checks: Vec<Box<dyn HealthCheck>>,
    cache_duration: Duration,
    cached_status: Arc<RwLock<Option<(HealthStatus, Instant)>>>,
}

impl QueueHealthMonitor {
    pub fn new(cache_duration: Duration) -> Self {
        Self {
            checks: Vec::new(),
            cache_duration,
            cached_status: Arc::new(RwLock::new(None)),
        }
    }

    pub fn add_check(&mut self, check: Box<dyn HealthCheck>) {
        self.checks.push(check);
    }

    pub async fn check_health(&self) -> HealthStatus {
        // Check cache first
        {
            let cached = self.cached_status.read().await;
            if let Some((status, timestamp)) = cached.as_ref() {
                if timestamp.elapsed() < self.cache_duration {
                    return status.clone();
                }
            }
        }

        // Perform health checks
        let start_time = Instant::now();
        let mut check_results = HashMap::new();
        let mut tasks = Vec::new();

        for check in &self.checks {
            let check_name = check.name().to_string();
            tasks.push(async move {
                let result = check.check().await;
                (check_name, result)
            });
        }

        // Execute all checks concurrently with timeout
        let results = timeout(Duration::from_secs(30), futures::future::join_all(tasks)).await;

        match results {
            Ok(check_results_vec) => {
                for (name, result) in check_results_vec {
                    check_results.insert(name, result);
                }
            }
            Err(_) => {
                // Timeout occurred
                for check in &self.checks {
                    check_results.entry(check.name().to_string()).or_insert(HealthCheckResult {
                        status: HealthState::Unhealthy,
                        duration: Duration::from_secs(30),
                        message: Some("Health check timed out".to_string()),
                        details: HashMap::new(),
                    });
                }
            }
        }

        let total_duration = start_time.elapsed();

        // Calculate overall status
        let overall_status = self.calculate_overall_status(&check_results);

        let summary = HealthSummary {
            total_checks: check_results.len() as u32,
            healthy_checks: check_results.values().filter(|r| r.status == HealthState::Healthy).count() as u32,
            degraded_checks: check_results.values().filter(|r| r.status == HealthState::Degraded).count() as u32,
            unhealthy_checks: check_results.values().filter(|r| r.status == HealthState::Unhealthy).count() as u32,
            total_duration,
        };

        let health_status = HealthStatus {
            status: overall_status,
            timestamp: Utc::now(),
            checks: check_results,
            summary,
        };

        // Update cache
        {
            let mut cached = self.cached_status.write().await;
            *cached = Some((health_status.clone(), Instant::now()));
        }

        health_status
    }

    fn calculate_overall_status(&self, checks: &HashMap<String, HealthCheckResult>) -> HealthState {
        if checks.values().any(|r| r.status == HealthState::Unhealthy) {
            HealthState::Unhealthy
        } else if checks.values().any(|r| r.status == HealthState::Degraded) {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        }
    }
}
```

### Specific Health Checks

```rust
pub struct QueueConnectionHealthCheck<T> {
    queue_client: Arc<dyn QueueClient<T>>,
    test_queue_name: String,
}

impl<T> QueueConnectionHealthCheck<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    pub fn new(queue_client: Arc<dyn QueueClient<T>>, test_queue_name: String) -> Self {
        Self {
            queue_client,
            test_queue_name,
        }
    }
}

#[async_trait]
impl<T> HealthCheck for QueueConnectionHealthCheck<T>
where
    T: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    async fn check(&self) -> HealthCheckResult {
        let start_time = Instant::now();

        // Try to receive from queue (non-blocking)
        match self.queue_client.receive(&self.test_queue_name, 1).await {
            Ok(_) => HealthCheckResult {
                status: HealthState::Healthy,
                duration: start_time.elapsed(),
                message: Some("Queue connection is healthy".to_string()),
                details: HashMap::new(),
            },
            Err(QueueError::QueueNotFound(_)) => HealthCheckResult {
                status: HealthState::Degraded,
                duration: start_time.elapsed(),
                message: Some("Test queue not found, but connection works".to_string()),
                details: HashMap::new(),
            },
            Err(error) => HealthCheckResult {
                status: HealthState::Unhealthy,
                duration: start_time.elapsed(),
                message: Some(format!("Queue connection failed: {}", error)),
                details: HashMap::from([("error".to_string(), error.to_string())]),
            },
        }
    }

    fn name(&self) -> &str {
        "queue_connection"
    }
}

pub struct MessageProcessingHealthCheck {
    metrics: Arc<QueueMetrics>,
    error_rate_threshold: f64, // e.g., 0.1 for 10%
    response_time_threshold: Duration,
}

impl MessageProcessingHealthCheck {
    pub fn new(metrics: Arc<QueueMetrics>, error_rate_threshold: f64, response_time_threshold: Duration) -> Self {
        Self {
            metrics,
            error_rate_threshold,
            response_time_threshold,
        }
    }
}

#[async_trait]
impl HealthCheck for MessageProcessingHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start_time = Instant::now();

        // Calculate error rate
        let total_processed = self.metrics.messages_acknowledged_total.get() + self.metrics.messages_rejected_total.get();
        let total_errors = self.metrics.processing_errors_total.get();

        let error_rate = if total_processed > 0 {
            total_errors as f64 / total_processed as f64
        } else {
            0.0
        };

        // Check average processing time
        let avg_processing_time = Duration::from_secs_f64(
            self.metrics.message_processing_duration.get_sample_sum() /
            self.metrics.message_processing_duration.get_sample_count() as f64
        );

        let mut details = HashMap::new();
        details.insert("error_rate".to_string(), format!("{:.2}%", error_rate * 100.0));
        details.insert("avg_processing_time".to_string(), format!("{:.2}s", avg_processing_time.as_secs_f64()));
        details.insert("total_processed".to_string(), total_processed.to_string());
        details.insert("total_errors".to_string(), total_errors.to_string());

        let status = if error_rate > self.error_rate_threshold {
            HealthState::Unhealthy
        } else if avg_processing_time > self.response_time_threshold {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        };

        let message = match status {
            HealthState::Healthy => Some("Message processing is healthy".to_string()),
            HealthState::Degraded => Some(format!("Slow processing: avg {:.2}s", avg_processing_time.as_secs_f64())),
            HealthState::Unhealthy => Some(format!("High error rate: {:.2}%", error_rate * 100.0)),
        };

        HealthCheckResult {
            status,
            duration: start_time.elapsed(),
            message,
            details,
        }
    }

    fn name(&self) -> &str {
        "message_processing"
    }
}

pub struct DeadLetterQueueHealthCheck {
    dlq_manager: Arc<dyn DeadLetterQueueManager<serde_json::Value>>,
    queue_names: Vec<String>,
    dlq_threshold: u64, // Alert if DLQ has more than this many messages
}

#[async_trait]
impl HealthCheck for DeadLetterQueueHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start_time = Instant::now();
        let mut total_dlq_messages = 0u64;
        let mut unhealthy_queues = Vec::new();
        let mut details = HashMap::new();

        for queue_name in &self.queue_names {
            match self.dlq_manager.get_dlq_stats(queue_name).await {
                Ok(stats) => {
                    total_dlq_messages += stats.total_messages;
                    details.insert(
                        format!("{}_dlq_count", queue_name),
                        stats.total_messages.to_string()
                    );

                    if stats.total_messages > self.dlq_threshold {
                        unhealthy_queues.push(queue_name.clone());
                    }
                }
                Err(error) => {
                    details.insert(
                        format!("{}_dlq_error", queue_name),
                        error.to_string()
                    );
                    unhealthy_queues.push(queue_name.clone());
                }
            }
        }

        details.insert("total_dlq_messages".to_string(), total_dlq_messages.to_string());
        details.insert("monitored_queues".to_string(), self.queue_names.len().to_string());

        let status = if !unhealthy_queues.is_empty() {
            HealthState::Unhealthy
        } else if total_dlq_messages > 0 {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        };

        let message = match status {
            HealthState::Healthy => Some("No dead letter messages".to_string()),
            HealthState::Degraded => Some(format!("{} messages in dead letter queues", total_dlq_messages)),
            HealthState::Unhealthy => Some(format!("High DLQ volume in queues: {}", unhealthy_queues.join(", "))),
        };

        HealthCheckResult {
            status,
            duration: start_time.elapsed(),
            message,
            details,
        }
    }

    fn name(&self) -> &str {
        "dead_letter_queues"
    }
}
```

## Logging Configuration

### Structured Logging

```rust
use tracing::{Level, field::{Field, Visit}};
use tracing_subscriber::{
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub struct QueueLoggingConfig {
    pub level: Level,
    pub json_format: bool,
    pub file_logging: Option<FileLoggingConfig>,
    pub include_trace_id: bool,
    pub include_span_id: bool,
    pub sensitive_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FileLoggingConfig {
    pub directory: String,
    pub file_prefix: String,
    pub rotation: Rotation,
    pub max_files: usize,
}

impl QueueLoggingConfig {
    pub fn init_logging(&self) -> Result<(), Box<dyn std::error::Error>> {
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(self.level.to_string()));

        let mut layers = Vec::new();

        // Console layer
        if self.json_format {
            let console_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false);
            layers.push(console_layer.boxed());
        } else {
            let console_layer = tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_current_span(true);
            layers.push(console_layer.boxed());
        }

        // File layer
        if let Some(file_config) = &self.file_logging {
            let file_appender = RollingFileAppender::builder()
                .rotation(file_config.rotation)
                .filename_prefix(&file_config.file_prefix)
                .max_log_files(file_config.max_files)
                .build(&file_config.directory)?;

            let file_layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(file_appender)
                .with_current_span(true);

            layers.push(file_layer.boxed());
        }

        // OpenTelemetry layer for distributed tracing
        let tracer = opentelemetry_jaeger::new_agent_pipeline()
            .with_service_name("queue-runtime")
            .install_simple()?;

        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        layers.push(telemetry_layer.boxed());

        // Custom filtering layer for sensitive fields
        let filtering_layer = SensitiveFieldFilter::new(self.sensitive_fields.clone());
        layers.push(filtering_layer.boxed());

        Registry::default()
            .with(env_filter)
            .with(layers)
            .init();

        Ok(())
    }
}

struct SensitiveFieldFilter {
    sensitive_fields: Vec<String>,
}

impl SensitiveFieldFilter {
    fn new(sensitive_fields: Vec<String>) -> Self {
        Self { sensitive_fields }
    }

    fn should_redact(&self, field_name: &str) -> bool {
        self.sensitive_fields.iter().any(|pattern| {
            field_name.contains(pattern) ||
            field_name.to_lowercase().contains(&pattern.to_lowercase())
        })
    }
}

impl<S> tracing_subscriber::Layer<S> for SensitiveFieldFilter
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let mut visitor = SensitiveFieldVisitor::new(&self.sensitive_fields);
        event.record(&mut visitor);

        if visitor.has_sensitive_data {
            // Log a warning about redacted fields
            tracing::warn!("Sensitive fields redacted from log event");
        }
    }
}

struct SensitiveFieldVisitor {
    sensitive_fields: Vec<String>,
    has_sensitive_data: bool,
}

impl SensitiveFieldVisitor {
    fn new(sensitive_fields: &[String]) -> Self {
        Self {
            sensitive_fields: sensitive_fields.to_vec(),
            has_sensitive_data: false,
        }
    }
}

impl Visit for SensitiveFieldVisitor {
    fn record_debug(&mut self, field: &Field, _value: &dyn std::fmt::Debug) {
        if self.sensitive_fields.iter().any(|pattern| field.name().contains(pattern)) {
            self.has_sensitive_data = true;
        }
    }

    fn record_str(&mut self, field: &Field, _value: &str) {
        if self.sensitive_fields.iter().any(|pattern| field.name().contains(pattern)) {
            self.has_sensitive_data = true;
        }
    }
}
```

## Alerting and Notifications

### Alert Manager

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub name: String,
    pub description: String,
    pub condition: AlertCondition,
    pub severity: AlertSeverity,
    pub cooldown: Duration,
    pub channels: Vec<AlertChannel>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertCondition {
    MetricThreshold {
        metric_name: String,
        operator: ComparisonOperator,
        threshold: f64,
        duration: Duration,
    },
    ErrorRate {
        threshold: f64,
        window: Duration,
    },
    HealthCheckFailure {
        check_name: String,
        consecutive_failures: u32,
    },
    QueueDepth {
        queue_name: String,
        threshold: u64,
        duration: Duration,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOperator {
    GreaterThan,
    LessThan,
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertChannel {
    Log,
    Email { recipients: Vec<String> },
    Slack { webhook_url: String, channel: String },
    PagerDuty { integration_key: String },
    Webhook { url: String, headers: HashMap<String, String> },
}

pub struct AlertManager {
    rules: Vec<AlertRule>,
    metrics: Arc<QueueMetrics>,
    health_monitor: Arc<QueueHealthMonitor>,
    active_alerts: Arc<RwLock<HashMap<String, AlertState>>>,
}

#[derive(Debug, Clone)]
struct AlertState {
    rule_name: String,
    triggered_at: DateTime<Utc>,
    last_notification: DateTime<Utc>,
    consecutive_triggers: u32,
}

impl AlertManager {
    pub fn new(
        rules: Vec<AlertRule>,
        metrics: Arc<QueueMetrics>,
        health_monitor: Arc<QueueHealthMonitor>,
    ) -> Self {
        Self {
            rules,
            metrics,
            health_monitor,
            active_alerts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start_monitoring(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));

        loop {
            interval.tick().await;
            self.evaluate_rules().await;
        }
    }

    async fn evaluate_rules(&self) {
        for rule in &self.rules {
            if self.evaluate_condition(&rule.condition).await {
                self.trigger_alert(rule).await;
            } else {
                self.clear_alert(&rule.name).await;
            }
        }
    }

    async fn evaluate_condition(&self, condition: &AlertCondition) -> bool {
        match condition {
            AlertCondition::MetricThreshold { metric_name, operator, threshold, duration: _ } => {
                // Simplified metric evaluation
                self.evaluate_metric_threshold(metric_name, operator, *threshold)
            }
            AlertCondition::ErrorRate { threshold, window: _ } => {
                let total_processed = self.metrics.messages_acknowledged_total.get() + self.metrics.messages_rejected_total.get();
                let total_errors = self.metrics.processing_errors_total.get();

                if total_processed == 0 {
                    return false;
                }

                let error_rate = total_errors as f64 / total_processed as f64;
                error_rate > *threshold
            }
            AlertCondition::HealthCheckFailure { check_name, consecutive_failures: _ } => {
                let health_status = self.health_monitor.check_health().await;
                health_status.checks.get(check_name)
                    .map(|check| check.status != HealthState::Healthy)
                    .unwrap_or(false)
            }
            AlertCondition::QueueDepth { queue_name: _, threshold, duration: _ } => {
                self.metrics.queue_depth.get() as u64 > *threshold
            }
        }
    }

    fn evaluate_metric_threshold(&self, metric_name: &str, operator: &ComparisonOperator, threshold: f64) -> bool {
        let value = match metric_name {
            "messages_sent_total" => self.metrics.messages_sent_total.get() as f64,
            "messages_received_total" => self.metrics.messages_received_total.get() as f64,
            "processing_errors_total" => self.metrics.processing_errors_total.get() as f64,
            "queue_depth" => self.metrics.queue_depth.get() as f64,
            "active_sessions" => self.metrics.active_sessions.get() as f64,
            _ => return false,
        };

        match operator {
            ComparisonOperator::GreaterThan => value > threshold,
            ComparisonOperator::LessThan => value < threshold,
            ComparisonOperator::Equal => (value - threshold).abs() < f64::EPSILON,
        }
    }

    async fn trigger_alert(&self, rule: &AlertRule) {
        let mut active_alerts = self.active_alerts.write().await;
        let now = Utc::now();

        if let Some(alert_state) = active_alerts.get_mut(&rule.name) {
            // Check cooldown
            if now.signed_duration_since(alert_state.last_notification) < chrono::Duration::from_std(rule.cooldown).unwrap() {
                return;
            }

            alert_state.last_notification = now;
            alert_state.consecutive_triggers += 1;
        } else {
            // New alert
            active_alerts.insert(rule.name.clone(), AlertState {
                rule_name: rule.name.clone(),
                triggered_at: now,
                last_notification: now,
                consecutive_triggers: 1,
            });
        }

        // Send notifications
        for channel in &rule.channels {
            if let Err(e) = self.send_notification(channel, rule).await {
                tracing::error!("Failed to send alert notification: {}", e);
            }
        }

        tracing::warn!(
            alert.name = %rule.name,
            alert.severity = ?rule.severity,
            "Alert triggered"
        );
    }

    async fn clear_alert(&self, rule_name: &str) {
        let mut active_alerts = self.active_alerts.write().await;
        if active_alerts.remove(rule_name).is_some() {
            tracing::info!(alert.name = %rule_name, "Alert cleared");
        }
    }

    async fn send_notification(&self, channel: &AlertChannel, rule: &AlertRule) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match channel {
            AlertChannel::Log => {
                tracing::warn!(
                    alert.name = %rule.name,
                    alert.description = %rule.description,
                    alert.severity = ?rule.severity,
                    "ALERT"
                );
            }
            AlertChannel::Email { recipients } => {
                // Implementation would depend on email service
                tracing::info!("Would send email alert to: {:?}", recipients);
            }
            AlertChannel::Slack { webhook_url, channel } => {
                // Implementation would use reqwest to post to Slack webhook
                tracing::info!("Would send Slack alert to channel: {}", channel);
            }
            AlertChannel::PagerDuty { integration_key } => {
                // Implementation would use PagerDuty API
                tracing::info!("Would trigger PagerDuty alert with key: {}", integration_key);
            }
            AlertChannel::Webhook { url, headers } => {
                // Implementation would make HTTP POST to webhook URL
                tracing::info!("Would send webhook alert to: {}", url);
            }
        }

        Ok(())
    }
}
```

## Dashboard Integration

### Grafana Dashboard Configuration

```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaDashboard {
    pub id: Option<u32>,
    pub title: String,
    pub tags: Vec<String>,
    pub timezone: String,
    pub panels: Vec<GrafanaPanel>,
    pub time: GrafanaTimeRange,
    pub refresh: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaPanel {
    pub id: u32,
    pub title: String,
    pub panel_type: String, // "graph", "stat", "table", etc.
    pub targets: Vec<GrafanaTarget>,
    pub grid_pos: GrafanaGridPos,
    pub options: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaTarget {
    pub expr: String, // Prometheus query
    pub legend_format: String,
    pub ref_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaGridPos {
    pub h: u32, // height
    pub w: u32, // width
    pub x: u32, // x position
    pub y: u32, // y position
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrafanaTimeRange {
    pub from: String,
    pub to: String,
}

pub fn create_queue_runtime_dashboard() -> GrafanaDashboard {
    GrafanaDashboard {
        id: None,
        title: "Queue Runtime Monitoring".to_string(),
        tags: vec!["queue".to_string(), "runtime".to_string()],
        timezone: "UTC".to_string(),
        panels: vec![
            // Message throughput panel
            GrafanaPanel {
                id: 1,
                title: "Message Throughput".to_string(),
                panel_type: "graph".to_string(),
                targets: vec![
                    GrafanaTarget {
                        expr: "rate(queue_messages_sent_total[5m])".to_string(),
                        legend_format: "Messages Sent/sec".to_string(),
                        ref_id: "A".to_string(),
                    },
                    GrafanaTarget {
                        expr: "rate(queue_messages_received_total[5m])".to_string(),
                        legend_format: "Messages Received/sec".to_string(),
                        ref_id: "B".to_string(),
                    },
                ],
                grid_pos: GrafanaGridPos { h: 8, w: 12, x: 0, y: 0 },
                options: serde_json::json!({}),
            },
            // Error rate panel
            GrafanaPanel {
                id: 2,
                title: "Error Rate".to_string(),
                panel_type: "stat".to_string(),
                targets: vec![
                    GrafanaTarget {
                        expr: "rate(queue_processing_errors_total[5m]) / rate(queue_messages_received_total[5m]) * 100".to_string(),
                        legend_format: "Error Rate %".to_string(),
                        ref_id: "A".to_string(),
                    },
                ],
                grid_pos: GrafanaGridPos { h: 8, w: 12, x: 12, y: 0 },
                options: serde_json::json!({
                    "colorMode": "background",
                    "thresholds": {
                        "steps": [
                            {"color": "green", "value": 0},
                            {"color": "yellow", "value": 5},
                            {"color": "red", "value": 10}
                        ]
                    }
                }),
            },
            // Queue depth panel
            GrafanaPanel {
                id: 3,
                title: "Queue Depth".to_string(),
                panel_type: "graph".to_string(),
                targets: vec![
                    GrafanaTarget {
                        expr: "queue_depth".to_string(),
                        legend_format: "Messages in Queue".to_string(),
                        ref_id: "A".to_string(),
                    },
                ],
                grid_pos: GrafanaGridPos { h: 8, w: 24, x: 0, y: 8 },
                options: serde_json::json!({}),
            },
        ],
        time: GrafanaTimeRange {
            from: "now-1h".to_string(),
            to: "now".to_string(),
        },
        refresh: "30s".to_string(),
    }
}
```

## Testing Support

```rust
#[cfg(test)]
pub mod testing {
    use super::*;

    pub struct MockMetrics {
        pub counters: HashMap<String, u64>,
        pub gauges: HashMap<String, i64>,
        pub histograms: HashMap<String, Vec<f64>>,
    }

    impl MockMetrics {
        pub fn new() -> Self {
            Self {
                counters: HashMap::new(),
                gauges: HashMap::new(),
                histograms: HashMap::new(),
            }
        }

        pub fn increment_counter(&mut self, name: &str, value: u64) {
            *self.counters.entry(name.to_string()).or_insert(0) += value;
        }

        pub fn set_gauge(&mut self, name: &str, value: i64) {
            self.gauges.insert(name.to_string(), value);
        }

        pub fn record_histogram(&mut self, name: &str, value: f64) {
            self.histograms.entry(name.to_string()).or_default().push(value);
        }
    }

    pub struct TestHealthCheck {
        name: String,
        status: HealthState,
        duration: Duration,
        message: Option<String>,
    }

    impl TestHealthCheck {
        pub fn healthy(name: &str) -> Self {
            Self {
                name: name.to_string(),
                status: HealthState::Healthy,
                duration: Duration::from_millis(10),
                message: Some("Test check is healthy".to_string()),
            }
        }

        pub fn unhealthy(name: &str, message: &str) -> Self {
            Self {
                name: name.to_string(),
                status: HealthState::Unhealthy,
                duration: Duration::from_millis(10),
                message: Some(message.to_string()),
            }
        }
    }

    #[async_trait]
    impl HealthCheck for TestHealthCheck {
        async fn check(&self) -> HealthCheckResult {
            HealthCheckResult {
                status: self.status.clone(),
                duration: self.duration,
                message: self.message.clone(),
                details: HashMap::new(),
            }
        }

        fn name(&self) -> &str {
            &self.name
        }
    }
}
```

## Best Practices

1. **Comprehensive Metrics**: Track both technical and business metrics
2. **Distributed Tracing**: Enable end-to-end request tracing across services
3. **Structured Logging**: Use consistent, searchable log formats
4. **Health Monitoring**: Implement proactive health checks
5. **Alerting Strategy**: Set up meaningful alerts with appropriate thresholds
6. **Dashboard Design**: Create actionable dashboards for operators
7. **Performance Monitoring**: Track latency and throughput metrics
8. **Security Logging**: Audit access and operations without exposing sensitive data
