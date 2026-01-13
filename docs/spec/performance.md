# Performance Optimization

This document defines performance optimization strategies, benchmarking guidelines, and scalability patterns for the queue-runtime. It provides guidance for achieving optimal throughput, latency, and resource utilization across different deployment scenarios.

## Overview

Performance optimization in queue-runtime focuses on maximizing message throughput while minimizing latency and resource consumption. Different optimization strategies apply depending on workload characteristics, provider capabilities, and infrastructure constraints.

## Performance Metrics and Targets

### Key Performance Indicators

**Throughput Metrics**:

- Messages processed per second (msg/s)
- Batch processing efficiency (messages per batch operation)
- Sustained throughput over time periods
- Peak throughput capacity

**Latency Metrics**:

- End-to-end message processing latency (p50, p95, p99)
- Queue operation latency (send, receive, acknowledge)
- Provider API call latency
- Session processing latency

**Resource Metrics**:

- CPU utilization patterns
- Memory consumption and garbage collection
- Network bandwidth utilization
- Connection pool efficiency

**Reliability Metrics**:

- Error rate and retry frequency
- Circuit breaker activation patterns
- Dead letter queue accumulation
- Connection failure and recovery time

### Performance Targets by Environment

#### Production Environment

```yaml
performance_targets:
  throughput:
    messages_per_second: 1000
    batch_efficiency: ">90%"
    sustained_duration: "1 hour"

  latency:
    p50_message_latency: "<100ms"
    p95_message_latency: "<500ms"
    p99_message_latency: "<1000ms"
    api_call_latency: "<50ms"

  reliability:
    error_rate: "<0.1%"
    availability: ">99.9%"
    circuit_breaker_frequency: "<1 per day"

  resources:
    cpu_utilization: "<70%"
    memory_utilization: "<80%"
    connection_pool_efficiency: ">95%"
```

#### Development Environment

```yaml
performance_targets:
  throughput:
    messages_per_second: 100
    batch_efficiency: ">80%"

  latency:
    p95_message_latency: "<1000ms"
    api_call_latency: "<200ms"

  reliability:
    error_rate: "<1%"
    availability: ">95%"
```

## Provider-Specific Optimization

### Azure Service Bus Optimization

#### Connection Management

**Connection Pooling Strategy**:

- Maintain persistent connections with automatic renewal
- Configure connection multiplexing for multiple queues
- Implement exponential backoff for connection failures
- Use managed identity to avoid credential management overhead

**Configuration Tuning**:

```rust
pub struct OptimizedAzureConfig {
    pub max_concurrent_calls: u32,        // 16-32 for high throughput
    pub prefetch_count: u32,              // 10-50 based on processing speed
    pub max_auto_lock_renewal_duration: Duration, // 5-10 minutes
    pub transport_type: TransportType,    // AMQP for performance
    pub retry_policy: RetryPolicy,        // Custom exponential backoff
}

impl OptimizedAzureConfig {
    pub fn for_high_throughput() -> Self {
        Self {
            max_concurrent_calls: 32,
            prefetch_count: 50,
            max_auto_lock_renewal_duration: Duration::from_minutes(10),
            transport_type: TransportType::Amqp,
            retry_policy: RetryPolicy::exponential_backoff(
                Duration::from_millis(100),
                Duration::from_seconds(30),
                3.0
            ),
        }
    }

    pub fn for_low_latency() -> Self {
        Self {
            max_concurrent_calls: 4,
            prefetch_count: 1,
            max_auto_lock_renewal_duration: Duration::from_minutes(1),
            transport_type: TransportType::Amqp,
            retry_policy: RetryPolicy::fixed_interval(Duration::from_millis(50)),
        }
    }
}
```

#### Session Processing Optimization

**Session Affinity Patterns**:

- Distribute sessions across multiple consumers
- Implement session load balancing strategies
- Monitor session processing duration and queuing
- Configure session timeout based on processing characteristics

**Batch Processing Within Sessions**:

- Process multiple messages per session lock
- Implement session-aware batch acknowledgment
- Balance throughput vs ordering requirements
- Handle session timeout gracefully during batch processing

### AWS SQS Optimization

#### Queue Configuration Tuning

**FIFO vs Standard Queue Selection**:

- Use Standard queues for maximum throughput (>3000 msg/s)
- Use FIFO queues for strict ordering requirements
- Consider multiple FIFO queues with different message groups
- Implement sharding strategies for high-throughput FIFO scenarios

**Polling Optimization**:

```rust
pub struct OptimizedSqsConfig {
    pub max_number_of_messages: i32,      // 10 for batch efficiency
    pub wait_time_seconds: Option<Duration>, // 20s for long polling
    pub visibility_timeout: Option<Duration>, // Based on processing time
    pub receive_request_attempt_id: Option<String>, // For deduplication
}

impl OptimizedSqsConfig {
    pub fn for_high_throughput() -> Self {
        Self {
            max_number_of_messages: 10,
            wait_time_seconds: Some(Duration::from_secs(20)),
            visibility_timeout: Some(Duration::from_secs(300)), // 5 minutes
            receive_request_attempt_id: Some(uuid::Uuid::new_v4().to_string()),
        }
    }

    pub fn for_cost_optimization() -> Self {
        Self {
            max_number_of_messages: 10,
            wait_time_seconds: Some(Duration::from_secs(20)), // Reduce empty receives
            visibility_timeout: Some(Duration::from_secs(30)),
            receive_request_attempt_id: None,
        }
    }
}
```

#### Batch Operation Patterns

**Send Batching Strategy**:

- Accumulate messages for batch sending (up to 10 messages)
- Implement time-based and size-based batching triggers
- Handle partial batch failures gracefully
- Monitor batch size distribution for optimization

**Receive Batching Strategy**:

- Always request maximum messages per receive call
- Implement parallel processing of batch messages
- Use message-level acknowledgment patterns
- Handle visibility timeout extension for slow processing

### In-Memory Optimization

#### Development Environment Tuning

**Memory Management**:

- Configure appropriate queue size limits
- Implement memory pressure detection
- Use efficient data structures for message storage
- Monitor garbage collection impact

**Concurrency Control**:

```rust
pub struct OptimizedInMemoryConfig {
    pub max_queue_size: usize,
    pub enable_persistence: bool,
    pub persistence_path: Option<PathBuf>,
    pub worker_threads: usize,
    pub channel_buffer_size: usize,
}

impl OptimizedInMemoryConfig {
    pub fn for_high_throughput() -> Self {
        Self {
            max_queue_size: 10000,
            enable_persistence: false,
            persistence_path: None,
            worker_threads: num_cpus::get(),
            channel_buffer_size: 1000,
        }
    }

    pub fn for_testing() -> Self {
        Self {
            max_queue_size: 1000,
            enable_persistence: false,
            persistence_path: None,
            worker_threads: 1, // Deterministic testing
            channel_buffer_size: 100,
        }
    }
}
```

## Message Processing Patterns

### High-Throughput Processing

#### Parallel Processing Strategy

**Consumer Scaling Patterns**:

- Implement horizontal scaling with multiple consumer instances
- Use session-aware load balancing for ordered processing
- Configure optimal consumer-to-queue ratios
- Monitor queue depth and scale consumers dynamically

**Asynchronous Processing Design**:

```rust
pub struct HighThroughputProcessor {
    client: Arc<dyn QueueClient>,
    worker_pool: ThreadPool,
    metrics: Arc<ProcessingMetrics>,
    semaphore: Arc<Semaphore>,
}

impl HighThroughputProcessor {
    pub async fn process_messages_parallel(&self) -> Result<(), ProcessingError> {
        let receive_options = ReceiveOptions::new()
            .with_max_messages(10)
            .with_timeout(Duration::from_secs(30));

        loop {
            let messages = self.client.receive_messages(&receive_options).await?;

            if messages.is_empty() {
                continue;
            }

            // Process messages in parallel while respecting concurrency limits
            let tasks: Vec<_> = messages.into_iter().map(|msg| {
                let client = Arc::clone(&self.client);
                let metrics = Arc::clone(&self.metrics);
                let semaphore = Arc::clone(&self.semaphore);

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    let start = Instant::now();
                    let result = process_single_message(&msg.message).await;
                    let duration = start.elapsed();

                    match result {
                        Ok(_) => {
                            client.acknowledge(msg.receipt).await?;
                            metrics.record_success(duration);
                        }
                        Err(e) => {
                            client.reject(msg.receipt, &e.to_string()).await?;
                            metrics.record_error();
                        }
                    }

                    Ok::<(), ProcessingError>(())
                })
            }).collect();

            // Wait for all tasks to complete
            for task in tasks {
                task.await??;
            }
        }
    }
}
```

### Low-Latency Processing

#### Optimized Message Flow

**Single Message Processing**:

- Minimize message batching for immediate processing
- Use small prefetch counts to reduce queuing
- Implement fast-path processing for common cases
- Optimize serialization and deserialization

**Connection Optimization**:

- Maintain warm connections to avoid setup overhead
- Use connection multiplexing efficiently
- Implement connection health monitoring
- Configure aggressive timeout settings

### Batch Processing Optimization

#### Intelligent Batching Strategy

**Dynamic Batch Sizing**:

```rust
pub struct AdaptiveBatchProcessor {
    min_batch_size: usize,
    max_batch_size: usize,
    target_batch_duration: Duration,
    processing_history: VecDeque<BatchMetrics>,
}

impl AdaptiveBatchProcessor {
    pub fn calculate_optimal_batch_size(&mut self) -> usize {
        let recent_metrics = self.processing_history.iter()
            .rev()
            .take(10)
            .collect::<Vec<_>>();

        if recent_metrics.is_empty() {
            return self.min_batch_size;
        }

        // Calculate average processing time per message
        let avg_time_per_message = recent_metrics.iter()
            .map(|m| m.total_duration.as_millis() as f64 / m.message_count as f64)
            .sum::<f64>() / recent_metrics.len() as f64;

        // Calculate target batch size based on desired duration
        let target_batch_size = (self.target_batch_duration.as_millis() as f64 / avg_time_per_message) as usize;

        // Clamp to configured limits
        target_batch_size.clamp(self.min_batch_size, self.max_batch_size)
    }

    pub async fn process_adaptive_batch(&mut self, client: &dyn QueueClient) -> Result<(), ProcessingError> {
        let batch_size = self.calculate_optimal_batch_size();

        let receive_options = ReceiveOptions::new()
            .with_max_messages(batch_size as u32)
            .with_timeout(Duration::from_secs(10));

        let start_time = Instant::now();
        let messages = client.receive_messages(&receive_options).await?;

        if messages.is_empty() {
            return Ok(());
        }

        // Process batch and record metrics
        let processing_start = Instant::now();
        let results = self.process_message_batch(messages).await?;
        let processing_duration = processing_start.elapsed();

        // Record batch metrics for future optimization
        self.processing_history.push_back(BatchMetrics {
            message_count: results.len(),
            total_duration: start_time.elapsed(),
            processing_duration,
            success_count: results.iter().filter(|r| r.is_ok()).count(),
        });

        // Keep limited history
        if self.processing_history.len() > 50 {
            self.processing_history.pop_front();
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BatchMetrics {
    pub message_count: usize,
    pub total_duration: Duration,
    pub processing_duration: Duration,
    pub success_count: usize,
}
```

## Memory and Resource Optimization

### Memory Management Strategies

#### Message Lifecycle Management

**Efficient Message Handling**:

- Use streaming deserialization for large messages
- Implement message pooling for frequent allocations
- Configure garbage collection for message processing patterns
- Monitor memory pressure and implement backpressure

**Connection Resource Management**:

- Pool and reuse network connections
- Implement connection lifecycle management
- Monitor connection health and performance
- Configure appropriate timeout values

### CPU Optimization

#### Processing Efficiency

**Serialization Optimization**:

- Use efficient serialization formats (bincode vs JSON)
- Implement zero-copy deserialization where possible
- Cache serialized representations for repeated operations
- Profile serialization hotspots

**Async Runtime Tuning**:

```rust
pub fn configure_tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .thread_name("queue-runtime-worker")
        .thread_stack_size(2 * 1024 * 1024) // 2MB stack
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime")
}

pub struct RuntimeConfiguration {
    pub worker_threads: usize,
    pub max_blocking_threads: usize,
    pub thread_stack_size: usize,
    pub enable_io: bool,
    pub enable_time: bool,
}

impl RuntimeConfiguration {
    pub fn for_high_throughput() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            max_blocking_threads: 512,
            thread_stack_size: 2 * 1024 * 1024,
            enable_io: true,
            enable_time: true,
        }
    }

    pub fn for_low_resource() -> Self {
        Self {
            worker_threads: 2,
            max_blocking_threads: 16,
            thread_stack_size: 1024 * 1024,
            enable_io: true,
            enable_time: true,
        }
    }
}
```

## Monitoring and Observability

### Performance Metrics Collection

#### Key Performance Indicators

**Throughput Monitoring**:

```rust
pub struct ThroughputMetrics {
    messages_processed: Counter,
    processing_duration: Histogram,
    batch_sizes: Histogram,
    error_rate: Counter,
}

impl ThroughputMetrics {
    pub fn new() -> Self {
        Self {
            messages_processed: Counter::new(
                "queue_runtime_messages_processed_total",
                "Total number of messages processed"
            ).unwrap(),

            processing_duration: Histogram::with_opts(
                HistogramOpts::new(
                    "queue_runtime_processing_duration_seconds",
                    "Time spent processing messages"
                ).buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0])
            ).unwrap(),

            batch_sizes: Histogram::with_opts(
                HistogramOpts::new(
                    "queue_runtime_batch_sizes",
                    "Distribution of batch sizes"
                ).buckets(vec![1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0])
            ).unwrap(),

            error_rate: Counter::new(
                "queue_runtime_errors_total",
                "Total number of processing errors"
            ).unwrap(),
        }
    }

    pub fn record_batch_processed(&self, batch_size: usize, duration: Duration) {
        self.messages_processed.inc_by(batch_size as u64);
        self.processing_duration.observe(duration.as_secs_f64());
        self.batch_sizes.observe(batch_size as f64);
    }
}
```

#### Performance Alerting

**Threshold-Based Alerts**:

- Throughput degradation alerts (>20% decrease)
- Latency spike alerts (p95 >2x baseline)
- Error rate increase alerts (>5x baseline)
- Resource utilization alerts (>80% sustained)

### Benchmarking Framework

#### Performance Testing Harness

```rust
pub struct PerformanceBenchmark {
    client: Box<dyn QueueClient>,
    message_count: usize,
    concurrent_consumers: usize,
    message_size: usize,
}

impl PerformanceBenchmark {
    pub async fn run_throughput_test(&self) -> BenchmarkResults {
        let start_time = Instant::now();

        // Generate test messages
        let messages = self.generate_test_messages().await?;

        // Send messages concurrently
        let send_start = Instant::now();
        self.send_messages_concurrent(messages).await?;
        let send_duration = send_start.elapsed();

        // Receive and process messages
        let receive_start = Instant::now();
        let processed_count = self.consume_messages_concurrent().await?;
        let receive_duration = receive_start.elapsed();

        let total_duration = start_time.elapsed();

        BenchmarkResults {
            total_messages: self.message_count,
            send_throughput: self.message_count as f64 / send_duration.as_secs_f64(),
            receive_throughput: processed_count as f64 / receive_duration.as_secs_f64(),
            end_to_end_throughput: processed_count as f64 / total_duration.as_secs_f64(),
            send_latency_p95: self.calculate_send_latency_p95(),
            receive_latency_p95: self.calculate_receive_latency_p95(),
        }
    }

    async fn send_messages_concurrent(&self, messages: Vec<EventEnvelope>) -> Result<(), BenchmarkError> {
        let chunk_size = messages.len() / self.concurrent_consumers;
        let chunks: Vec<_> = messages.chunks(chunk_size).collect();

        let tasks: Vec<_> = chunks.into_iter().map(|chunk| {
            let client = Arc::clone(&self.client);
            let chunk = chunk.to_vec();

            tokio::spawn(async move {
                for message in chunk {
                    let send_options = SendOptions::default();
                    client.send_message(message, &send_options).await?;
                }
                Ok::<(), BenchmarkError>(())
            })
        }).collect();

        for task in tasks {
            task.await??;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub total_messages: usize,
    pub send_throughput: f64,
    pub receive_throughput: f64,
    pub end_to_end_throughput: f64,
    pub send_latency_p95: Duration,
    pub receive_latency_p95: Duration,
}
```

## Scalability Patterns

### Horizontal Scaling Strategies

#### Consumer Scaling Patterns

**Auto-Scaling Configuration**:

- Monitor queue depth and processing lag
- Scale consumers based on throughput requirements
- Implement graceful consumer shutdown
- Balance load across available consumers

**Session-Aware Scaling**:

- Scale consumers per session group
- Implement session affinity routing
- Monitor session processing distribution
- Handle session redistribution during scaling

### Vertical Scaling Optimization

#### Resource Allocation Tuning

**Memory Scaling**:

- Configure heap size based on message volume
- Tune garbage collection for message processing patterns
- Monitor memory pressure and allocation patterns
- Implement memory pressure backpressure

**CPU Scaling**:

- Optimize thread pool sizing for workload characteristics
- Configure NUMA-aware thread placement
- Implement CPU affinity for performance-critical paths
- Monitor CPU utilization and processing efficiency

## Behavioral Assertions

The following assertions define expected performance characteristics:

### Throughput Assertions

1. **Sustained Throughput**: System MUST maintain target throughput for extended periods
2. **Batch Efficiency**: Batch operations MUST be more efficient than individual operations
3. **Linear Scaling**: Throughput MUST scale linearly with consumer count up to provider limits
4. **Provider Limits**: System MUST respect and handle provider throughput limits gracefully

### Latency Assertions

5. **Latency SLA**: 95th percentile latency MUST remain below configured thresholds
6. **Processing Overhead**: Queue client overhead MUST be <10% of total processing time
7. **Connection Reuse**: Connection establishment overhead MUST be amortized across operations
8. **Timeout Handling**: All operations MUST respect configured timeout values

### Resource Assertions

9. **Memory Bounds**: Memory usage MUST remain within configured limits
10. **Connection Limits**: Number of connections MUST not exceed provider or system limits
11. **CPU Efficiency**: CPU utilization MUST correlate with actual message processing work
12. **Resource Cleanup**: All resources MUST be properly cleaned up when no longer needed

### Scalability Assertions

13. **Consumer Scaling**: Adding consumers MUST increase overall system throughput
14. **Queue Depth Management**: Queue depth MUST decrease with increased consumer capacity
15. **Graceful Degradation**: Performance MUST degrade gracefully under resource pressure
16. **Recovery Time**: System MUST recover to normal performance within defined time limits
