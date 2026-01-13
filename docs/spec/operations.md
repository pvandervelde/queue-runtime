# Queue Runtime - Operations Guide

## Overview

This document defines operational requirements for deploying, monitoring, and maintaining applications using queue-runtime. While the library itself is a dependency (not a standalone service), it has operational implications for how applications interact with cloud queue infrastructure.

---

## Deployment Requirements

### Infrastructure Prerequisites

**Cloud Resources Required**:

1. **Azure Service Bus** (if using Azure provider):
   - Service Bus namespace (Standard or Premium tier)
   - Queues created with appropriate settings (sessions enabled if needed)
   - Connection string or Managed Identity access configured

2. **AWS SQS** (if using AWS provider):
   - SQS queues created (Standard or FIFO type)
   - IAM roles/policies configured for queue access
   - Queue URLs known and configurable

**Networking**:

- Outbound HTTPS access to cloud provider APIs
- DNS resolution for provider endpoints
- Optional: VPN/private endpoints for enhanced security

**Credentials**:

- Azure: Connection string, or Managed Identity, or Service Principal
- AWS: IAM credentials, or IAM role (for EC2/ECS), or assumed role

### Application Deployment Checklist

**Before Deploying**:

- [ ] Queue resources provisioned in target environment
- [ ] Credentials configured (environment variables or secret management)
- [ ] Network access validated to queue endpoints
- [ ] Configuration validated (connection strings, queue names, timeouts)
- [ ] Monitoring/observability configured

**Deployment Validation**:

- [ ] Application can connect to queue (test with simple send/receive)
- [ ] Metrics are flowing to monitoring system
- [ ] Logs include queue operation context
- [ ] DLQ is accessible and monitored

**Rollback Considerations**:

- Messages in-flight during deployment may be reprocessed
- Lock timeouts should be considered for rolling updates
- Session-based processing may require draining before shutdown

---

## Configuration Management

### Environment-Based Configuration

**Standard Environment Variables**:

```bash
# Provider Selection
QUEUE_PROVIDER=azure  # or 'aws'

# Azure Configuration
AZURE_SERVICE_BUS_CONNECTION_STRING="Endpoint=sb://..."
# OR use Managed Identity
AZURE_CLIENT_ID="..."
AZURE_TENANT_ID="..."

# AWS Configuration
AWS_REGION="us-west-2"
AWS_ACCESS_KEY_ID="..."
AWS_SECRET_ACCESS_KEY="..."
# OR use IAM role (automatically detected in ECS/EC2)

# Queue Names (environment-specific)
QUEUE_NAME="prod-task-tactician"
QUEUE_DLQ_NAME="prod-task-tactician-dlq"

# Timeouts (optional, defaults provided)
QUEUE_RECEIVE_TIMEOUT_SECONDS=30
QUEUE_VISIBILITY_TIMEOUT_SECONDS=300

# Retry Configuration (optional)
QUEUE_MAX_RETRY_ATTEMPTS=3
QUEUE_RETRY_BACKOFF_MS=1000
```

**Configuration Layering**:

1. **Defaults**: Sensible defaults in code
2. **Configuration File**: Optional `config.toml` or `config.yaml`
3. **Environment Variables**: Override file config
4. **Runtime Overrides**: Programmatic configuration for special cases

**Secret Management**:

- Connection strings should be stored in secret management systems:
  - Azure Key Vault for Azure deployments
  - AWS Secrets Manager for AWS deployments
  - HashiCorp Vault for multi-cloud
- Applications should load secrets at startup and refresh periodically
- Never commit secrets to version control

### Multi-Environment Strategy

**Environment Isolation**:

Each environment (dev, staging, prod) should have:

- Separate queue namespaces/accounts
- Distinct queue names (prefixed with environment)
- Isolated credentials (no shared credentials across environments)
- Environment-specific monitoring/alerting

**Queue Naming Pattern**:

```
{environment}-{application}-{purpose}
prod-task-tactician-main
prod-task-tactician-dlq
staging-task-tactician-main
staging-task-tactician-dlq
```

---

## Monitoring and Observability

### Key Metrics

**Queue Metrics** (collected via library):

- `queue_messages_sent_total{queue, status}` - Messages sent (success/failure)
- `queue_messages_received_total{queue}` - Messages received
- `queue_messages_completed_total{queue}` - Messages successfully processed
- `queue_messages_abandoned_total{queue}` - Messages returned to queue
- `queue_messages_dead_lettered_total{queue}` - Messages moved to DLQ

**Performance Metrics**:

- `queue_send_duration_seconds{queue}` - Send operation latency (histogram)
- `queue_receive_duration_seconds{queue}` - Receive operation latency (histogram)
- `queue_complete_duration_seconds{queue}` - Complete operation latency (histogram)

**Error Metrics**:

- `queue_errors_total{queue, error_type}` - Errors by category
- `queue_retry_attempts_total{queue}` - Retry attempts before success/failure

**Session Metrics** (if sessions enabled):

- `queue_sessions_accepted_total{queue}` - Sessions accepted
- `queue_sessions_completed_total{queue}` - Sessions completed
- `queue_sessions_abandoned_total{queue}` - Sessions abandoned
- `queue_session_duration_seconds{queue}` - Session processing time

### Logging

**Structured Logging Requirements**:

Every log entry should include:

- `queue_name`: Which queue is being operated on
- `message_id`: Unique identifier for the message
- `session_id`: Session identifier (if applicable)
- `correlation_id`: Request correlation ID
- `operation`: send, receive, complete, abandon, dead_letter
- `delivery_count`: Number of times message has been delivered

**Log Levels**:

- `TRACE`: Detailed operation internals (use sparingly)
- `DEBUG`: Configuration, connection establishment, provider-specific details
- `INFO`: Normal operations (message sent, received, completed)
- `WARN`: Retryable errors, approaching limits, degraded performance
- `ERROR`: Permanent failures, DLQ movements, configuration errors

**Sensitive Data**:

Never log:

- Connection strings or credentials
- Full message bodies (may contain sensitive data)
- Personal information from messages

Do log:

- Message IDs and metadata
- Operation outcomes
- Error categories and context

### Distributed Tracing

**Trace Context Propagation**:

- Applications should propagate trace context via `correlation_id` message property
- Library includes trace context in all provider API calls
- Spans created for: send, receive, complete, abandon operations
- Session operations create parent spans with message operations as children

**Trace Attributes**:

Standard attributes added to all spans:

- `messaging.system`: "azure_service_bus" or "aws_sqs"
- `messaging.destination`: Queue name
- `messaging.message_id`: Message identifier
- `messaging.conversation_id`: Session ID
- `messaging.operation`: Operation type

### Alerting

**Critical Alerts**:

1. **High DLQ Rate**: >5% of messages ending in DLQ
   - Indicates systematic processing failures
   - Investigate application error logs and DLQ message content

2. **Connection Failures**: Unable to connect to queue service
   - Check credentials, network access, service health
   - May indicate misconfiguration or cloud service outage

3. **High Latency**: p95 latency >500ms
   - Check cloud service status
   - May indicate throttling or resource constraints

4. **Queue Depth Growth**: Queue depth growing over time
   - Consumer not keeping up with producer
   - May need to scale consumers or optimize processing

**Warning Alerts**:

1. **Elevated Retry Rate**: >10% of operations retrying
   - Indicates transient issues
   - Monitor for escalation to failures

2. **Session Lock Timeouts**: Sessions timing out frequently
   - Processing taking too long
   - May need to adjust lock duration or optimize handlers

3. **Authentication Refresh Failures**: Credential renewal failing
   - Managed identity or IAM role issues
   - Check credential configuration

---

## Scaling

### Horizontal Scaling

**Consumer Scaling**:

- Run multiple application instances to increase throughput
- Each instance receives independent messages from queue
- Session-based processing: Each session handled by one consumer at a time
- No coordination needed between consumers (queue manages distribution)

**Scaling Limits**:

- Azure Service Bus: 2,000 concurrent connections per namespace
- AWS SQS: No practical connection limit, but request rate quotas apply
- Session processing: Limited by number of active sessions, not instances

**Auto-Scaling Triggers**:

Scale consumers based on:

- Queue depth (messages waiting)
- Message age (oldest message)
- Consumer CPU/memory utilization

### Vertical Scaling

**When to Scale Up**:

- Message processing is CPU-intensive
- Memory required per message is high
- Provider SDK benefits from more resources

**Resource Requirements**:

Typical resource profile per consumer instance:

- **Memory**: 512MB - 2GB (depends on message size and concurrency)
- **CPU**: 0.5 - 2 vCPU (depends on processing complexity)
- **Network**: 10-100 Mbps (depends on message throughput)

### Performance Optimization

**Connection Pooling**:

- Reuse connections across operations (library handles this)
- Avoid recreating clients frequently
- Consider connection pool size for high-throughput scenarios

**Batch Operations**:

- Send messages in batches where possible (up to provider limits)
- Azure: 100 messages per batch
- AWS: 10 messages per batch
- Reduces network round trips and improves throughput

**Concurrent Processing**:

- Process multiple messages concurrently within single instance
- Balance concurrency with resource usage
- Session-based processing: Concurrency per session, not global

---

## Disaster Recovery

### Backup and Recovery

**Queue Data**:

- Messages in queues are transient (not typically backed up)
- DLQ messages should be preserved for analysis
- Consider exporting DLQ messages to long-term storage (S3, Blob Storage)

**Recovery Procedures**:

1. **Lost Messages**: Messages are durable in cloud queues (replicated by provider)
2. **DLQ Recovery**: Replay messages from DLQ after fixing root cause
3. **Configuration Recovery**: Store configuration in version control

### Failure Scenarios

**Queue Service Outage**:

- Symptoms: Connection failures, timeouts, authentication errors
- Response:
  - Check cloud provider status page
  - Verify network connectivity
  - Enable circuit breaker to stop retry storms
  - Consider failover to alternative provider (if configured)

**Application Failures**:

- Symptoms: Messages moving to DLQ, session lock timeouts
- Response:
  - Check application logs for errors
  - Verify message format hasn't changed
  - Roll back recent deployments if necessary
  - Analyze DLQ messages for patterns

**Credential Expiration**:

- Symptoms: Authentication errors, sudden connection failures
- Response:
  - Rotate credentials immediately
  - Update secret management system
  - Verify automatic credential refresh is working

---

## Maintenance

### Routine Maintenance

**Daily**:

- Monitor queue depth and DLQ growth
- Review error rate metrics
- Check application logs for warnings

**Weekly**:

- Review DLQ messages and categorize failure types
- Analyze performance metrics for trends
- Check for credential expiration warnings

**Monthly**:

- Audit queue configuration against best practices
- Review and update alerting thresholds
- Test disaster recovery procedures

### Queue Hygiene

**DLQ Management**:

- Regularly review DLQ messages (don't let them accumulate)
- Categorize failures: transient, permanent, code bugs, data issues
- Replay recoverable messages after fixing issues
- Archive or delete messages that cannot be recovered

**Queue Depth Management**:

- Monitor for unexpectedly empty queues (producer issues?)
- Monitor for growing queues (consumer not keeping up?)
- Adjust consumer count based on queue depth trends

**Resource Cleanup**:

- Remove unused queues from test/development
- Clean up old session data if applicable
- Review and remove obsolete monitoring dashboards

---

## Cost Optimization

### Azure Service Bus Costs

**Factors**:

- Namespace tier (Basic, Standard, Premium)
- Number of operations (send, receive, management)
- Message size and throughput
- Sessions enabled (higher cost)

**Optimization**:

- Use batch operations to reduce operation count
- Consider message size (smaller = cheaper)
- Use Standard tier for most cases (Premium for high-throughput)
- Monitor unused queues and remove them

### AWS SQS Costs

**Factors**:

- Number of requests (send, receive, delete)
- FIFO queues cost more than Standard
- Data transfer costs (cross-region)

**Optimization**:

- Use batch operations (10 messages per request)
- Adjust receive wait time to reduce empty receives
- Consider Standard queues if strict ordering not needed
- Monitor request patterns for optimization opportunities

### General Cost Optimization

**Message Design**:

- Keep messages small (avoid embedding large payloads)
- Use compression for large payloads if necessary
- Reference large data by URL instead of embedding

**Polling Strategy**:

- Use long polling (30s wait) instead of short polling
- Reduces empty receive operations
- Lower cost and better performance
