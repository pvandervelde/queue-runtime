# AWS SQS Provider Specification

This document defines the design requirements for the AWS SQS implementation of the queue-runtime client interface, supporting both standard and FIFO queues for high-throughput and ordered message processing scenarios.

## Overview

The AWS SQS provider implements queue operations using Amazon Simple Queue Service, providing reliable message delivery with configurable throughput and ordering guarantees. The implementation must support both standard queues for maximum throughput and FIFO queues for strict message ordering.

## Core Requirements

### AWS SDK Integration

**SDK Dependencies**:

- AWS SDK for Rust (aws-sdk-sqs) for SQS operations
- AWS credential providers for authentication
- AWS configuration management for region and endpoint settings
- Error handling integration with AWS SDK error types

### Client Architecture

**Client Design Requirements**:

- Thread-safe client implementation supporting concurrent operations
- Connection pooling and reuse for efficiency
- Queue URL caching to avoid repeated lookups
- Configuration-driven client instantiation
- Generic message type support with serialization abstraction

## Configuration Requirements

### Authentication Methods

**Authentication Strategy Support**:

- IAM role-based authentication for production deployments
- Access key and secret key for development and testing scenarios
- Named AWS profile support for local development
- Session token support for temporary credentials
- Default credential chain for automatic credential discovery

**Regional Configuration**:

- AWS region selection for service endpoint routing
- Custom endpoint URL support for LocalStack and testing scenarios
- Cross-region queue access capabilities
- Multi-region deployment support

### Queue Management

**Queue URL Handling**:

- Automatic queue URL resolution and caching
- Queue existence validation and error handling
- FIFO queue detection and special handling
- Queue creation and deletion operations

**Queue Type Support**:

- Standard queues for high-throughput scenarios
- FIFO queues for ordered message processing
- Dead letter queue configuration and management
- Cross-account queue access patterns

## Message Processing Requirements

### Message Attributes

**Metadata Handling**:

- Message type information for deserialization
- Timestamp tracking for processing metrics
- Correlation ID support for distributed tracing
- Custom application-specific attributes
- Message deduplication support for FIFO queues

### Serialization Requirements

**Message Serialization**:

- JSON serialization for message body content
- UTF-8 encoding validation and error handling
- Message attribute serialization for metadata
- Type information preservation for deserialization
- Large message handling with S3 offloading support

## Queue Operations

### Send Operations

**Message Send Requirements**:

- Queue URL resolution and caching for performance
- Message attribute creation and validation
- FIFO queue message group ID assignment from session ID
- Deduplication ID generation for FIFO queues
- Standard queue delay configuration support
- Error handling and retry logic for transient failures

**FIFO-Specific Requirements**:

- Message group ID mapping from session IDs
- Content-based or explicit deduplication ID generation
- Ordering guarantee within message groups
- Throughput limitations (3000 messages/second with batching)

### Receive Operations

**Message Reception Requirements**:

- Configurable batch size (1-10 messages per request)
- Long polling configuration for efficient message retrieval
- Visibility timeout configuration for message processing windows
- Message attribute retrieval for deserialization metadata
- Receipt handle management for message lifecycle operations

**Processing Pattern Support**:

- Multiple consumer support with automatic load balancing
- Message visibility timeout extension for long processing
- Dead letter queue integration for poison message handling
- Batch message processing with parallel acknowledgment

### Message Acknowledgment

**Acknowledgment Requirements**:

- Successful processing confirmation through message deletion
- Receipt handle validation and queue URL verification
- Error handling for invalid or expired receipt handles
- Batch acknowledgment support for improved throughput

**Rejection and Retry Requirements**:

- Message visibility timeout reset for retry scenarios
- Immediate visibility reset for fast retry (0 visibility timeout)
- Integration with retry counting and dead letter queue policies
- Error handling for receipt handle expiration

**Dead Letter Handling Requirements**:

- Automatic dead letter queue integration after max receive count
- Manual dead letter operation through message deletion
- Reason logging for debugging and compliance requirements
- Dead letter queue monitoring and alerting integration

### Session-Based Operations

**FIFO Session Support Requirements**:

- Session-specific message retrieval for FIFO queues
- Message group ID filtering and session isolation
- Error handling for session operations on standard queues
- Performance optimization for session-based filtering

## Receipt Management

### Receipt Handle Requirements

**Receipt Structure Requirements**:

- Unique receipt handle for message lifecycle operations
- Queue URL association for operation routing
- Client reference for AWS SDK operations
- Validation support for expired or invalid handles

**Receipt Validation Requirements**:

- Receipt handle format validation
- Visibility timeout expiration checking
- Queue existence and accessibility validation
- Error handling for invalid receipt operations

## Error Handling

### Error Classification Requirements

**AWS-Specific Error Types**:

- SQS service errors with appropriate HTTP status mapping
- Network connectivity and timeout error handling
- AWS throttling and quota exceeded error handling
- Authentication and authorization error differentiation
- Resource not found and invalid parameter error handling

**Error Recovery Requirements**:

- Retryable vs non-retryable error classification
- Exponential backoff for retryable errors
- Circuit breaker pattern for persistent failures
- Error context preservation for debugging

**Error Mapping Requirements**:

- AWS SDK error to queue system error mapping
- HTTP status code interpretation (400, 401, 403, 404, 429, 5xx)
- Service-specific error code translation
- Consistent error interface across providers

## Configuration Management

### Configuration Structure Requirements

**Core Configuration Parameters**:

- AWS region specification with default fallback
- Custom endpoint URL support for testing (LocalStack)
- Authentication method selection and validation
- Timeout and polling configuration parameters

**Operational Configuration Requirements**:

- Message visibility timeout configuration (default 30 seconds)
- Long polling wait time optimization (0-20 seconds)
- Standard queue message delay support (0-900 seconds)
- Message retention period configuration (1-1209600 seconds)
- Maximum message size limits (up to 262144 bytes)
- Dead letter queue integration with max receive count

**Security Configuration Requirements**:

- Server-side encryption enablement options
- KMS key ID specification for encryption
- IAM role and credential management integration

### Authentication Method Requirements

**Credential Provider Support**:

- Access key and secret key with optional session token
- AWS profile-based authentication
- Default credential provider chain support
- EC2 instance role-based authentication
- Instance profile credential support

### Configuration Validation Requirements

**Default Configuration Values**:

- Default region: us-east-1 (with environment variable override)
- Default visibility timeout: 30 seconds
- Default long polling: 20 seconds (maximum)
- Default message retention: 14 days (1,209,600 seconds)
- Default message size limit: 256 KB (262,144 bytes)
- Default max receive count: 5 (for dead letter queue integration)

## Queue Lifecycle Management

### Queue Creation Requirements

**Standard Queue Creation**:

- Basic attribute configuration (visibility timeout, retention period, max receive count)
- Delay seconds support for standard queues (0-900 seconds)
- Encryption configuration with SQS-managed or KMS keys
- Queue naming validation and normalization

**FIFO Queue Creation**:

- FIFO queue attribute enablement (.fifo suffix enforcement)
- Content-based deduplication configuration options
- Message group ID requirement validation
- Throughput optimization settings

**Dead Letter Queue Setup**:

- Automatic DLQ creation with matching type (standard/FIFO)
- DLQ naming convention enforcement (-dlq suffix)
- Redrive policy configuration with max receive count
- ARN resolution and policy attachment

### Queue Operation Requirements

**Queue Discovery**:

- Queue URL resolution and caching
- Queue existence validation
- Cross-account and cross-region queue support
- Error handling for non-existent queues

**Queue Statistics**:

- Active message count retrieval (approximate)
- In-flight message count monitoring
- Delayed message count tracking
- Queue attribute inspection and validation

**Queue Deletion**:

- Safe queue deletion with confirmation
- Cascade deletion considerations for related DLQs
- Error handling for deletion failures
- Cleanup of cached references

## FIFO Queue Support

### Message Group ID Management

**Entity-Based Grouping Requirements**:

- Pull request message grouping by repository and PR number
- Issue message grouping by repository and issue number
- Branch message grouping by repository and branch identifier
- Repository-level message grouping for global events
- User-specific message grouping within repository context

### Deduplication Strategy

**Deduplication ID Generation Requirements**:

- Timestamp-based deduplication with event ID combination
- Content-based deduplication support as fallback option
- Explicit deduplication ID specification for precise control
- Deduplication window management (5-minute AWS default)

### Queue Naming Validation

**FIFO Queue Naming Requirements**:

- .fifo suffix validation and enforcement
- Maximum length validation (80 characters including suffix)
- Character set validation (alphanumeric, hyphens, underscores, dots)
- Queue name normalization for invalid characters
- Reserved name collision avoidance

## Testing Support

### Mock Implementation Requirements

**Mock Client Interface**:

- Full QueueClient trait implementation for unit testing
- Configurable behavior for send/receive operations
- Receipt handle simulation for acknowledgment testing
- Error simulation for failure scenario testing

**Test Configuration Support**:

- LocalStack endpoint configuration for integration testing
- Test credential provider for isolated testing environments
- Configurable timeouts and polling intervals for fast tests
- Queue lifecycle management in test environments

### Test Validation Requirements

**FIFO Queue Testing**:

- Message ordering validation within message groups
- Deduplication ID collision testing
- Session-based message filtering validation
- Queue name validation and normalization testing
- Message group ID generation consistency validation
- Error classification and retry logic validation

## Performance Optimization

### Batch Processing Requirements

**Batch Send Operations**:

- Up to 10 messages per batch request (AWS SQS limit)
- Automatic chunking for larger message sets
- Individual message serialization error handling
- FIFO batch processing with proper group ID and deduplication ID assignment
- Batch failure handling with individual message retry capability

**Batch Receive Operations**:

- Configurable batch size optimization (1-10 messages)
- Parallel message processing within batch limits
- Batch acknowledgment strategies for improved throughput
- Error isolation within batch operations

### Throughput Optimization Requirements

**Standard Queue Performance**:

- Near-unlimited throughput capability
- Optimized polling intervals to balance latency and costs
- Connection pooling and reuse strategies
- Regional optimization for reduced latency

**FIFO Queue Performance**:

- Up to 3,000 messages per second with batching
- 300 messages per second without batching
- Message group parallelism optimization
- Deduplication performance considerations

## Implementation Guidelines

### Best Practices Requirements

**Queue Type Selection**:

- FIFO queue selection criteria for ordering requirements
- Standard queue benefits for high-throughput scenarios
- Dead letter queue integration for poison message handling

**Configuration Optimization**:

- Visibility timeout alignment with message processing duration
- Long polling enablement for cost and efficiency optimization
- Batch operation utilization for improved throughput

**Monitoring Integration**:

- Queue depth and processing metrics tracking
- Dead letter queue monitoring and alerting
- Throttling detection and circuit breaker integration

**Security Requirements**:

- IAM role-based access control implementation
- Cross-account queue access patterns
- Encryption in transit and at rest configuration
