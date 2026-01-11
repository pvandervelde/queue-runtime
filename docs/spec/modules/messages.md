# Message Types Module

The message types module defines the standardized message formats, serialization patterns, and envelope structures used throughout the queue runtime system.

## Overview

This module establishes the canonical message format for GitHub events flowing through the queue system, providing type-safe serialization/deserialization and ensuring compatibility between Queue-Keeper and bot consumers.

## Core Message Types

### EventEnvelope Design Requirements

**Core Message Structure**:

- Unique event identifier for deduplication and tracking
- GitHub event type classification (pull_request, issues, push, etc.)
- Repository information for routing and security
- Entity type and ID for session-based ordering (PR number, issue number, etc.)
- Optional session ID for ordered processing requirements

**Message Content Requirements**:

- Raw GitHub webhook payload preservation for downstream processing
- Processing metadata including timestamps and correlation IDs
- Optional distributed tracing context for end-to-end monitoring
- Serializable structure using standard JSON format

**Behavioral Requirements**:

- Support correlation key generation for entity-based grouping
- Enable ordered processing detection based on entity type
- Provide builder pattern methods for fluent construction
- Implement QueueMessage trait for provider compatibility

### Repository

Repository identification information:

**Repository Data Structure**:

- Repository owner (user or organization name)
- Repository name (excluding owner)
- Full repository name in format `owner/name`
- GitHub repository ID for unique identification
- Repository HTML URL for navigation links
- Privacy status flag for access control

**Repository Construction Requirements**:

- Support creation from owner/name pairs
- Support parsing from full repository names
- Support extraction from GitHub webhook payloads
- Error handling for malformed repository data
- Validation of required fields during construction

### EntityType

Classification of the primary entity involved in an event:

**Entity Classification Requirements**:

- Repository-level events (push, repository settings)
- Pull request events (opened, closed, synchronized)
- Issue events (opened, commented, closed)
- Branch events (created, deleted, protected)
- Release events (published, edited, deleted)
- User and organization events (membership changes)
- Workflow and check events (runs, suites, status)
- Deployment events (created, status updates)
- Unknown type as fallback for new GitHub event types

**Entity Detection Logic**:

- Map GitHub event types to entity classifications
- Handle related event types (e.g., pull_request_review → PullRequest)
- Extract entity IDs from GitHub webhook payloads
- Support branch name normalization (strip refs/heads/ prefix)
- Default to Unknown for unrecognized event types

**Entity ID Extraction Requirements**:

- Pull request and issue numbers from GitHub payload
- Release tag names for version identification
- Branch names with ref prefix normalization
- Check run and suite IDs for CI/CD tracking
- Deployment IDs for deployment lifecycle
- Workflow run IDs for automation tracking
- Return None for entities without meaningful IDs

**Ordering Support Requirements**:

- Enable ordered processing for pull requests, issues, and branches
- Other entity types process without ordering constraints
- Support session-based message grouping for ordered entities

**Display Format Requirements**:

- Convert entity types to lowercase string names
- Match GitHub webhook event naming conventions

### EventMetadata

Processing and routing metadata for events:

**Metadata Structure Requirements**:

- Event reception timestamp for processing order
- Optional processing completion timestamp
- Event source classification (GitHub webhook, replay, test)
- GitHub delivery ID from webhook headers for deduplication
- Webhook signature validation status for security
- Retry attempt counter for reliability monitoring
- Matched routing rules list for audit trails
- Correlation ID for distributed tracing
- Custom message properties for queue provider features
- Optional time-to-live for message expiration
- Optional scheduled enqueue time for delayed processing
- Cached serialized body for queue provider performance

**Metadata Builder Requirements**:

- Fluent builder methods for metadata construction
- Support delivery ID assignment from webhook headers
- Support signature validation status tracking
- Support event source classification
- Retry count increment for failure tracking
- Processing completion timestamp marking

### EventSource

Classification of event origins:

- **GitHub**: Live webhook events from GitHub
- **Replay**: Re-processed events from audit logs
- **Test**: Events generated for testing purposes
- **Manual**: Events created through administrative interfaces

### TraceContext

Distributed tracing context for correlation across services:

**W3C Trace Context Requirements**:

- 128-bit trace ID for unique request identification
- 64-bit span ID for service-specific operation tracking
- Trace flags byte for sampling and debug configuration
- Optional trace state for vendor-specific data
- Parent span ID for distributed call chain reconstruction

**Header Integration Requirements**:

- Parse W3C traceparent header format from HTTP requests
- Generate new span IDs while preserving trace ID
- Convert trace context to HTTP headers for downstream calls
- Support trace state propagation for observability tools
- Handle malformed headers gracefully with fallbacks

## Serialization Support

### MessageSerializer

**Message Serialization Requirements**:

- JSON serialization for cross-platform compatibility
- Binary data support for efficient queue transport
- Error handling with detailed failure information
- Performance optimization through cached serialized bodies
- Generic type support for different message types

**EventEnvelope Serialization Requirements**:

- Specialized handling for EventEnvelope structures
- Cached serialized body population for performance
- Deserialization with body cache reconstruction
- Validation of required fields during deserialization

### Message Validation

**Validation Requirements**:

- Required field validation (event ID, event type, repository)
- Session ID format and length constraints (max 128 characters)
- Trace context W3C format validation
- Repository full name format validation
- Entity ID format validation when present
- Payload structure validation for known event types
- Error reporting with specific field and reason information

**Trace Context Validation Requirements**:

- Trace ID format validation (32-character hex string)
- Span ID format validation (16-character hex string)
- Trace flags validation for W3C compliance
- Graceful error handling for malformed trace data

## Error Types

**MessageError Classifications**:

- **SerializationFailed**: JSON serialization errors with underlying cause
- **DeserializationFailed**: JSON parsing errors with detailed information
- **MissingField**: Required field absent from message structure
- **ValidationFailed**: Field validation errors with specific reasons
- **InvalidRepositoryName**: Malformed repository name format
- **InvalidEntityType**: Unrecognized entity type classification
- **InvalidTraceContext**: W3C trace context format violations
- **MessageTooLarge**: Message exceeds size limits for queue provider

## Usage Patterns

### Message Creation Workflow

**EventEnvelope Construction**:
1. Create repository information from owner/name
2. Construct envelope with event type and GitHub payload
3. Extract entity type and ID from payload content
4. Generate session ID for ordered processing entities
5. Add distributed tracing context for observability
6. Validate message structure and required fields
7. Serialize for queue transmission

### Message Processing Workflow

**EventEnvelope Processing**:
1. Deserialize message from queue provider
2. Validate message structure and field constraints
3. Route based on event type and entity classification
4. Extract entity-specific data from GitHub payload
5. Process event according to business logic requirements

### Trace Context Integration Patterns

**Trace Propagation Requirements**:

- Extract trace context from incoming HTTP headers using W3C format
- Attach trace context to EventEnvelope for end-to-end correlation
- Propagate trace headers to downstream service calls
- Handle missing trace context with new trace generation

## Testing Support

**Test Builder Requirements**:

- Fluent builder pattern for test EventEnvelope construction
- Pre-configured templates for common event types (pull request, issue)
- Repository configuration support for different test scenarios
- Session ID and trace context injection for integration testing
- Sample event generators for consistent test data

## Performance Characteristics

- **Serialization**: ~1-3ms for typical GitHub event (5-50KB)
- **Deserialization**: ~2-5ms for typical GitHub event
- **Validation**: ~0.1-0.5ms per message
- **Memory Usage**: ~2-10KB per EventEnvelope in memory
- **Trace Context Overhead**: ~50-100 bytes per message
- **Session Key Generation**: ~0.01ms per message
