# Queue-Runtime Behavioral Assertions

## Overview

This document defines testable behavioral assertions for the queue-runtime library. These assertions verify that all provider implementations (Azure Service Bus, AWS SQS) behave consistently and meet the functional requirements regardless of the underlying queue technology.

## Core Queue Operations

### Assertion 1: Message Send Success

**Given**: A valid queue client and a message to send
**When**: `send_message()` is called with the message
**Then**: Operation returns `Ok(MessageId)` with a valid message identifier
**And**: Message is available for receiving from the same queue

**Test Criteria**:

- Message ID is non-empty and unique
- Sent message can be retrieved via `receive_message()`
- Message content matches exactly what was sent

### Assertion 2: Message Send to Non-Existent Queue

**Given**: A queue client configured for a non-existent queue
**When**: `send_message()` is called
**Then**: Operation returns `Err(QueueError::QueueNotFound)`
**And**: No message is sent to any queue

**Test Criteria**:

- Error type is specifically `QueueNotFound`
- Error includes the queue name that was not found
- No side effects occur (no partial sends)

### Assertion 3: Message Receive Success

**Given**: A queue with at least one message available
**When**: `receive_message()` is called
**Then**: Operation returns `Ok(Some(ReceivedMessage))`
**And**: Message contains the original payload and valid receipt handle

**Test Criteria**:

- Message payload matches what was originally sent
- Receipt handle is valid for completion operations
- Message visibility timeout starts immediately

### Assertion 4: Message Receive from Empty Queue

**Given**: A queue with no available messages
**When**: `receive_message()` is called with a timeout
**Then**: Operation returns `Ok(None)` when timeout expires
**And**: No error occurs

**Test Criteria**:

- Returns exactly at timeout boundary (±100ms tolerance)
- No exception or error returned
- Operation is cancellable before timeout

### Assertion 5: Message Completion Success

**Given**: A message that has been received but not yet completed
**When**: `complete_message()` is called with valid receipt handle
**Then**: Operation returns `Ok(())`
**And**: Message is permanently removed from the queue

**Test Criteria**:

- Message cannot be received again after completion
- Receipt handle becomes invalid after completion
- No error occurs during completion

### Assertion 6: Message Completion with Invalid Receipt

**Given**: An invalid or expired receipt handle
**When**: `complete_message()` is called
**Then**: Operation returns `Err(QueueError::InvalidReceipt)`
**And**: No messages are affected

**Test Criteria**:

- Error type is specifically `InvalidReceipt`
- Error includes the invalid receipt handle for debugging
- Queue state remains unchanged

## Session-Based Operations

### Assertion 7: Session Message Ordering (Azure Service Bus)

**Given**: A session-enabled queue and multiple messages with the same session ID
**When**: Messages are sent in sequence A, B, C
**Then**: Messages are received in the same order: A, B, C
**And**: No other session's messages interleave during processing

**Test Criteria**:

- Strict FIFO ordering within session
- Session lock prevents concurrent processing
- Messages from different sessions can be processed concurrently

### Assertion 8: Session Compatibility (AWS SQS)

**Given**: An AWS SQS queue configured for sessions (via message groups)
**When**: Session operations are performed
**Then**: Operations succeed with emulated session behavior
**And**: Ordering is preserved within message groups

**Test Criteria**:

- Message group ID used as session identifier
- FIFO ordering maintained within same message group
- Graceful degradation when native sessions unavailable

### Assertion 9: Session Lock Acquisition

**Given**: A session-enabled queue with messages in a specific session
**When**: `accept_session()` is called
**Then**: Operation returns `Ok(SessionClient)` with exclusive lock
**And**: Concurrent session acceptance fails with lock error

**Test Criteria**:

- Only one client can hold session lock at a time
- Lock automatically renewed during active processing
- Lock released on session client drop

### Assertion 10: Session Lock Timeout

**Given**: A session client that becomes inactive
**When**: Session lock timeout period expires
**Then**: Session lock is automatically released
**And**: Another client can acquire the session lock

**Test Criteria**:

- Lock timeout occurs at expected interval
- Messages become available to other clients
- Original client receives lock lost error on next operation

## Error Handling and Recovery

### Assertion 11: Network Connectivity Failure

**Given**: A queue client when network connectivity is lost
**When**: Any queue operation is attempted
**Then**: Operation returns `Err(QueueError::ConnectionFailed)`
**And**: Client can recover when connectivity is restored

**Test Criteria**:

- Specific connection error is returned
- Client automatically retries on connection recovery
- No corruption of internal client state

### Assertion 12: Provider Service Throttling

**Given**: A queue client experiencing provider throttling (HTTP 429)
**When**: Operations are attempted during throttling
**Then**: Client implements exponential backoff automatically
**And**: Operations eventually succeed when throttling stops

**Test Criteria**:

- Exponential backoff with jitter applied
- Maximum retry attempts respected
- Success after throttling period ends

### Assertion 13: Message Visibility Timeout Expiry

**Given**: A message that has been received but not completed
**When**: Visibility timeout period expires
**Then**: Message becomes available for receiving again
**And**: Original receipt handle becomes invalid

**Test Criteria**:

- Message reappears in queue after exact timeout period
- New receipt handle issued on re-receipt
- Old receipt handle returns `InvalidReceipt` error

### Assertion 14: Dead Letter Queue Routing

**Given**: A message that has exceeded maximum delivery attempts
**When**: Message processing fails repeatedly
**Then**: Message is automatically moved to dead letter queue
**And**: Original queue no longer contains the message

**Test Criteria**:

- Message appears in dead letter queue with metadata
- Original failure context preserved
- Dead letter queue configured correctly

## Configuration and Provider Selection

### Assertion 15: Provider Runtime Selection

**Given**: Queue runtime configured with provider selection
**When**: Different provider configurations are used
**Then**: Correct provider adapter is instantiated
**And**: All operations work consistently across providers

**Test Criteria**:

- Azure Service Bus selected for Azure configurations
- AWS SQS selected for AWS configurations
- Same API behavior regardless of provider

### Assertion 16: Configuration Validation

**Given**: Invalid queue configuration (missing connection string, etc.)
**When**: Queue client is instantiated
**Then**: Operation returns `Err(QueueError::ConfigurationError)`
**And**: Error message clearly identifies the configuration problem

**Test Criteria**:

- Validation occurs at client creation time
- Specific field validation errors provided
- No partial initialization occurs

### Assertion 17: Connection String Security

**Given**: Queue configuration with connection strings containing secrets
**When**: Configuration is logged or serialized
**Then**: Sensitive values are redacted or masked
**And**: Full connection functionality is preserved

**Test Criteria**:

- Connection strings not visible in logs
- Serde serialization masks sensitive fields
- Actual connections work correctly

## Performance and Scalability

### Assertion 18: Concurrent Operations

**Given**: Multiple concurrent queue operations on the same client
**When**: Operations execute simultaneously
**Then**: All operations complete successfully without interference
**And**: No race conditions or data corruption occurs

**Test Criteria**:

- Thread safety maintained across all operations
- Performance scales with concurrent usage
- No deadlocks or resource contention

### Assertion 19: Connection Pooling

**Given**: A queue client with connection pooling enabled
**When**: Multiple operations require connections
**Then**: Connections are reused efficiently
**And**: Pool limits are respected

**Test Criteria**:

- Maximum connections not exceeded
- Idle connections reused appropriately
- Graceful handling when pool exhausted

### Assertion 20: Batch Operations

**Given**: A provider that supports batch operations
**When**: Multiple messages are sent/received in batch
**Then**: Operations are batched automatically for efficiency
**And**: Individual operation semantics are preserved

**Test Criteria**:

- Azure: Up to 100 messages per batch
- AWS: Up to 10 messages per batch
- Partial batch failures handled correctly

## Observability and Monitoring

### Assertion 21: Distributed Tracing Propagation

**Given**: Queue operations within a distributed trace context
**When**: Messages are sent and received
**Then**: Trace context is propagated through the message flow
**And**: Spans are created for all major operations

**Test Criteria**:

- OpenTelemetry trace context preserved
- Send and receive operations create spans
- Error spans include appropriate error information

### Assertion 22: Metrics Collection

**Given**: Queue client with metrics enabled
**When**: Various operations are performed
**Then**: Appropriate metrics are recorded
**And**: Metrics include operation type, status, and timing

**Test Criteria**:

- Counter metrics for operations (sent, received, completed)
- Histogram metrics for operation latency
- Error rate metrics by error type

### Assertion 23: Structured Logging

**Given**: Queue operations with structured logging enabled
**When**: Operations and errors occur
**Then**: Log entries include structured context
**And**: Log levels are appropriate for the event type

**Test Criteria**:

- Queue names and operation types in log context
- Error logs include full error context
- No sensitive data in log messages

## Cryptography and MITM Protection

### Assertion 24: Message Encryption Round-Trip

**Given**: A queue client with encryption enabled and a valid key provider
**When**: A message is sent with plaintext body
**Then**: Message is automatically encrypted before sending
**And**: When received, message is automatically decrypted to original plaintext

**Test Criteria**:

- Decrypted plaintext exactly matches original plaintext
- Application code does not handle encryption/decryption
- Encryption transparent to caller (same API as non-encrypted)

### Assertion 25: Tampered Message Rejection

**Given**: An encrypted message that has been tampered with
**When**: The tampered message is decrypted
**Then**: Operation returns `Err(CryptoError::AuthenticationFailed)`
**And**: Plaintext is never returned to caller

**Test Criteria**:

- Ciphertext modification detected (bit flip in body)
- Authentication tag modification detected
- Associated data modification detected (message ID change)
- Error message does not reveal key information

### Assertion 26: Freshness Validation

**Given**: An encrypted message with timestamp older than configured max age
**When**: Message is received with freshness validation enabled
**Then**: Operation returns `Err(CryptoError::MessageExpired)`
**And**: Message is not decrypted or processed

**Test Criteria**:

- Message encrypted 10 minutes ago rejected (max_age = 5 minutes)
- Message encrypted 2 minutes ago accepted (max_age = 5 minutes)
- Error includes timestamp and max age for debugging
- Validation can be disabled via configuration

### Assertion 27: Key Rotation Support

**Given**: A key provider with multiple active keys
**When**: Messages are encrypted with key A and key provider rotates to key B
**Then**: New messages encrypt with key B
**And**: Old messages encrypted with key A still decrypt successfully

**Test Criteria**:

- Messages encrypted with old key decrypt correctly
- Messages encrypted with new key decrypt correctly
- Key ID stored in encrypted message metadata
- No service interruption during key rotation

### Assertion 28: Key Not Found Error

**Given**: An encrypted message referencing a non-existent key ID
**When**: Message decryption is attempted
**Then**: Operation returns `Err(CryptoError::KeyNotFound { key_id })`
**And**: Error includes the missing key ID for debugging

**Test Criteria**:

- Error clearly identifies which key is missing
- Error distinguishes key-not-found from authentication-failed
- Suggests checking key rotation and key provider configuration

### Assertion 29: Replay Attack Prevention (Nonce Tracking)

**Given**: Crypto config with nonce tracking enabled
**When**: Same encrypted message is received twice
**Then**: First receive succeeds, second receive returns `Err(CryptoError::NonceReused)`

**Test Criteria**:

- Duplicate nonce detected and rejected
- Nonce cache respects configured TTL
- Nonce tracking optional (disabled by default for performance)

### Assertion 30: Metadata Remains Cleartext

**Given**: A message with session ID, correlation ID, and properties
**When**: Message is encrypted
**Then**: Message body is encrypted
**And**: Session ID, correlation ID, and message ID remain in cleartext

**Test Criteria**:

- Session-based routing works with encrypted messages
- Correlation IDs visible in logs for tracing
- Message IDs used for deduplication
- Only message body encrypted (routing metadata cleartext)

### Assertion 31: Key Material Security

**Given**: An encryption key loaded into memory
**When**: Key is no longer needed
**Then**: Key material is zeroed from memory
**And**: Key never appears in logs or error messages

**Test Criteria**:

- Debug implementation redacts key material
- Drop implementation zeros memory (zeroize crate)
- Error messages never include key bytes
- Key IDs MAY be logged (non-sensitive)

### Assertion 32: Crypto Disabled by Default

**Given**: A queue client created without explicit crypto configuration
**When**: Messages are sent and received
**Then**: No encryption/decryption occurs
**And**: Messages sent as plaintext (backward compatible)

**Test Criteria**:

- Default config has `crypto.enabled = false`
- Encryption opt-in via explicit configuration
- No performance overhead when disabled
- Clear documentation on enabling crypto

### Assertion 33: Algorithm Versioning

**Given**: An encrypted message with version field
**When**: Message is received by library
**Then**: If version supported, decrypt successfully
**And**: If version unsupported, return `Err(CryptoError::UnsupportedVersion)`

**Test Criteria**:

- Version 1 (AES-256-GCM) supported
- Unknown versions rejected with clear error
- Enables future algorithm upgrades without breaking changes
- Version field in encrypted message envelope

### Assertion 34: Constant-Time Verification

**Given**: Authentication tag verification during decryption
**When**: Tag is correct or incorrect
**Then**: Verification time does not reveal information about tag correctness

**Test Criteria**:

- Use constant-time comparison functions
- No timing-based information leakage
- Prevents timing attacks on authentication tag
- Use `subtle` crate or equivalent for comparisons

### Assertion 35: Encryption Detection and Mixed Mode

**Given**: A receiver configured to accept both encrypted and plaintext messages
**When**: Messages arrive with and without encryption
**Then**: Receiver correctly detects encryption status for each message
**And**: Plaintext messages log WARNING and emit metric `encrypted="false"`
**And**: Encrypted messages log INFO and emit metric `encrypted="true"`

**Test Criteria**:

- Message body starting with "QRE1" detected as encrypted
- Message body without marker detected as plaintext
- Both message types processed correctly
- Metrics distinguish encrypted vs plaintext (labeled counters)
- Logs include encryption status for observability

### Assertion 36: Debug Mode with Encryption Disabled

**Given**: A sender with crypto config `enabled: false`
**When**: Messages are sent
**Then**: Messages sent as plaintext (no encryption)
**And**: Each send logs WARNING about encryption disabled
**And**: Metric `queue_messages_sent{encrypted="false"}` incremented

**Test Criteria**:

- No "QRE1" marker in message body
- No encryption overhead (performance)
- Clear warnings in logs for audit trail
- Metrics enable monitoring of unencrypted messages

### Assertion 37: Plaintext Policy Enforcement

**Given**: A receiver with `plaintext_policy: PlaintextPolicy::Reject`
**When**: A plaintext (unencrypted) message is received
**Then**: Operation returns `Err(QueueError::UnencryptedMessage)`
**And**: Message is not processed
**And**: Error logged and metric incremented

**Test Criteria**:

- Plaintext messages rejected in strict mode
- Error clearly indicates encryption requirement
- No security bypass possible
- Policy configurable (Allow/Reject/AllowWithAlert)

## Integration and Compatibility

### Assertion 35: Provider Feature Compatibility

**Given**: Operations that use provider-specific features
**When**: The same operations are performed on different providers
**Then**: Equivalent functionality is provided on all providers
**And**: Feature gaps are clearly documented and handled

**Test Criteria**:

- Session support matrix documented and tested
- Graceful degradation when features unavailable
- Clear error messages for unsupported operations

### Assertion 36: Version Compatibility

**Given**: Different versions of provider SDKs
**When**: Queue runtime is used with various SDK versions
**Then**: Compatible SDK versions work correctly
**And**: Incompatible SDK versions are detected early

**Test Criteria**:

- Minimum supported SDK versions documented
- Compile-time compatibility checking where possible
- Runtime compatibility detection with clear errors
