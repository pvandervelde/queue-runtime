# Azure Service Bus Provider

This document defines the design requirements for the Azure Service Bus implementation of the queue-runtime client interface, supporting session-based ordered message processing and reliable delivery patterns.

## Overview

The Azure Service Bus provider implements queue operations using Azure Service Bus queues and sessions, providing ordered message processing and reliable delivery. The implementation must support both standard queues for high throughput and session-enabled queues for strict message ordering within sessions.

## Core Requirements

### Azure SDK Integration Requirements

**Service Bus Client Dependencies**:

- Azure Service Bus SDK for message operations (send, receive, complete, abandon, dead letter)
- Azure Core SDK for authentication and error handling
- Azure Identity SDK for credential management (managed identity, service principal, default credential chain)
- Session management for ordered message processing

## Client Architecture

### Authentication Requirements

**Connection String Authentication**:

- Service Bus connection string parsing and validation
- Endpoint and credential extraction from connection string
- Error handling for malformed connection strings
- Connection string security considerations

**Managed Identity Authentication**:

- Azure managed identity integration for serverless environments
- Service principal authentication with client ID and secret
- Default Azure credential chain support for development environments
- Token refresh and automatic credential renewal

### Client Lifecycle Management

**Service Bus Client Requirements**:

- Thread-safe client implementation supporting concurrent operations
- Connection pooling and reuse for multiple queues
- Sender and receiver cache management with automatic cleanup
- Session receiver management for ordered processing scenarios

**Resource Management Requirements**:

- Automatic connection management with health monitoring
- Graceful client shutdown with proper resource cleanup
- Connection retry logic for transient failures
- Memory-efficient cache management for senders and receivers

        Ok(Self {
            client,
            senders: Arc::new(RwLock::new(HashMap::new())),
            receivers: Arc::new(RwLock::new(HashMap::new())),
            session_receivers: Arc::new(RwLock::new(HashMap::new())),
            _phantom: std::marker::PhantomData,
        })
    }

    async fn get_or_create_sender(&self, queue_name: &str) -> Result<ServiceBusSender, AzureError> {
        let senders = self.senders.read().await;
        if let Some(sender) = senders.get(queue_name) {
            return Ok(sender.clone());
        }
        drop(senders);

        let mut senders = self.senders.write().await;

        // Double-check pattern
        if let Some(sender) = senders.get(queue_name) {
            return Ok(sender.clone());
        }

        let sender = self.client.create_sender(queue_name, None)
            .map_err(AzureError::from)?;

        senders.insert(queue_name.to_string(), sender.clone());
        Ok(sender)
    }

## Queue Operations

### Sender and Receiver Management

**Sender Creation Requirements**:

- Thread-safe sender creation and caching per queue
- Double-check locking pattern for sender initialization
- Automatic sender cleanup on connection failures
- Error handling for sender creation failures

**Receiver Management Requirements**:

- PeekLock receive mode for message processing safety
- Receiver caching and reuse patterns
- Concurrent receiver support for multiple consumers
- Session receiver management for ordered processing

**Session Receiver Requirements**:

- Session ID-based receiver key generation
- Session acceptance and lifecycle management
- Session lock renewal for long-running processing
- Session timeout handling and recovery
}

### Message Send Operations

**Message Serialization Requirements**:

- JSON serialization for message payloads with UTF-8 encoding
- Message ID generation for tracking and deduplication
- Session ID assignment for ordered processing requirements
- Message metadata configuration (TTL, content type, custom properties)

**Send Operation Requirements**:

- Sender lookup and caching for performance optimization
- Error handling for serialization failures
- Service Bus message construction with proper metadata
- Response processing and message ID extraction

### Message Receive Operations

**Standard Receive Requirements**:

- Configurable batch size for receive operations
- PeekLock mode for safe message processing
- Message deserialization with error handling
- Receipt handle management for acknowledgment operations

**Session-Based Receive Requirements**:

- Session receiver creation and management
- Session ID validation and assignment
- Message ordering guarantee within sessions
- Session lock renewal for long-running operations

**Message Envelope Construction**:

- Received message wrapper with payload and metadata
- Delivery count tracking for retry logic
- Enqueue timestamp extraction and validation
- Queue name and session ID preservation
        receipt.receiver.complete_message(&receipt.lock_token, None).await
            .map_err(AzureError::from_service_bus_error)
            .map_err(QueueError::from)
    }

    async fn reject(&self, receipt: &Self::Receipt) -> Result<(), QueueError> {
        receipt.receiver.abandon_message(&receipt.lock_token, None).await
            .map_err(AzureError::from_service_bus_error)
            .map_err(QueueError::from)
    }

    async fn dead_letter(&self, receipt: &Self::Receipt, reason: &str) -> Result<(), QueueError> {
        let properties = HashMap::from([
            ("DeadLetterReason".to_string(), reason.to_string()),
            ("DeadLetterDescription".to_string(), "Message processing failed".to_string()),
        ]);

        receipt.receiver.dead_letter_message(&receipt.lock_token, &properties, None).await
            .map_err(AzureError::from_service_bus_error)
            .map_err(QueueError::from)
    }
}

```

## Receipt Implementation

```rust
use azure_messaging_servicebus::LockToken;

#[derive(Debug, Clone)]
pub struct AzureReceipt {
    pub lock_token: LockToken,
    pub receiver: ServiceBusReceiver,
}

impl MessageReceipt for AzureReceipt {
    fn message_id(&self) -> &str {
        // Lock token serves as receipt identifier
        &self.lock_token.to_string()
    }

    fn is_valid(&self) -> bool {
        // Check if lock token is still valid (not expired)
        // This is a simplified check - in practice you'd verify with the service
        true
    }
}
```

### Message Acknowledgment

**Acknowledgment Requirements**:

- Lock token validation for message completion
- Complete message operation for successful processing
- Error handling for expired or invalid lock tokens
- Batch acknowledgment support for improved throughput

**Rejection and Retry Requirements**:

- Abandon message operation for retry scenarios
- Dead letter message operation for permanent failures
- Custom dead letter properties and reason codes
- Session state management during message processing

## Error Handling

### Azure-Specific Error Classification

**Service Bus Error Types**:

- Authentication and authorization error differentiation
- Network connectivity and timeout error handling
- Resource not found and quota exceeded scenarios
- Message and session lock expiration handling

**Error Recovery Requirements**:

- Retryable vs non-retryable error classification
- HTTP status code interpretation (401, 403, 404, 429)
- Azure Core error kind mapping and translation
- Exponential backoff for retryable operations

**Lock Management Error Handling**:

- Message lock expiration detection and handling
- Session lock lost scenarios and recovery patterns
- Automatic lock renewal for long-running operations
- Error context preservation for debugging

## Configuration Management

### Configuration Structure Requirements

**Core Configuration Parameters**:

- Connection string authentication for development environments
- Namespace specification for managed identity scenarios
- Authentication method selection and credential configuration
- Message behavior and queue feature configuration

**Message Processing Configuration**:

- Default message time-to-live (TTL) settings (default 24 hours)
- Duplicate detection enablement and detection window (10 minutes default)
- Session enablement for ordered processing
- Lock duration for message processing windows (30 seconds default)

**Quality of Service Configuration**:

- Maximum delivery count before dead lettering (default 10)
- Auto-delete on idle timeout for queue cleanup (optional)
- Lock renewal settings for long-running operations
- Batch processing configuration for throughput optimization

### Authentication Method Requirements

**Connection String Authentication**:

- Service Bus connection string parsing and validation
- Endpoint extraction and credential validation
- Environment variable and secure storage integration

**Managed Identity Support**:

- Azure managed identity integration for cloud environments
- Service principal authentication with client credentials (tenant ID, client ID, client secret)
- Default Azure credential chain for development scenarios

### Configuration Validation Requirements

**Default Configuration Values**:
            connection_string: None,
            namespace: None,
            auth_method: AzureAuthMethod::DefaultCredential,
            default_ttl: Duration::from_hours(24),
            enable_duplicate_detection: true,
            duplicate_detection_window: Duration::from_minutes(10),
            enable_sessions: true,
            max_delivery_count: 5,
            lock_duration: Duration::from_seconds(60),
            auto_delete_on_idle: Some(Duration::from_days(7)),
        }
    }
}

impl AzureServiceBusConfig {
    pub async fn create_credential(&self) -> Result<Arc<dyn TokenCredential>, AzureError> {
        match &self.auth_method {
            AzureAuthMethod::ManagedIdentity => {
                Ok(Arc::new(ManagedIdentityCredential::default()))
            }
            AzureAuthMethod::ClientSecret { tenant_id, client_id, client_secret } => {
                let credential = ClientSecretCredential::new(
                    tenant_id.clone(),
                    client_id.clone(),
                    client_secret.clone(),
                    None,
                );
                Ok(Arc::new(credential))
            }
            AzureAuthMethod::DefaultCredential => {
                Ok(Arc::new(DefaultAzureCredential::default()))
            }
            AzureAuthMethod::ConnectionString => {
                return Err(AzureError::AuthenticationError(
                    "Connection string auth should not create credential".to_string()
                ));
            }
        }
    }
}

```

## Queue Management

```rust
use azure_mgmt_servicebus::{ServiceBusManagementClient, models::*};

pub struct AzureQueueManager {
    management_client: ServiceBusManagementClient,
    resource_group: String,
    namespace_name: String,
}

impl AzureQueueManager {
    pub async fn new(
        subscription_id: String,
        resource_group: String,
        namespace_name: String,
        credential: Arc<dyn TokenCredential>,
    ) -> Result<Self, AzureError> {
        let management_client = ServiceBusManagementClient::new(credential, subscription_id, None);

        Ok(Self {
            management_client,
            resource_group,
            namespace_name,
        })
    }

    pub async fn create_queue(&self, queue_name: &str, config: &AzureServiceBusConfig) -> Result<(), AzureError> {
        let queue_properties = SBQueue {
            properties: Some(SBQueueProperties {
                lock_duration: Some(format!("PT{}S", config.lock_duration.as_secs())),
                max_size_in_megabytes: Some(1024), // 1GB default
                requires_duplicate_detection: Some(config.enable_duplicate_detection),
                duplicate_detection_history_time_window: Some(format!("PT{}S", config.duplicate_detection_window.as_secs())),
                requires_session: Some(config.enable_sessions),
                default_message_time_to_live: Some(format!("PT{}S", config.default_ttl.as_secs())),
                max_delivery_count: Some(config.max_delivery_count as i32),
                auto_delete_on_idle: config.auto_delete_on_idle.map(|d| format!("PT{}S", d.as_secs())),
                enable_partitioning: Some(false), // Disable partitioning for session support
                enable_express: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        self.management_client
            .queues()
            .create_or_update(
                &self.resource_group,
                &self.namespace_name,
                queue_name,
                queue_properties,
                None,
            )
            .await
            .map_err(|e| AzureError::ServiceBusError(e.to_string()))?;

        Ok(())
    }

    pub async fn delete_queue(&self, queue_name: &str) -> Result<(), AzureError> {
        self.management_client
            .queues()
            .delete(
                &self.resource_group,
                &self.namespace_name,
                queue_name,
                None,
            )
            .await
            .map_err(|e| AzureError::ServiceBusError(e.to_string()))?;

        Ok(())
    }

    pub async fn queue_exists(&self, queue_name: &str) -> Result<bool, AzureError> {
        match self.management_client
            .queues()
            .get(
                &self.resource_group,
                &self.namespace_name,
                queue_name,
                None,
            )
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    Ok(false)
                } else {
                    Err(AzureError::ServiceBusError(e.to_string()))
                }
            }
        }
    }

    pub async fn get_queue_stats(&self, queue_name: &str) -> Result<QueueStats, AzureError> {
        let queue = self.management_client
            .queues()
            .get(
                &self.resource_group,
                &self.namespace_name,
                queue_name,
                None,
            )
            .await
            .map_err(|e| AzureError::ServiceBusError(e.to_string()))?;

        let properties = queue.properties.unwrap_or_default();

        Ok(QueueStats {
            active_message_count: properties.count_details
                .and_then(|cd| cd.active_message_count)
                .unwrap_or(0) as u64,
            dead_letter_message_count: properties.count_details
                .and_then(|cd| cd.dead_letter_message_count)
                .unwrap_or(0) as u64,
            scheduled_message_count: properties.count_details
                .and_then(|cd| cd.scheduled_message_count)
                .unwrap_or(0) as u64,
            transfer_message_count: properties.count_details
                .and_then(|cd| cd.transfer_message_count)
                .unwrap_or(0) as u64,
            size_in_bytes: properties.size_in_bytes.unwrap_or(0) as u64,
        })
    }
}

#[derive(Debug, Clone)]
pub struct QueueStats {
    pub active_message_count: u64,
    pub dead_letter_message_count: u64,
    pub scheduled_message_count: u64,
    pub transfer_message_count: u64,
    pub size_in_bytes: u64,
}
```

## Session Management

```rust
pub struct AzureSessionManager {
    client: ServiceBusClient,
    active_sessions: Arc<RwLock<HashMap<String, SessionInfo>>>,
}

#[derive(Debug, Clone)]
struct SessionInfo {
    session_id: String,
    queue_name: String,
    receiver: SessionReceiver,
    last_activity: DateTime<Utc>,
    message_count: u32,
}

impl AzureSessionManager {
    pub async fn new(client: ServiceBusClient) -> Self {
        Self {
            client,
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn acquire_session(&self, queue_name: &str, session_id: &str) -> Result<SessionReceiver, AzureError> {
        let session_key = format!("{}::{}", queue_name, session_id);

        // Check if session is already active
        {
            let sessions = self.active_sessions.read().await;
            if let Some(session_info) = sessions.get(&session_key) {
                return Ok(session_info.receiver.clone());
            }
        }

        // Acquire new session
        let receiver = self.client
            .accept_session(queue_name, session_id, ReceiveMode::PeekLock, None)
            .await
            .map_err(AzureError::from_service_bus_error)?;

        let session_info = SessionInfo {
            session_id: session_id.to_string(),
            queue_name: queue_name.to_string(),
            receiver: receiver.clone(),
            last_activity: Utc::now(),
            message_count: 0,
        };

        let mut sessions = self.active_sessions.write().await;
        sessions.insert(session_key, session_info);

        Ok(receiver)
    }

    pub async fn close_session(&self, queue_name: &str, session_id: &str) -> Result<(), AzureError> {
        let session_key = format!("{}::{}", queue_name, session_id);

        let mut sessions = self.active_sessions.write().await;
        if let Some(session_info) = sessions.remove(&session_key) {
            session_info.receiver.close().await
                .map_err(AzureError::from_service_bus_error)?;
        }

        Ok(())
    }

    pub async fn set_session_state(&self, queue_name: &str, session_id: &str, state: &[u8]) -> Result<(), AzureError> {
        let receiver = self.acquire_session(queue_name, session_id).await?;

        receiver.set_session_state(state, None).await
            .map_err(AzureError::from_service_bus_error)?;

        Ok(())
    }

    pub async fn get_session_state(&self, queue_name: &str, session_id: &str) -> Result<Option<Vec<u8>>, AzureError> {
        let receiver = self.acquire_session(queue_name, session_id).await?;

        let state = receiver.get_session_state(None).await
            .map_err(AzureError::from_service_bus_error)?;

        Ok(state)
    }

    pub async fn cleanup_idle_sessions(&self, idle_timeout: Duration) -> Result<Vec<String>, AzureError> {
        let mut closed_sessions = Vec::new();
        let cutoff_time = Utc::now() - chrono::Duration::from_std(idle_timeout).unwrap();

        let mut sessions = self.active_sessions.write().await;
        let idle_sessions: Vec<String> = sessions
            .iter()
            .filter(|(_, info)| info.last_activity < cutoff_time)
            .map(|(key, _)| key.clone())
            .collect();

        for session_key in idle_sessions {
            if let Some(session_info) = sessions.remove(&session_key) {
                if let Err(e) = session_info.receiver.close().await {
                    tracing::warn!("Failed to close idle session {}: {}", session_key, e);
                } else {
                    closed_sessions.push(session_key);
                }
            }
        }

        Ok(closed_sessions)
    }
}
```

## Testing Support

```rust
#[cfg(test)]
pub mod testing {
    use super::*;
    use mockall::mock;

    mock! {
        pub AzureServiceBusClient<T: Clone + Send + Sync + 'static> {}

        #[async_trait]
        impl<T: Clone + Send + Sync + 'static> QueueClient<T> for AzureServiceBusClient<T> {
            type Receipt = AzureReceipt;

            async fn send(&self, queue_name: &str, message: &T, session_id: Option<&str>) -> Result<MessageId, QueueError>;
            async fn receive(&self, queue_name: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError>;
            async fn receive_from_session(&self, queue_name: &str, session_id: &str, max_messages: u32) -> Result<Vec<ReceivedMessage<T, Self::Receipt>>, QueueError>;
            async fn acknowledge(&self, receipt: &Self::Receipt) -> Result<(), QueueError>;
            async fn reject(&self, receipt: &Self::Receipt) -> Result<(), QueueError>;
            async fn dead_letter(&self, receipt: &Self::Receipt, reason: &str) -> Result<(), QueueError>;
        }
    }

    pub fn create_mock_client<T: Clone + Send + Sync + 'static>() -> MockAzureServiceBusClient<T> {
        MockAzureServiceBusClient::new()
    }

    pub fn create_test_config() -> AzureServiceBusConfig {
        AzureServiceBusConfig {
            connection_string: Some("Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=test".to_string()),
            auth_method: AzureAuthMethod::ConnectionString,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_azure_error_classification() {
        let retryable_error = AzureError::NetworkError("Connection failed".to_string());
        assert!(retryable_error.is_retryable());

        let non_retryable_error = AzureError::AuthenticationError("Invalid credentials".to_string());
        assert!(!non_retryable_error.is_retryable());

        let lock_lost_error = AzureError::MessageLockLost("Lock expired".to_string());
        assert!(!lock_lost_error.is_retryable());
    }

    #[tokio::test]
    async fn test_config_credential_creation() {
        let config = AzureServiceBusConfig {
            auth_method: AzureAuthMethod::DefaultCredential,
            ..Default::default()
        };

        let credential = config.create_credential().await;
        assert!(credential.is_ok());
    }
}
```

## Performance Optimization

### Connection Pooling

```rust
pub struct AzureConnectionPool {
    clients: Arc<RwLock<Vec<Arc<ServiceBusClient>>>>,
    config: AzureServiceBusConfig,
    pool_size: usize,
}

impl AzureConnectionPool {
    pub async fn new(config: AzureServiceBusConfig, pool_size: usize) -> Result<Self, AzureError> {
        let mut clients = Vec::new();

        for _ in 0..pool_size {
            let client = if let Some(connection_string) = &config.connection_string {
                ServiceBusClient::from_connection_string(connection_string, None)
                    .map_err(AzureError::from)?
            } else if let Some(namespace) = &config.namespace {
                let credential = config.create_credential().await?;
                ServiceBusClient::new(namespace, credential, None)
                    .map_err(AzureError::from)?
            } else {
                return Err(AzureError::AuthenticationError("No connection string or namespace provided".to_string()));
            };

            clients.push(Arc::new(client));
        }

        Ok(Self {
            clients: Arc::new(RwLock::new(clients)),
            config,
            pool_size,
        })
    }

    pub async fn get_client(&self) -> Arc<ServiceBusClient> {
        let clients = self.clients.read().await;
        let index = rand::thread_rng().gen_range(0..self.pool_size);
        clients[index].clone()
    }
}
```

## Best Practices

1. **Use Sessions**: Enable sessions for ordered message processing
2. **Set Appropriate TTL**: Configure message time-to-live based on use case
3. **Handle Lock Renewal**: Renew message locks for long-running operations
4. **Monitor Dead Letters**: Track and analyze dead letter queue messages
5. **Use Managed Identity**: Prefer managed identity over connection strings
6. **Connection Pooling**: Pool Service Bus clients for better performance
7. **Error Classification**: Properly classify errors for retry logic
8. **Session State Management**: Use session state for complex workflows
