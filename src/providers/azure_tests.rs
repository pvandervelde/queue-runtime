//! Tests for Azure Service Bus provider implementation.

use super::*;
use crate::message::Message;
use bytes::Bytes;
use chrono::Duration;

// ============================================================================
// Authentication and Configuration Tests
// ============================================================================

mod authentication_tests {
    use super::*;

    /// Test connection string authentication succeeds with valid config
    #[tokio::test]
    async fn test_connection_string_auth_succeeds() {
        // Arrange
        let config = AzureServiceBusConfig {
            connection_string: Some(
                "Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=dGVzdA=="
                    .to_string(),
            ),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(result.is_ok(), "Connection string auth should succeed");
        let provider = result.unwrap();
        assert_eq!(provider.provider_type(), ProviderType::AzureServiceBus);
    }

    /// Test managed identity authentication requires namespace
    #[tokio::test]
    async fn test_managed_identity_requires_namespace() {
        // Arrange
        let config = AzureServiceBusConfig {
            connection_string: None,
            namespace: None,
            auth_method: AzureAuthMethod::ManagedIdentity,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(result.is_err(), "Should fail without namespace");
        let err = result.unwrap_err();
        assert!(
            matches!(err, AzureError::ConfigurationError(_)),
            "Should be configuration error"
        );
    }

    /// Test managed identity authentication succeeds with namespace
    #[tokio::test]
    async fn test_managed_identity_auth_succeeds() {
        // Arrange
        let config = AzureServiceBusConfig {
            connection_string: None,
            namespace: Some("test-namespace".to_string()),
            auth_method: AzureAuthMethod::ManagedIdentity,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(
            result.is_ok(),
            "Managed identity auth with namespace should succeed"
        );
    }

    /// Test client secret authentication requires all parameters
    #[tokio::test]
    async fn test_client_secret_requires_all_params() {
        // Arrange - missing namespace
        let config = AzureServiceBusConfig {
            connection_string: None,
            namespace: None,
            auth_method: AzureAuthMethod::ClientSecret {
                tenant_id: "tenant".to_string(),
                client_id: "client".to_string(),
                client_secret: "secret".to_string(),
            },
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(result.is_err(), "Should fail without namespace");
    }

    /// Test client secret authentication succeeds with all parameters
    #[tokio::test]
    async fn test_client_secret_auth_succeeds() {
        // Arrange
        let config = AzureServiceBusConfig {
            connection_string: None,
            namespace: Some("test-namespace".to_string()),
            auth_method: AzureAuthMethod::ClientSecret {
                tenant_id: "tenant-id".to_string(),
                client_id: "client-id".to_string(),
                client_secret: "client-secret".to_string(),
            },
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(
            result.is_ok(),
            "Client secret auth with all params should succeed"
        );
    }

    /// Test default credential authentication succeeds
    #[tokio::test]
    async fn test_default_credential_auth_succeeds() {
        // Arrange
        let config = AzureServiceBusConfig {
            connection_string: None,
            namespace: Some("test-namespace".to_string()),
            auth_method: AzureAuthMethod::DefaultCredential,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        // Act
        let result = AzureServiceBusProvider::new(config).await;

        // Assert
        assert!(result.is_ok(), "Default credential auth should succeed");
    }

    /// Test connection string auth method doesn't expose secrets in debug
    #[tokio::test]
    async fn test_connection_string_security_in_debug() {
        // Arrange
        let auth = AzureAuthMethod::ConnectionString;

        // Act
        let debug_output = format!("{:?}", auth);

        // Assert
        assert_eq!(debug_output, "ConnectionString");
        assert!(
            !debug_output.contains("test"),
            "Debug output should not contain secrets"
        );
    }

    /// Test client secret auth method doesn't expose secrets in debug
    #[tokio::test]
    async fn test_client_secret_security_in_debug() {
        // Arrange
        let auth = AzureAuthMethod::ClientSecret {
            tenant_id: "tenant-id".to_string(),
            client_id: "client-id".to_string(),
            client_secret: "super-secret".to_string(),
        };

        // Act
        let debug_output = format!("{:?}", auth);

        // Assert
        // Should show structure and non-secret fields but redact client_secret
        assert!(debug_output.contains("ClientSecret"));
        assert!(
            debug_output.contains("tenant_id"),
            "Should show tenant_id field"
        );
        assert!(
            debug_output.contains("client_id"),
            "Should show client_id field"
        );
        assert!(
            debug_output.contains("REDACTED"),
            "Should redact client_secret"
        );
        assert!(
            !debug_output.contains("super-secret"),
            "Should not expose secret value"
        );
    }
}

// ============================================================================
// Error Classification Tests
// ============================================================================

mod error_tests {
    use super::*;

    /// Test authentication errors are not transient
    #[test]
    fn test_authentication_error_not_transient() {
        // Arrange
        let error = AzureError::AuthenticationError("Invalid credentials".to_string());

        // Act & Assert
        assert!(!error.is_transient(), "Auth errors should not be transient");
    }

    /// Test network errors are transient
    #[test]
    fn test_network_error_is_transient() {
        // Arrange
        let error = AzureError::NetworkError("Connection timeout".to_string());

        // Act & Assert
        assert!(error.is_transient(), "Network errors should be transient");
    }

    /// Test Service Bus errors are transient
    #[test]
    fn test_service_bus_error_is_transient() {
        // Arrange
        let error = AzureError::ServiceBusError("Throttled".to_string());

        // Act & Assert
        assert!(
            error.is_transient(),
            "Service Bus errors should be transient"
        );
    }

    /// Test message lock lost is not transient
    #[test]
    fn test_message_lock_lost_not_transient() {
        // Arrange
        let error = AzureError::MessageLockLost("Lock expired".to_string());

        // Act & Assert
        assert!(!error.is_transient(), "Lock lost should not be transient");
    }

    /// Test session lock lost is not transient
    #[test]
    fn test_session_lock_lost_not_transient() {
        // Arrange
        let error = AzureError::SessionLockLost("session-123".to_string());

        // Act & Assert
        assert!(
            !error.is_transient(),
            "Session lock lost should not be transient"
        );
    }

    /// Test Azure error maps to correct QueueError type
    #[test]
    fn test_azure_error_to_queue_error_mapping() {
        // Authentication error
        let azure_err = AzureError::AuthenticationError("test".to_string());
        let queue_err = azure_err.to_queue_error();
        assert!(
            matches!(queue_err, QueueError::AuthenticationFailed { .. }),
            "Should map to AuthenticationFailed"
        );

        // Network error
        let azure_err = AzureError::NetworkError("test".to_string());
        let queue_err = azure_err.to_queue_error();
        assert!(
            matches!(queue_err, QueueError::ConnectionFailed { .. }),
            "Should map to ConnectionFailed"
        );

        // Message lock lost
        let azure_err = AzureError::MessageLockLost("receipt-123".to_string());
        let queue_err = azure_err.to_queue_error();
        assert!(
            matches!(queue_err, QueueError::InvalidReceipt { .. }),
            "Should map to InvalidReceipt"
        );

        // Session lock lost
        let azure_err = AzureError::SessionLockLost("session-123".to_string());
        let queue_err = azure_err.to_queue_error();
        assert!(
            matches!(queue_err, QueueError::SessionNotFound { .. }),
            "Should map to SessionNotFound"
        );
    }
}

// ============================================================================
// Provider Trait Implementation Tests
// ============================================================================

mod provider_tests {
    use super::*;

    /// Helper to create test provider
    async fn create_test_provider() -> AzureServiceBusProvider {
        let config = AzureServiceBusConfig {
            connection_string: Some(
                "Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=dGVzdA=="
                    .to_string(),
            ),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        AzureServiceBusProvider::new(config)
            .await
            .expect("Should create test provider")
    }

    /// Test provider type returns AzureServiceBus
    #[tokio::test]
    async fn test_provider_type() {
        // Arrange
        let provider = create_test_provider().await;

        // Act
        let provider_type = provider.provider_type();

        // Assert
        assert_eq!(
            provider_type,
            ProviderType::AzureServiceBus,
            "Should return AzureServiceBus type"
        );
    }

    /// Test provider supports native sessions
    #[tokio::test]
    async fn test_supports_sessions() {
        // Arrange
        let provider = create_test_provider().await;

        // Act
        let session_support = provider.supports_sessions();

        // Assert
        assert_eq!(
            session_support,
            SessionSupport::Native,
            "Azure Service Bus should advertise native session support"
        );
    }

    /// Test provider supports batching
    #[tokio::test]
    async fn test_supports_batching() {
        // Arrange
        let provider = create_test_provider().await;

        // Act
        let supports_batching = provider.supports_batching();

        // Assert
        assert!(supports_batching, "Should support batching");
    }

    /// Test max batch size is 100 for Azure Service Bus
    #[tokio::test]
    async fn test_max_batch_size() {
        // Arrange
        let provider = create_test_provider().await;

        // Act
        let max_batch_size = provider.max_batch_size();

        // Assert
        assert_eq!(
            max_batch_size, 100,
            "Azure Service Bus max batch size should be 100"
        );
    }

    /// Test send_messages enforces batch size limit
    #[tokio::test]
    async fn test_send_messages_batch_size_limit() {
        // Arrange
        let provider = create_test_provider().await;
        let queue = QueueName::new("test-queue".to_string()).unwrap();

        // Create 101 messages (exceeds limit)
        let messages: Vec<Message> = (0..101)
            .map(|i| Message::new(Bytes::from(format!("message-{}", i))))
            .collect();

        // Act
        let result = provider.send_messages(&queue, &messages).await;

        // Assert
        assert!(result.is_err(), "Should fail with batch too large");
        if let Err(QueueError::BatchTooLarge { size, max_size }) = result {
            assert_eq!(size, 101);
            assert_eq!(max_size, 100);
        } else {
            panic!("Expected BatchTooLarge error");
        }
    }

    /// Test receive_messages enforces batch size limit (32 for Azure)
    #[tokio::test]
    async fn test_receive_messages_batch_size_limit() {
        // Arrange
        let provider = create_test_provider().await;
        let queue = QueueName::new("test-queue".to_string()).unwrap();

        // Act - request 33 messages (exceeds Azure limit)
        let result = provider
            .receive_messages(&queue, 33, Duration::seconds(1))
            .await;

        // Assert
        assert!(result.is_err(), "Should fail with batch too large");
        if let Err(QueueError::BatchTooLarge { size, max_size }) = result {
            assert_eq!(size, 33);
            assert_eq!(max_size, 32);
        } else {
            panic!("Expected BatchTooLarge error");
        }
    }
}

// ============================================================================
// Session Provider Tests
// ============================================================================

mod session_tests {
    use super::*;
    use crate::message::Timestamp;
    use reqwest::Client as HttpClient;

    /// Build a minimal test config backed by a fake connection string.
    fn make_test_config() -> AzureServiceBusConfig {
        AzureServiceBusConfig {
            connection_string: Some(
                "Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=dGVzdA=="
                    .to_string(),
            ),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        }
    }

    /// Build an `AzureSessionProvider` wired with test credentials.
    fn make_test_session_provider(
        session_id: SessionId,
        queue_name: QueueName,
    ) -> AzureSessionProvider {
        let config = make_test_config();
        let http_client = HttpClient::new();
        let namespace_url = "https://test.servicebus.windows.net".to_string();
        AzureSessionProvider::new(
            session_id,
            queue_name,
            Duration::minutes(5),
            http_client,
            namespace_url,
            config,
            None,
        )
    }

    /// Test session provider construction records the correct session ID.
    #[test]
    fn test_session_provider_creation() {
        let session_id = SessionId::new("test-session".to_string()).unwrap();
        let queue_name = QueueName::new("test-queue".to_string()).unwrap();

        let provider = make_test_session_provider(session_id.clone(), queue_name);

        assert_eq!(provider.session_id(), &session_id);
        assert!(
            provider.session_expires_at().as_datetime() > Utc::now(),
            "Session should not be expired immediately after creation"
        );
    }

    /// Test that `session_expires_at` is ~session_timeout from creation.
    #[test]
    fn test_session_expiry_calculation() {
        let session_id = SessionId::new("test-session".to_string()).unwrap();
        let queue_name = QueueName::new("test-queue".to_string()).unwrap();
        let timeout = Duration::minutes(5);
        let before = Utc::now();

        let provider = make_test_session_provider(session_id, queue_name);

        let expiry = provider.session_expires_at().as_datetime();
        let expected_expiry = before + timeout;
        let diff = (expiry - expected_expiry).num_seconds().abs();
        assert!(
            diff < 2,
            "Expiry should be ~5 minutes from creation (diff: {}s)",
            diff
        );
    }

    /// `receive_message` should attempt an HTTP call (fails with test creds, not a stub error).
    #[tokio::test]
    async fn test_receive_message_attempts_http_operation() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let result = provider.receive_message(Duration::seconds(5)).await;

        assert!(
            result.is_err(),
            "Should fail with test credentials; got {:?}",
            result.ok()
        );
        // Must be a network/auth error, not a stub NotImplemented error.
        if let Err(QueueError::ProviderError { ref code, .. }) = result {
            assert_ne!(code, "NotImplemented", "Should not be a stub error");
        }
    }

    /// `complete_message` with an unknown receipt returns `InvalidReceipt` immediately.
    #[tokio::test]
    async fn test_complete_message_unknown_receipt_returns_invalid_receipt() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let receipt = ReceiptHandle::new(
            "nonexistent-lock-token".to_string(),
            Timestamp::from_datetime(Utc::now() + Duration::minutes(1)),
            ProviderType::AzureServiceBus,
        );

        let result = provider.complete_message(&receipt).await;

        assert!(
            matches!(result, Err(QueueError::InvalidReceipt { .. })),
            "Unknown receipt should return InvalidReceipt; got {:?}",
            result
        );
    }

    /// `abandon_message` with an unknown receipt returns `InvalidReceipt` immediately.
    #[tokio::test]
    async fn test_abandon_message_unknown_receipt_returns_invalid_receipt() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let receipt = ReceiptHandle::new(
            "nonexistent-lock-token".to_string(),
            Timestamp::from_datetime(Utc::now() + Duration::minutes(1)),
            ProviderType::AzureServiceBus,
        );

        let result = provider.abandon_message(&receipt).await;

        assert!(
            matches!(result, Err(QueueError::InvalidReceipt { .. })),
            "Unknown receipt should return InvalidReceipt; got {:?}",
            result
        );
    }

    /// `dead_letter_message` with an unknown receipt returns `InvalidReceipt` immediately.
    #[tokio::test]
    async fn test_dead_letter_message_unknown_receipt_returns_invalid_receipt() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let receipt = ReceiptHandle::new(
            "nonexistent-lock-token".to_string(),
            Timestamp::from_datetime(Utc::now() + Duration::minutes(1)),
            ProviderType::AzureServiceBus,
        );

        let result = provider.dead_letter_message(&receipt, "test reason").await;

        assert!(
            matches!(result, Err(QueueError::InvalidReceipt { .. })),
            "Unknown receipt should return InvalidReceipt; got {:?}",
            result
        );
    }

    /// `renew_session_lock` should attempt an HTTP call (fails with test creds).
    #[tokio::test]
    async fn test_renew_session_lock_attempts_http_operation() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let result = provider.renew_session_lock().await;

        assert!(
            result.is_err(),
            "Should fail with test credentials; got {:?}",
            result.ok()
        );
        if let Err(QueueError::ProviderError { ref code, .. }) = result {
            assert_ne!(code, "NotImplemented", "Should not be a stub error");
        }
    }

    /// `close_session` always succeeds and clears local state.
    #[tokio::test]
    async fn test_close_session_succeeds() {
        let session_id = SessionId::new("order-session".to_string()).unwrap();
        let queue_name = QueueName::new("orders".to_string()).unwrap();
        let provider = make_test_session_provider(session_id, queue_name);

        let result = provider.close_session().await;

        assert!(result.is_ok(), "close_session should always succeed");
    }

    /// `create_session_client` with an explicit session ID returns immediately without HTTP.
    #[tokio::test]
    async fn test_create_session_client_with_explicit_session_id() {
        let config = make_test_config();
        let provider = AzureServiceBusProvider::new(config).await.unwrap();
        let queue = QueueName::new("orders".to_string()).unwrap();
        let session_id = SessionId::new("explicit-session".to_string()).unwrap();

        let result = provider
            .create_session_client(&queue, Some(session_id.clone()))
            .await;

        assert!(
            result.is_ok(),
            "Should create session provider with explicit ID; got {:?}",
            result.err()
        );
        let session_provider = result.unwrap();
        assert_eq!(session_provider.session_id(), &session_id);
        assert!(
            session_provider.session_expires_at().as_datetime() > Utc::now(),
            "Returned session should not be immediately expired"
        );
    }

    /// `create_session_client` with `None` session ID attempts HTTP to enumerate sessions.
    #[tokio::test]
    async fn test_create_session_client_without_session_id_attempts_http() {
        let config = make_test_config();
        let provider = AzureServiceBusProvider::new(config).await.unwrap();
        let queue = QueueName::new("orders".to_string()).unwrap();

        let result = provider.create_session_client(&queue, None).await;

        // Fails with test credentials but must NOT be a stub NotImplemented error.
        assert!(result.is_err(), "Should fail with test credentials");
        if let Err(QueueError::ProviderError { ref code, .. }) = result {
            assert_ne!(
                code, "NotImplemented",
                "Should attempt HTTP rather than return a stub error"
            );
        }
    }
}

// ============================================================================
// Provider Operation Tests (verify operations attempt HTTP, not stub errors)
// ============================================================================

mod provider_operation_tests {
    use super::*;

    async fn create_test_provider() -> AzureServiceBusProvider {
        let config = AzureServiceBusConfig {
            connection_string: Some(
                "Endpoint=sb://test.servicebus.windows.net/;SharedAccessKeyName=test;SharedAccessKey=dGVzdA=="
                    .to_string(),
            ),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: true,
            session_timeout: Duration::minutes(5),
        };

        AzureServiceBusProvider::new(config)
            .await
            .expect("Should create test provider")
    }

    /// `send_message` attempts an HTTP operation (fails with test credentials).
    #[tokio::test]
    async fn test_send_message_attempts_http() {
        let provider = create_test_provider().await;
        let queue = QueueName::new("test-queue".to_string()).unwrap();
        let message = Message::new(Bytes::from("test"));

        let result = provider.send_message(&queue, &message).await;

        assert!(result.is_err(), "Should fail with test credentials");
    }

    /// `receive_message` attempts an HTTP operation (fails with test credentials).
    #[tokio::test]
    async fn test_receive_message_attempts_http() {
        let provider = create_test_provider().await;
        let queue = QueueName::new("test-queue".to_string()).unwrap();

        let result = provider.receive_message(&queue, Duration::seconds(1)).await;

        assert!(result.is_err(), "Should fail with test credentials");
    }

    /// `receive_messages` rejects batch sizes above 32 (Azure Service Bus limit).
    #[tokio::test]
    async fn test_receive_messages_validates_batch_size() {
        let provider = create_test_provider().await;
        let queue = QueueName::new("test-queue".to_string()).unwrap();

        let result = provider
            .receive_messages(&queue, 50, Duration::seconds(5))
            .await;

        assert!(result.is_err(), "Should reject batch size > 32");
        match result {
            Err(QueueError::BatchTooLarge { size, max_size }) => {
                assert_eq!(size, 50);
                assert_eq!(max_size, 32);
            }
            other => panic!("Expected BatchTooLarge error, got {:?}", other),
        }
    }
}

// ============================================================================
// Security Tests — credential redaction in Debug output
// ============================================================================

mod security_tests {
    use super::*;

    /// `AzureServiceBusConfig` must not expose connection string secrets through
    /// its Debug impl.
    ///
    /// The connection string contains `SharedAccessKey=<base64 secret>`.  The
    /// derived `Debug` impl will print this verbatim unless the type overrides
    /// `fmt::Debug` and redacts it.  This test enforces that requirement.
    #[test]
    fn azure_config_debug_does_not_expose_connection_string_secret() {
        let secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY==";
        let config = AzureServiceBusConfig {
            connection_string: Some(format!(
                "Endpoint=sb://ns.servicebus.windows.net/;\
                 SharedAccessKeyName=RootManageSharedAccessKey;\
                 SharedAccessKey={}",
                secret_key
            )),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: false,
            session_timeout: Duration::minutes(5),
        };

        let debug_output = format!("{:?}", config);

        assert!(
            !debug_output.contains(secret_key),
            "Debug output must not contain the raw SharedAccessKey value. \
             Add a custom Debug impl that redacts the connection_string field. \
             Got: {}",
            debug_output
        );
    }

    /// `AzureServiceBusConfig::connection_string` must be omitted from serialized output.
    ///
    /// The field carries a `SharedAccessKey` secret.  Docs/spec/security.md and
    /// Assertion 17 both require that sensitive fields are masked in Serde output.
    /// The `#[serde(skip_serializing)]` annotation on the field enforces this.
    /// `#[serde(skip)]` is intentionally NOT used so that configs can still be
    /// loaded from files (deserialization is preserved).
    #[test]
    fn azure_config_serde_does_not_serialize_connection_string() {
        let secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY==";
        let config = AzureServiceBusConfig {
            connection_string: Some(format!(
                "Endpoint=sb://ns.servicebus.windows.net/;\
                 SharedAccessKeyName=RootManageSharedAccessKey;\
                 SharedAccessKey={}",
                secret_key
            )),
            namespace: None,
            auth_method: AzureAuthMethod::ConnectionString,
            use_sessions: false,
            session_timeout: Duration::minutes(5),
        };

        let json = serde_json::to_string(&config).expect("serialization must succeed");

        assert!(
            !json.contains(secret_key),
            "Serialized config must not contain the raw SharedAccessKey value. \
             Ensure connection_string has #[serde(skip_serializing)]. Got: {}",
            json
        );
        assert!(
            !json.contains("connection_string"),
            "connection_string key must not appear in serialized output. Got: {}",
            json
        );
    }
}
