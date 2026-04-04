//! Tests for provider types.

use super::*;

#[test]
fn test_provider_capabilities() {
    assert_eq!(
        ProviderType::AzureServiceBus.supports_sessions(),
        SessionSupport::Native
    );
    assert_eq!(
        ProviderType::AwsSqs.supports_sessions(),
        SessionSupport::Emulated
    );
    assert!(ProviderType::InMemory.supports_batching());
    assert_eq!(
        ProviderType::RabbitMq.supports_sessions(),
        SessionSupport::Emulated
    );
    assert_eq!(
        ProviderType::Nats.supports_sessions(),
        SessionSupport::Emulated
    );
    assert!(ProviderType::RabbitMq.supports_batching());
    assert!(ProviderType::Nats.supports_batching());
}

#[test]
fn test_provider_message_sizes() {
    assert_eq!(
        ProviderType::AzureServiceBus.max_message_size(),
        1024 * 1024
    );
    assert_eq!(ProviderType::AwsSqs.max_message_size(), 256 * 1024);
    assert_eq!(ProviderType::InMemory.max_message_size(), 10 * 1024 * 1024);
    assert_eq!(ProviderType::RabbitMq.max_message_size(), 128 * 1024 * 1024);
    assert_eq!(ProviderType::Nats.max_message_size(), 1024 * 1024);
}

#[test]
fn test_queue_config_defaults() {
    let config = QueueConfig::default();
    assert_eq!(config.max_retry_attempts, 3);
    assert_eq!(config.default_timeout, Duration::seconds(30));
    assert!(config.enable_dead_letter);
}

#[test]
fn test_in_memory_config_defaults() {
    let config = InMemoryConfig::default();
    assert_eq!(config.max_queue_size, 10000);
    assert!(!config.enable_persistence);
}

#[test]
fn test_provider_config_rabbitmq_variant() {
    use crate::providers::rabbitmq::RabbitMqConfig;
    let config = ProviderConfig::RabbitMq(RabbitMqConfig::default());
    match config {
        ProviderConfig::RabbitMq(c) => {
            assert_eq!(c.url, "amqp://guest:guest@localhost:5672");
        }
        _ => panic!("Expected RabbitMq variant"),
    }
}

#[test]
fn test_provider_config_nats_variant() {
    use crate::providers::nats::NatsConfig;
    let config = ProviderConfig::Nats(NatsConfig::default());
    match config {
        ProviderConfig::Nats(c) => {
            assert_eq!(c.url, "nats://localhost:4222");
        }
        _ => panic!("Expected Nats variant"),
    }
}
