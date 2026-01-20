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
}

#[test]
fn test_provider_message_sizes() {
    assert_eq!(
        ProviderType::AzureServiceBus.max_message_size(),
        1024 * 1024
    );
    assert_eq!(ProviderType::AwsSqs.max_message_size(), 256 * 1024);
    assert_eq!(ProviderType::InMemory.max_message_size(), 10 * 1024 * 1024);
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
