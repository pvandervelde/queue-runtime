//! Queue provider implementations.
//!
//! This module contains concrete implementations of the `QueueProvider` and
//! `SessionProvider` traits for different queue backends.

pub mod aws;
pub mod azure;
pub mod memory;
pub mod nats;
pub mod rabbitmq;

pub use aws::{AwsError, AwsSessionProvider, AwsSqsProvider};
pub use azure::{AzureAuthMethod, AzureError, AzureServiceBusProvider, AzureSessionProvider};
pub use memory::{InMemoryProvider, InMemorySessionProvider};
pub use nats::{NatsError, NatsProvider, NatsSessionProvider};
pub use rabbitmq::{RabbitMqError, RabbitMqProvider, RabbitMqSessionProvider};
