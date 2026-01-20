//! Queue provider implementations.
//!
//! This module contains concrete implementations of the `QueueProvider` and
//! `SessionProvider` traits for different queue backends.

pub mod aws;
pub mod azure;
pub mod memory;

pub use aws::{AwsError, AwsSessionProvider, AwsSqsProvider};
pub use azure::{AzureAuthMethod, AzureServiceBusProvider, AzureSessionProvider};
pub use memory::{InMemoryProvider, InMemorySessionProvider};
