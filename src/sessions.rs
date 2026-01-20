//! Session management for ordered message processing.
//!
//! This module provides a generic framework for session key generation that enables
//! ordered message processing for any domain. Session keys group related messages
//! to ensure they are processed in FIFO order.
//!
//! # Design Philosophy
//!
//! This module is intentionally **domain-agnostic**. It provides the infrastructure
//! for session-based ordering without assuming any specific message structure or
//! business domain (GitHub events, e-commerce orders, IoT telemetry, etc.).
//!
//! # Core Concepts
//!
//! - **SessionKeyGenerator**: Trait for extracting session keys from messages
//! - **Session Keys**: Strings that group related messages for ordered processing
//! - **Message Metadata**: Messages provide metadata via the `SessionKeyExtractor` trait
//!
//! # Usage Pattern
//!
//! 1. Implement `SessionKeyExtractor` for your message type
//! 2. Implement `SessionKeyGenerator` for your domain-specific strategy
//! 3. Use the generator to produce session IDs when sending messages to queues
//!
//! # Example
//!
//! ```rust
//! use queue_runtime::sessions::{SessionKeyGenerator, SessionKeyExtractor};
//! use queue_runtime::message::SessionId;
//! use std::collections::HashMap;
//!
//! // Your domain message type
//! struct OrderEvent {
//!     order_id: String,
//!     customer_id: String,
//! }
//!
//! // Implement metadata extraction
//! impl SessionKeyExtractor for OrderEvent {
//!     fn get_metadata(&self, key: &str) -> Option<String> {
//!         match key {
//!             "order_id" => Some(self.order_id.clone()),
//!             "customer_id" => Some(self.customer_id.clone()),
//!             _ => None,
//!         }
//!     }
//! }
//!
//! // Implement your session strategy
//! struct OrderSessionStrategy;
//!
//! impl SessionKeyGenerator for OrderSessionStrategy {
//!     fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
//!         extractor.get_metadata("order_id")
//!             .and_then(|id| SessionId::new(format!("order-{}", id)).ok())
//!     }
//! }
//! ```

use crate::error::ValidationError;
use crate::message::{SessionId, Timestamp};
use crate::QueueError;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::Instant;

#[cfg(test)]
#[path = "sessions_tests.rs"]
mod tests;

// ============================================================================
// Session Key Extractor Trait
// ============================================================================

/// Trait for extracting metadata from messages for session key generation.
///
/// This trait provides a completely generic interface for messages to expose
/// metadata that can be used to generate session keys. It makes no assumptions
/// about the message structure or domain.
///
/// # Design
///
/// The trait uses a key-value interface where messages expose named metadata
/// fields. Session key generators query for the metadata they need.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::SessionKeyExtractor;
///
/// struct MyMessage {
///     user_id: String,
///     resource_id: String,
/// }
///
/// impl SessionKeyExtractor for MyMessage {
///     fn get_metadata(&self, key: &str) -> Option<String> {
///         match key {
///             "user_id" => Some(self.user_id.clone()),
///             "resource_id" => Some(self.resource_id.clone()),
///             _ => None,
///         }
///     }
///
///     fn list_metadata_keys(&self) -> Vec<String> {
///         vec!["user_id".to_string(), "resource_id".to_string()]
///     }
/// }
/// ```
pub trait SessionKeyExtractor {
    /// Get a metadata value by key.
    ///
    /// Returns `None` if the key doesn't exist or has no value for this message.
    ///
    /// # Arguments
    ///
    /// * `key` - The metadata key to retrieve
    ///
    /// # Returns
    ///
    /// Optional string value for the requested key
    fn get_metadata(&self, key: &str) -> Option<String>;

    /// List all available metadata keys for this message.
    ///
    /// This is useful for debugging and introspection. Default implementation
    /// returns an empty list.
    ///
    /// # Returns
    ///
    /// Vector of available metadata key names
    fn list_metadata_keys(&self) -> Vec<String> {
        Vec::new()
    }

    /// Get all metadata as a map (optional, for bulk operations).
    ///
    /// Default implementation iterates over `list_metadata_keys()` and calls
    /// `get_metadata()` for each key.
    ///
    /// # Returns
    ///
    /// HashMap of all available metadata
    fn get_all_metadata(&self) -> HashMap<String, String> {
        self.list_metadata_keys()
            .into_iter()
            .filter_map(|key| self.get_metadata(&key).map(|value| (key, value)))
            .collect()
    }
}

// ============================================================================
// Session Key Generator Trait
// ============================================================================

/// Strategy trait for generating session keys from messages.
///
/// Implementations define how messages are grouped for ordered processing.
/// The generator extracts relevant metadata from messages and produces
/// session keys that group related messages together.
///
/// # Design Principles
///
/// - **Domain-Agnostic**: Works with any message structure via `SessionKeyExtractor`
/// - **Strategy Pattern**: Different strategies provide different ordering semantics
/// - **Composable**: Strategies can be combined or chained
/// - **Optional Ordering**: Returning `None` allows concurrent processing
///
/// # Common Patterns
///
/// - **Entity-based**: Group by entity ID (order-123, user-456)
/// - **Hierarchical**: Group by parent/child relationships
/// - **Temporal**: Group by time windows
/// - **Custom**: Domain-specific grouping logic
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::{SessionKeyGenerator, SessionKeyExtractor};
/// use queue_runtime::message::SessionId;
///
/// struct ResourceIdStrategy;
///
/// impl SessionKeyGenerator for ResourceIdStrategy {
///     fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
///         extractor.get_metadata("resource_id")
///             .and_then(|id| SessionId::new(format!("resource-{}", id)).ok())
///     }
/// }
/// ```
pub trait SessionKeyGenerator: Send + Sync {
    /// Generate a session key for the given message.
    ///
    /// Returns `None` if the message should not be session-ordered, allowing
    /// it to be processed concurrently without ordering constraints.
    ///
    /// # Arguments
    ///
    /// * `extractor` - Message implementing SessionKeyExtractor trait
    ///
    /// # Returns
    ///
    /// Optional session ID for grouping related messages
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId>;
}

// ============================================================================
// Composite Key Strategy
// ============================================================================

/// Generates session keys by composing multiple metadata fields.
///
/// This strategy builds session keys from a list of metadata fields in order,
/// joining them with a separator. This is useful for creating hierarchical
/// or compound session keys.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::CompositeKeyStrategy;
///
/// // Create session keys like "tenant-123-resource-456"
/// let strategy = CompositeKeyStrategy::new(vec![
///     "tenant_id".to_string(),
///     "resource_id".to_string(),
/// ], "-");
/// ```
pub struct CompositeKeyStrategy {
    fields: Vec<String>,
    separator: String,
}

impl CompositeKeyStrategy {
    /// Create a new composite key strategy.
    ///
    /// # Arguments
    ///
    /// * `fields` - Ordered list of metadata field names to compose
    /// * `separator` - String to join field values with
    ///
    /// # Example
    ///
    /// ```rust
    /// use queue_runtime::sessions::CompositeKeyStrategy;
    ///
    /// let strategy = CompositeKeyStrategy::new(
    ///     vec!["region".to_string(), "customer_id".to_string()],
    ///     "-"
    /// );
    /// ```
    pub fn new(fields: Vec<String>, separator: &str) -> Self {
        Self {
            fields,
            separator: separator.to_string(),
        }
    }
}

impl SessionKeyGenerator for CompositeKeyStrategy {
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        // Return None if no fields specified
        if self.fields.is_empty() {
            return None;
        }

        // Collect all field values
        let values: Vec<String> = self
            .fields
            .iter()
            .filter_map(|field| extractor.get_metadata(field))
            .collect();

        // Return None if any required field is missing
        if values.len() != self.fields.len() {
            return None;
        }

        // Join values with separator
        let key = values.join(&self.separator);

        // Create session ID
        SessionId::new(key).ok()
    }
}

// ============================================================================
// Single Field Strategy
// ============================================================================

/// Generates session keys from a single metadata field.
///
/// This is the simplest strategy: extract one field and use it as the session key.
/// Optionally adds a prefix for namespacing.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::SingleFieldStrategy;
///
/// // Create session keys from "user_id" like "user-12345"
/// let strategy = SingleFieldStrategy::new("user_id", Some("user"));
/// ```
pub struct SingleFieldStrategy {
    field_name: String,
    prefix: Option<String>,
}

impl SingleFieldStrategy {
    /// Create a new single field strategy.
    ///
    /// # Arguments
    ///
    /// * `field_name` - The metadata field to use for the session key
    /// * `prefix` - Optional prefix to add before the field value
    ///
    /// # Example
    ///
    /// ```rust
    /// use queue_runtime::sessions::SingleFieldStrategy;
    ///
    /// let strategy = SingleFieldStrategy::new("order_id", Some("order"));
    /// // Produces keys like "order-123"
    /// ```
    pub fn new(field_name: &str, prefix: Option<&str>) -> Self {
        Self {
            field_name: field_name.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        }
    }
}

impl SessionKeyGenerator for SingleFieldStrategy {
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        // Get the field value
        let value = extractor.get_metadata(&self.field_name)?;

        // Build key with optional prefix
        let key = if let Some(ref prefix) = self.prefix {
            format!("{}-{}", prefix, value)
        } else {
            value
        };

        // Create session ID
        SessionId::new(key).ok()
    }
}

// ============================================================================
// No Ordering Strategy
// ============================================================================

/// Strategy that disables session-based ordering.
///
/// Always returns `None`, allowing concurrent message processing without
/// ordering guarantees. Use for stateless operations that don't require
/// message ordering.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::NoOrderingStrategy;
///
/// let strategy = NoOrderingStrategy;
/// // All messages can be processed concurrently
/// ```
pub struct NoOrderingStrategy;

impl SessionKeyGenerator for NoOrderingStrategy {
    fn generate_key(&self, _extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        None
    }
}

// ============================================================================
// Fallback Strategy
// ============================================================================

/// Strategy that tries multiple generators in order, using the first success.
///
/// This implements a fallback chain: try the primary strategy first, and if it
/// returns `None`, try the next strategy, and so on. Useful for providing
/// fine-grained ordering when possible, with coarser fallbacks.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::{FallbackStrategy, SingleFieldStrategy, CompositeKeyStrategy};
///
/// // Try specific entity ID first, fall back to tenant-level ordering
/// let primary = SingleFieldStrategy::new("entity_id", Some("entity"));
/// let fallback = SingleFieldStrategy::new("tenant_id", Some("tenant"));
///
/// let strategy = FallbackStrategy::new(vec![
///     Box::new(primary),
///     Box::new(fallback),
/// ]);
/// ```
pub struct FallbackStrategy {
    strategies: Vec<Box<dyn SessionKeyGenerator>>,
}

impl FallbackStrategy {
    /// Create a new fallback strategy with ordered generators.
    ///
    /// # Arguments
    ///
    /// * `strategies` - Ordered list of generators to try
    ///
    /// # Example
    ///
    /// ```rust
    /// use queue_runtime::sessions::{FallbackStrategy, SingleFieldStrategy, NoOrderingStrategy};
    ///
    /// let strategy = FallbackStrategy::new(vec![
    ///     Box::new(SingleFieldStrategy::new("user_id", Some("user"))),
    ///     Box::new(NoOrderingStrategy), // Ultimate fallback: no ordering
    /// ]);
    /// ```
    pub fn new(strategies: Vec<Box<dyn SessionKeyGenerator>>) -> Self {
        Self { strategies }
    }
}

impl SessionKeyGenerator for FallbackStrategy {
    fn generate_key(&self, extractor: &dyn SessionKeyExtractor) -> Option<SessionId> {
        // Try each strategy in order until one succeeds
        for strategy in &self.strategies {
            if let Some(session_id) = strategy.generate_key(extractor) {
                return Some(session_id);
            }
        }

        // All strategies failed
        None
    }
}

// ============================================================================
// Session Lock Management
// ============================================================================

/// Represents a lock on a session for exclusive message processing.
///
/// A session lock ensures that only one consumer can process messages from
/// a session at a time, maintaining FIFO ordering guarantees. Locks have
/// an expiration time and can be renewed to extend processing time.
///
/// # Design
///
/// - **Expiration**: Locks automatically expire after a timeout period
/// - **Renewal**: Locks can be renewed before expiration to extend processing
/// - **Owner Tracking**: Each lock tracks which consumer owns it
/// - **Timeout Handling**: Expired locks can be acquired by other consumers
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::SessionLock;
/// use queue_runtime::message::SessionId;
/// use std::time::Duration;
///
/// # tokio_test::block_on(async {
/// let session_id = SessionId::new("user-123".to_string()).unwrap();
/// let lock = SessionLock::new(session_id.clone(), "consumer-1".to_string(), Duration::from_secs(30));
///
/// assert!(!lock.is_expired());
/// assert_eq!(lock.owner(), "consumer-1");
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct SessionLock {
    session_id: SessionId,
    owner: String,
    acquired_at: Instant,
    expires_at: Instant,
    lock_duration: Duration,
}

impl SessionLock {
    /// Create a new session lock.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session being locked
    /// * `owner` - Identifier of the consumer owning this lock
    /// * `lock_duration` - How long the lock is valid before expiration
    ///
    /// # Returns
    ///
    /// A new session lock that expires after `lock_duration`
    pub fn new(session_id: SessionId, owner: String, lock_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            owner,
            acquired_at: now,
            expires_at: now + lock_duration,
            lock_duration,
        }
    }

    /// Get the session ID this lock is for.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the owner of this lock.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get when this lock was acquired.
    pub fn acquired_at(&self) -> Instant {
        self.acquired_at
    }

    /// Get when this lock expires.
    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    /// Get the configured lock duration.
    pub fn lock_duration(&self) -> Duration {
        self.lock_duration
    }

    /// Check if this lock has expired.
    ///
    /// # Returns
    ///
    /// `true` if the current time is past the expiration time
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get the remaining time before this lock expires.
    ///
    /// # Returns
    ///
    /// Duration until expiration, or zero if already expired
    pub fn time_remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            self.expires_at - now
        }
    }

    /// Renew this lock, extending its expiration time.
    ///
    /// # Arguments
    ///
    /// * `extension` - How long to extend the lock by
    ///
    /// # Returns
    ///
    /// A new lock with updated expiration time
    pub fn renew(&self, extension: Duration) -> Self {
        Self {
            session_id: self.session_id.clone(),
            owner: self.owner.clone(),
            acquired_at: self.acquired_at,
            expires_at: Instant::now() + extension,
            lock_duration: extension,
        }
    }
}

/// Manages session locks for concurrent message processing.
///
/// The lock manager coordinates exclusive access to sessions, ensuring that
/// only one consumer processes messages from a session at a time. It handles
/// lock acquisition, renewal, release, and automatic expiration cleanup.
///
/// # Thread Safety
///
/// This type is thread-safe and can be shared across async tasks using `Arc`.
///
/// # Example
///
/// ```rust
/// use queue_runtime::sessions::SessionLockManager;
/// use queue_runtime::message::SessionId;
/// use std::time::Duration;
///
/// # tokio_test::block_on(async {
/// let manager = SessionLockManager::new(Duration::from_secs(30));
/// let session_id = SessionId::new("order-456".to_string()).unwrap();
///
/// // Acquire lock
/// let lock = manager.acquire_lock(session_id.clone(), "consumer-1".to_string()).await?;
/// assert_eq!(lock.owner(), "consumer-1");
///
/// // Try to acquire same session with different consumer - should fail
/// let result = manager.try_acquire_lock(session_id.clone(), "consumer-2".to_string()).await;
/// assert!(result.is_err());
///
/// // Release lock
/// manager.release_lock(&session_id, "consumer-1").await?;
/// # Ok::<(), queue_runtime::QueueError>(())
/// # });
/// ```
pub struct SessionLockManager {
    locks: Arc<RwLock<HashMap<SessionId, SessionLock>>>,
    default_lock_duration: Duration,
}

impl SessionLockManager {
    /// Create a new session lock manager.
    ///
    /// # Arguments
    ///
    /// * `default_lock_duration` - Default duration for session locks
    ///
    /// # Example
    ///
    /// ```rust
    /// use queue_runtime::sessions::SessionLockManager;
    /// use std::time::Duration;
    ///
    /// let manager = SessionLockManager::new(Duration::from_secs(60));
    /// ```
    pub fn new(default_lock_duration: Duration) -> Self {
        Self {
            locks: Arc::new(RwLock::new(HashMap::new())),
            default_lock_duration,
        }
    }

    /// Try to acquire a lock on a session (non-blocking).
    ///
    /// Returns immediately with an error if the session is already locked
    /// by another consumer.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to lock
    /// * `owner` - Identifier of the consumer requesting the lock
    ///
    /// # Returns
    ///
    /// The acquired lock if successful, or an error if the session is locked
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionLocked` if the session is already locked
    /// by another consumer and the lock has not expired.
    pub async fn try_acquire_lock(
        &self,
        session_id: SessionId,
        owner: String,
    ) -> Result<SessionLock, QueueError> {
        let mut locks = self.locks.write().await;

        // Check if session is already locked
        if let Some(existing_lock) = locks.get(&session_id) {
            if !existing_lock.is_expired() {
                // Lock is still valid and owned by someone else
                if existing_lock.owner() != owner {
                    return Err(QueueError::SessionLocked {
                        session_id: session_id.to_string(),
                        locked_until: Timestamp::now(),
                    });
                }
                // Same owner - return existing lock
                return Ok(existing_lock.clone());
            }
            // Lock expired - remove it and acquire new lock below
        }

        // Acquire new lock
        let lock = SessionLock::new(session_id.clone(), owner, self.default_lock_duration);
        locks.insert(session_id, lock.clone());

        Ok(lock)
    }

    /// Acquire a lock on a session (blocking with timeout).
    ///
    /// Waits for the lock to become available if it's currently held by
    /// another consumer, up to the specified timeout.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to lock
    /// * `owner` - Identifier of the consumer requesting the lock
    ///
    /// # Returns
    ///
    /// The acquired lock if successful within the timeout period
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionLocked` if unable to acquire the lock
    /// within the timeout period.
    pub async fn acquire_lock(
        &self,
        session_id: SessionId,
        owner: String,
    ) -> Result<SessionLock, QueueError> {
        // For now, just try once - future enhancement could add retry logic
        self.try_acquire_lock(session_id, owner).await
    }

    /// Renew an existing session lock.
    ///
    /// Extends the lock's expiration time, allowing the consumer to continue
    /// processing messages from the session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session whose lock to renew
    /// * `owner` - Identifier of the consumer owning the lock
    /// * `extension` - How long to extend the lock by (if None, uses default duration)
    ///
    /// # Returns
    ///
    /// The renewed lock with updated expiration time
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionNotFound` if no lock exists for the session.
    /// Returns `QueueError::SessionLocked` if the lock is owned by a different consumer.
    pub async fn renew_lock(
        &self,
        session_id: &SessionId,
        owner: &str,
        extension: Option<Duration>,
    ) -> Result<SessionLock, QueueError> {
        let mut locks = self.locks.write().await;

        let existing_lock = locks
            .get(session_id)
            .ok_or_else(|| QueueError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        // Verify ownership
        if existing_lock.owner() != owner {
            return Err(QueueError::SessionLocked {
                session_id: session_id.to_string(),
                locked_until: Timestamp::now(),
            });
        }

        // Renew the lock
        let renewed_lock = existing_lock.renew(extension.unwrap_or(self.default_lock_duration));
        locks.insert(session_id.clone(), renewed_lock.clone());

        Ok(renewed_lock)
    }

    /// Release a session lock.
    ///
    /// Removes the lock, allowing other consumers to acquire it.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session whose lock to release
    /// * `owner` - Identifier of the consumer releasing the lock
    ///
    /// # Returns
    ///
    /// `Ok(())` if the lock was successfully released
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionNotFound` if no lock exists for the session.
    /// Returns `QueueError::SessionLocked` if the lock is owned by a different consumer.
    pub async fn release_lock(
        &self,
        session_id: &SessionId,
        owner: &str,
    ) -> Result<(), QueueError> {
        let mut locks = self.locks.write().await;

        let existing_lock = locks
            .get(session_id)
            .ok_or_else(|| QueueError::SessionNotFound {
                session_id: session_id.to_string(),
            })?;

        // Verify ownership
        if existing_lock.owner() != owner {
            return Err(QueueError::SessionLocked {
                session_id: session_id.to_string(),
                locked_until: Timestamp::now(),
            });
        }

        // Remove the lock
        locks.remove(session_id);

        Ok(())
    }

    /// Check if a session is currently locked.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to check
    ///
    /// # Returns
    ///
    /// `true` if the session has a valid (non-expired) lock
    pub async fn is_locked(&self, session_id: &SessionId) -> bool {
        let locks = self.locks.read().await;
        locks
            .get(session_id)
            .map(|lock| !lock.is_expired())
            .unwrap_or(false)
    }

    /// Get information about a session lock.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to query
    ///
    /// # Returns
    ///
    /// The lock information if it exists and is not expired
    pub async fn get_lock(&self, session_id: &SessionId) -> Option<SessionLock> {
        let locks = self.locks.read().await;
        locks
            .get(session_id)
            .filter(|lock| !lock.is_expired())
            .cloned()
    }

    /// Clean up expired locks.
    ///
    /// Removes all locks that have passed their expiration time.
    ///
    /// # Returns
    ///
    /// The number of expired locks that were removed
    pub async fn cleanup_expired_locks(&self) -> usize {
        let mut locks = self.locks.write().await;

        let expired: Vec<SessionId> = locks
            .iter()
            .filter(|(_, lock)| lock.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for session_id in expired {
            locks.remove(&session_id);
        }

        count
    }

    /// Get the number of currently held locks (including expired).
    ///
    /// # Returns
    ///
    /// Total number of locks in the manager
    pub async fn lock_count(&self) -> usize {
        let locks = self.locks.read().await;
        locks.len()
    }

    /// Get the number of active (non-expired) locks.
    ///
    /// # Returns
    ///
    /// Number of locks that have not expired
    pub async fn active_lock_count(&self) -> usize {
        let locks = self.locks.read().await;
        locks.values().filter(|lock| !lock.is_expired()).count()
    }
}

// ============================================================================
// Session Affinity Tracking
// ============================================================================

/// Mapping of a session to its assigned consumer.
///
/// Session affinity ensures that all messages for a given session are processed
/// by the same consumer, maintaining ordering and state consistency.
///
/// # Examples
///
/// ```
/// use queue_runtime::sessions::SessionAffinity;
/// use queue_runtime::message::SessionId;
/// use std::time::{SystemTime, Duration};
///
/// # tokio_test::block_on(async {
/// let session_id = SessionId::new("order-789".to_string()).unwrap();
/// let affinity = SessionAffinity::new(
///     session_id.clone(),
///     "worker-3".to_string(),
///     Duration::from_secs(300)
/// );
///
/// assert_eq!(affinity.session_id(), &session_id);
/// assert_eq!(affinity.consumer_id(), "worker-3");
/// assert!(!affinity.is_expired());
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct SessionAffinity {
    session_id: SessionId,
    consumer_id: String,
    assigned_at: Instant,
    expires_at: Instant,
    affinity_duration: Duration,
    last_activity: Instant,
}

impl SessionAffinity {
    /// Create a new session affinity mapping.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session being tracked
    /// * `consumer_id` - Identifier of the consumer assigned to this session
    /// * `affinity_duration` - How long the affinity is valid
    ///
    /// # Returns
    ///
    /// A new `SessionAffinity` instance
    pub fn new(session_id: SessionId, consumer_id: String, affinity_duration: Duration) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            consumer_id,
            assigned_at: now,
            expires_at: now + affinity_duration,
            affinity_duration,
            last_activity: now,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the consumer ID.
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    /// Get the affinity duration.
    pub fn affinity_duration(&self) -> Duration {
        self.affinity_duration
    }

    /// Get when the affinity was assigned.
    pub fn assigned_at(&self) -> Instant {
        self.assigned_at
    }

    /// Check if the affinity has expired.
    ///
    /// # Returns
    ///
    /// `true` if the affinity has expired, `false` otherwise
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Get the remaining time before expiration.
    ///
    /// # Returns
    ///
    /// Duration remaining, or zero if expired
    pub fn time_remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            self.expires_at - now
        }
    }

    /// Update the last activity time.
    ///
    /// This is called when a message is processed for the session,
    /// keeping the affinity fresh.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Get the time since last activity.
    pub fn idle_time(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }

    /// Extend the affinity expiration.
    ///
    /// # Arguments
    ///
    /// * `additional_duration` - Additional time to add to expiration
    ///
    /// # Returns
    ///
    /// A new `SessionAffinity` with extended expiration
    pub fn extend(&self, additional_duration: Duration) -> Self {
        let mut extended = self.clone();
        extended.expires_at = Instant::now() + additional_duration;
        extended
    }
}

/// Tracks session-to-consumer affinity mappings for ordered processing.
///
/// The affinity tracker ensures that all messages for a given session are
/// routed to the same consumer, maintaining message ordering and processing
/// consistency within sessions.
///
/// # Thread Safety
///
/// This type uses `Arc<RwLock<>>` internally and can be safely shared across
/// threads and tasks.
///
/// # Examples
///
/// ```
/// use queue_runtime::sessions::SessionAffinityTracker;
/// use queue_runtime::message::SessionId;
/// use std::time::Duration;
///
/// # tokio_test::block_on(async {
/// let tracker = SessionAffinityTracker::new(Duration::from_secs(600));
/// let session_id = SessionId::new("session-123".to_string()).unwrap();
///
/// // Assign session to consumer
/// let affinity = tracker.assign_session(session_id.clone(), "worker-1".to_string()).await.unwrap();
/// assert_eq!(affinity.consumer_id(), "worker-1");
///
/// // Query affinity
/// let consumer = tracker.get_consumer(&session_id).await;
/// assert_eq!(consumer, Some("worker-1".to_string()));
/// # });
/// ```
#[derive(Clone)]
pub struct SessionAffinityTracker {
    affinities: Arc<RwLock<HashMap<SessionId, SessionAffinity>>>,
    default_affinity_duration: Duration,
}

impl SessionAffinityTracker {
    /// Create a new session affinity tracker.
    ///
    /// # Arguments
    ///
    /// * `default_affinity_duration` - Default duration for affinity mappings
    ///
    /// # Returns
    ///
    /// A new `SessionAffinityTracker` instance
    pub fn new(default_affinity_duration: Duration) -> Self {
        Self {
            affinities: Arc::new(RwLock::new(HashMap::new())),
            default_affinity_duration,
        }
    }

    /// Assign a session to a consumer.
    ///
    /// If the session is already assigned and not expired, returns an error.
    /// If the session affinity has expired, reassigns to the new consumer.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to assign
    /// * `consumer_id` - The consumer to assign the session to
    ///
    /// # Returns
    ///
    /// The created affinity mapping on success, or an error if the session
    /// is already assigned to a different consumer.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionLocked` if the session is already assigned
    /// to a different consumer and the affinity has not expired.
    pub async fn assign_session(
        &self,
        session_id: SessionId,
        consumer_id: String,
    ) -> Result<SessionAffinity, QueueError> {
        let mut affinities = self.affinities.write().await;

        // Check if session is already assigned
        if let Some(existing) = affinities.get(&session_id) {
            if !existing.is_expired() {
                if existing.consumer_id() != consumer_id {
                    // Session assigned to different consumer
                    return Err(QueueError::SessionLocked {
                        session_id: session_id.to_string(),
                        locked_until: Timestamp::now(), // Approximate
                    });
                }
                // Same consumer - return existing affinity
                return Ok(existing.clone());
            }
            // Expired - will reassign below
        }

        // Create new affinity
        let affinity = SessionAffinity::new(
            session_id.clone(),
            consumer_id,
            self.default_affinity_duration,
        );

        affinities.insert(session_id, affinity.clone());
        Ok(affinity)
    }

    /// Get the consumer assigned to a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to query
    ///
    /// # Returns
    ///
    /// The consumer ID if the session has an active affinity, `None` otherwise
    pub async fn get_consumer(&self, session_id: &SessionId) -> Option<String> {
        let affinities = self.affinities.read().await;
        affinities
            .get(session_id)
            .filter(|affinity| !affinity.is_expired())
            .map(|affinity| affinity.consumer_id().to_string())
    }

    /// Get the full affinity information for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to query
    ///
    /// # Returns
    ///
    /// The affinity information if the session has an active affinity
    pub async fn get_affinity(&self, session_id: &SessionId) -> Option<SessionAffinity> {
        let affinities = self.affinities.read().await;
        affinities
            .get(session_id)
            .filter(|affinity| !affinity.is_expired())
            .cloned()
    }

    /// Check if a session has an active affinity.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to check
    ///
    /// # Returns
    ///
    /// `true` if the session has an active affinity
    pub async fn has_affinity(&self, session_id: &SessionId) -> bool {
        self.get_consumer(session_id).await.is_some()
    }

    /// Update the last activity time for a session.
    ///
    /// This should be called when a message is processed for the session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to update
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful, error if session not found or expired
    pub async fn touch_session(&self, session_id: &SessionId) -> Result<(), QueueError> {
        let mut affinities = self.affinities.write().await;

        if let Some(affinity) = affinities.get_mut(session_id) {
            if !affinity.is_expired() {
                affinity.touch();
                return Ok(());
            }
        }

        Err(QueueError::SessionNotFound {
            session_id: session_id.to_string(),
        })
    }

    /// Release a session affinity.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to release
    /// * `consumer_id` - The consumer releasing the session (for validation)
    ///
    /// # Returns
    ///
    /// `Ok(())` if successful
    ///
    /// # Errors
    ///
    /// Returns error if the consumer doesn't own the session
    pub async fn release_session(
        &self,
        session_id: &SessionId,
        consumer_id: &str,
    ) -> Result<(), QueueError> {
        let mut affinities = self.affinities.write().await;

        if let Some(affinity) = affinities.get(session_id) {
            if affinity.consumer_id() != consumer_id {
                return Err(QueueError::ValidationError(
                    ValidationError::InvalidFormat {
                        field: "consumer_id".to_string(),
                        message: format!(
                            "Session owned by {}, cannot release from {}",
                            affinity.consumer_id(),
                            consumer_id
                        ),
                    },
                ));
            }
        }

        affinities.remove(session_id);
        Ok(())
    }

    /// Extend the affinity duration for a session.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to extend
    /// * `consumer_id` - The consumer requesting the extension (for validation)
    /// * `additional_duration` - Additional time to add
    ///
    /// # Returns
    ///
    /// The updated affinity on success
    ///
    /// # Errors
    ///
    /// Returns error if consumer doesn't own the session or session not found
    pub async fn extend_affinity(
        &self,
        session_id: &SessionId,
        consumer_id: &str,
        additional_duration: Duration,
    ) -> Result<SessionAffinity, QueueError> {
        let mut affinities = self.affinities.write().await;

        if let Some(affinity) = affinities.get(session_id) {
            if affinity.consumer_id() != consumer_id {
                return Err(QueueError::ValidationError(
                    ValidationError::InvalidFormat {
                        field: "consumer_id".to_string(),
                        message: format!(
                            "Session owned by {}, cannot extend from {}",
                            affinity.consumer_id(),
                            consumer_id
                        ),
                    },
                ));
            }

            let extended = affinity.extend(additional_duration);
            affinities.insert(session_id.clone(), extended.clone());
            return Ok(extended);
        }

        Err(QueueError::SessionNotFound {
            session_id: session_id.to_string(),
        })
    }

    /// Get all sessions assigned to a consumer.
    ///
    /// # Arguments
    ///
    /// * `consumer_id` - The consumer to query
    ///
    /// # Returns
    ///
    /// List of session IDs assigned to the consumer
    pub async fn get_consumer_sessions(&self, consumer_id: &str) -> Vec<SessionId> {
        let affinities = self.affinities.read().await;
        affinities
            .iter()
            .filter(|(_, affinity)| !affinity.is_expired() && affinity.consumer_id() == consumer_id)
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }

    /// Clean up expired affinities.
    ///
    /// # Returns
    ///
    /// Number of affinities removed
    pub async fn cleanup_expired(&self) -> usize {
        let mut affinities = self.affinities.write().await;

        let expired: Vec<SessionId> = affinities
            .iter()
            .filter(|(_, affinity)| affinity.is_expired())
            .map(|(session_id, _)| session_id.clone())
            .collect();

        let count = expired.len();
        for session_id in expired {
            affinities.remove(&session_id);
        }

        count
    }

    /// Get the total number of affinity mappings (including expired).
    pub async fn affinity_count(&self) -> usize {
        let affinities = self.affinities.read().await;
        affinities.len()
    }

    /// Get the number of active (non-expired) affinities.
    pub async fn active_affinity_count(&self) -> usize {
        let affinities = self.affinities.read().await;
        affinities
            .values()
            .filter(|affinity| !affinity.is_expired())
            .count()
    }
}

// ============================================================================
// Session Lifecycle Management
// ============================================================================

/// Information about an active session's lifecycle state.
///
/// Tracks activity metrics used for determining when to close sessions
/// based on duration limits, message counts, or inactivity timeouts.
///
/// # Examples
///
/// ```
/// use queue_runtime::{SessionInfo, SessionId};
/// use std::time::Duration;
///
/// let session_id = SessionId::new("order-123".to_string()).unwrap();
/// let mut info = SessionInfo::new(session_id.clone(), "worker-1".to_string());
///
/// // Record message processing
/// info.increment_message_count();
/// info.increment_message_count();
///
/// // Check duration
/// assert!(info.duration() < Duration::from_secs(1));
///
/// // Check message count
/// assert_eq!(info.message_count(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct SessionInfo {
    session_id: SessionId,
    consumer_id: String,
    started_at: Instant,
    last_activity: Instant,
    message_count: u32,
}

impl SessionInfo {
    /// Create a new session info tracker.
    pub fn new(session_id: SessionId, consumer_id: String) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            consumer_id,
            started_at: now,
            last_activity: now,
            message_count: 0,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the consumer ID.
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    /// Get the time when this session was started.
    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    /// Get the time of last activity in this session.
    pub fn last_activity(&self) -> Instant {
        self.last_activity
    }

    /// Get the number of messages processed in this session.
    pub fn message_count(&self) -> u32 {
        self.message_count
    }

    /// Calculate how long this session has been active.
    pub fn duration(&self) -> Duration {
        Instant::now().saturating_duration_since(self.started_at)
    }

    /// Calculate how long since last activity.
    pub fn idle_time(&self) -> Duration {
        Instant::now().saturating_duration_since(self.last_activity)
    }

    /// Record message processing activity.
    pub fn increment_message_count(&mut self) {
        self.message_count += 1;
        self.last_activity = Instant::now();
    }

    /// Update last activity timestamp without incrementing message count.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Configuration for session lifecycle management.
///
/// Defines limits and timeouts that determine when sessions should be
/// automatically closed to prevent resource exhaustion and ensure fair
/// processing distribution.
///
/// # Examples
///
/// ```
/// use queue_runtime::SessionLifecycleConfig;
/// use std::time::Duration;
///
/// let config = SessionLifecycleConfig {
///     max_session_duration: Duration::from_secs(2 * 60 * 60), // 2 hours
///     max_messages_per_session: 1000,
///     session_timeout: Duration::from_secs(30 * 60), // 30 minutes
/// };
///
/// // Check if defaults are reasonable
/// assert_eq!(config.max_session_duration, Duration::from_secs(7200));
/// ```
#[derive(Debug, Clone)]
pub struct SessionLifecycleConfig {
    /// Maximum duration a session can be active before forced closure.
    pub max_session_duration: Duration,

    /// Maximum number of messages processed per session before forced closure.
    pub max_messages_per_session: u32,

    /// Maximum idle time before session is considered timed out.
    pub session_timeout: Duration,
}

impl Default for SessionLifecycleConfig {
    fn default() -> Self {
        Self {
            max_session_duration: Duration::from_secs(2 * 60 * 60), // 2 hours
            max_messages_per_session: 1000,
            session_timeout: Duration::from_secs(30 * 60), // 30 minutes
        }
    }
}

/// Manages session lifecycles with automatic cleanup and recovery.
///
/// Tracks active sessions and enforces limits on duration, message count,
/// and inactivity. Integrates with lock and affinity management to ensure
/// proper resource cleanup when sessions are forcibly closed.
///
/// # Thread Safety
///
/// All operations are async and use `Arc<RwLock<>>` for thread-safe access.
///
/// # Examples
///
/// ```
/// use queue_runtime::{SessionLifecycleManager, SessionId, SessionLifecycleConfig};
/// use std::time::Duration;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SessionLifecycleConfig::default();
/// let manager = SessionLifecycleManager::new(config);
///
/// let session_id = SessionId::new("order-456".to_string())?;
///
/// // Start tracking a session
/// manager.start_session(session_id.clone(), "worker-1".to_string()).await?;
///
/// // Record activity
/// manager.record_message(&session_id).await?;
///
/// // Check if session should be closed
/// let should_close = manager.should_close_session(&session_id).await;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SessionLifecycleManager {
    active_sessions: Arc<RwLock<HashMap<SessionId, SessionInfo>>>,
    config: SessionLifecycleConfig,
}

impl SessionLifecycleManager {
    /// Create a new session lifecycle manager with the given configuration.
    pub fn new(config: SessionLifecycleConfig) -> Self {
        Self {
            active_sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Start tracking a new session.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::ValidationError` if session is already being tracked.
    pub async fn start_session(
        &self,
        session_id: SessionId,
        consumer_id: String,
    ) -> Result<(), QueueError> {
        let mut sessions = self.active_sessions.write().await;

        if sessions.contains_key(&session_id) {
            return Err(QueueError::ValidationError(
                ValidationError::InvalidFormat {
                    field: "session_id".to_string(),
                    message: format!("Session {} is already active", session_id),
                },
            ));
        }

        sessions.insert(
            session_id.clone(),
            SessionInfo::new(session_id, consumer_id),
        );
        Ok(())
    }

    /// Stop tracking a session.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionNotFound` if session is not being tracked.
    pub async fn stop_session(&self, session_id: &SessionId) -> Result<(), QueueError> {
        let mut sessions = self.active_sessions.write().await;

        if sessions.remove(session_id).is_none() {
            return Err(QueueError::SessionNotFound {
                session_id: session_id.to_string(),
            });
        }

        Ok(())
    }

    /// Record message processing activity for a session.
    ///
    /// Increments message count and updates last activity timestamp.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionNotFound` if session is not being tracked.
    pub async fn record_message(&self, session_id: &SessionId) -> Result<(), QueueError> {
        let mut sessions = self.active_sessions.write().await;

        let session_info =
            sessions
                .get_mut(session_id)
                .ok_or_else(|| QueueError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;

        session_info.increment_message_count();
        Ok(())
    }

    /// Update last activity timestamp without incrementing message count.
    ///
    /// # Errors
    ///
    /// Returns `QueueError::SessionNotFound` if session is not being tracked.
    pub async fn touch_session(&self, session_id: &SessionId) -> Result<(), QueueError> {
        let mut sessions = self.active_sessions.write().await;

        let session_info =
            sessions
                .get_mut(session_id)
                .ok_or_else(|| QueueError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;

        session_info.touch();
        Ok(())
    }

    /// Get information about a session.
    ///
    /// Returns `None` if session is not being tracked.
    pub async fn get_session_info(&self, session_id: &SessionId) -> Option<SessionInfo> {
        let sessions = self.active_sessions.read().await;
        sessions.get(session_id).cloned()
    }

    /// Check if a session should be closed based on configured limits.
    ///
    /// A session should be closed if:
    /// - It has exceeded the maximum duration
    /// - It has processed more than the maximum message count
    /// - It has been idle longer than the timeout
    ///
    /// Returns `false` if session is not being tracked.
    pub async fn should_close_session(&self, session_id: &SessionId) -> bool {
        let sessions = self.active_sessions.read().await;

        if let Some(session_info) = sessions.get(session_id) {
            // Check duration limit
            if session_info.duration() > self.config.max_session_duration {
                return true;
            }

            // Check message count limit
            if session_info.message_count > self.config.max_messages_per_session {
                return true;
            }

            // Check timeout
            if session_info.idle_time() > self.config.session_timeout {
                return true;
            }

            false
        } else {
            false
        }
    }

    /// Get all sessions that should be closed based on configured limits.
    ///
    /// Returns a list of session IDs that have exceeded limits.
    pub async fn get_sessions_to_close(&self) -> Vec<SessionId> {
        let sessions = self.active_sessions.read().await;

        sessions
            .iter()
            .filter(|(_session_id, session_info)| {
                session_info.duration() > self.config.max_session_duration
                    || session_info.message_count > self.config.max_messages_per_session
                    || session_info.idle_time() > self.config.session_timeout
            })
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }

    /// Clean up sessions that have exceeded limits.
    ///
    /// # Returns
    ///
    /// Vector of session IDs that were cleaned up
    pub async fn cleanup_expired_sessions(&self) -> Vec<SessionId> {
        let expired_sessions = self.get_sessions_to_close().await;

        if !expired_sessions.is_empty() {
            let mut sessions = self.active_sessions.write().await;
            for session_id in &expired_sessions {
                sessions.remove(session_id);
            }
        }

        expired_sessions
    }

    /// Get the total number of active sessions.
    pub async fn session_count(&self) -> usize {
        let sessions = self.active_sessions.read().await;
        sessions.len()
    }

    /// Get all active session IDs.
    pub async fn get_active_sessions(&self) -> Vec<SessionId> {
        let sessions = self.active_sessions.read().await;
        sessions.keys().cloned().collect()
    }

    /// Get all sessions for a specific consumer.
    pub async fn get_consumer_sessions(&self, consumer_id: &str) -> Vec<SessionId> {
        let sessions = self.active_sessions.read().await;
        sessions
            .iter()
            .filter(|(_, info)| info.consumer_id() == consumer_id)
            .map(|(session_id, _)| session_id.clone())
            .collect()
    }
}
