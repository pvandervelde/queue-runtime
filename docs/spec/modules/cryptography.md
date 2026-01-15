# Cryptography Module

The cryptography module provides message-level security to prevent man-in-the-middle (MITM) attacks on messages stored in cloud queues. It implements authenticated encryption to ensure both confidentiality (encryption) and integrity (authentication) of message content.

## Overview

**Purpose**: Protect messages from tampering and eavesdropping between sender and receiver.

**Threat Model**: Malicious actor with access to the queue infrastructure can:

- Read message contents
- Modify message payloads
- Replay old messages
- Inject fake messages

**Defense Strategy**: Authenticated encryption with associated data (AEAD) using application-provided keys.

## Core Domain Identifiers

### EncryptionKeyId

Identifier for encryption keys, enabling key rotation without breaking existing messages.

**Type Definition**:

```rust
pub struct EncryptionKeyId(String);
```

**Purpose**:

- Identifies which key was used to encrypt a message
- Enables key rotation (multiple keys active simultaneously)
- Stored in message metadata for decryption key lookup

**Construction**:

```rust
/// Create key ID from string
pub fn new(id: impl Into<String>) -> Self;

/// Get key ID as string reference
pub fn as_str(&self) -> &str;
```

**Usage**:

```rust
let key_id = EncryptionKeyId::new("prod-key-2026-01");
```

### Nonce

Cryptographic nonce (number used once) for AEAD operations. Must be unique for each encryption operation with the same key.

**Type Definition**:

```rust
pub struct Nonce([u8; 12]); // 96-bit nonce for AES-GCM
```

**Purpose**:

- Ensures same plaintext encrypts to different ciphertext
- Prevents attacks exploiting repeated nonces
- Required for AEAD cipher security

**Construction**:

```rust
/// Generate random nonce
pub fn random() -> Self;

/// Get nonce as byte slice
pub fn as_bytes(&self) -> &[u8; 12];
```

### AuthenticationTag

Authentication tag produced by AEAD encryption, verifies message integrity.

**Type Definition**:

```rust
pub struct AuthenticationTag([u8; 16]); // 128-bit tag for AES-GCM
```

**Purpose**:

- Cryptographic proof that message hasn't been tampered with
- Verified during decryption before returning plaintext
- Failure to verify indicates tampering or corruption

---

## Responsibilities

### CryptoProvider Trait

**Responsibilities**:

- Knows: Encryption algorithms, key formats, nonce generation
- Does: Encrypts plaintext, decrypts ciphertext, generates authentication tags

**Collaborators**:

- KeyProvider (retrieves encryption keys)
- Message (encrypts/decrypts message bodies)

**Roles**:

- Encryptor: Transforms plaintext to ciphertext with authentication
- Decryptor: Transforms ciphertext to plaintext after verification
- Validator: Verifies message authenticity before decryption

**Operations**:

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    /// Encrypt plaintext with authenticated encryption
    ///
    /// # Arguments
    /// * `key_id` - Identifier for encryption key to use
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Additional data to authenticate (not encrypted)
    ///
    /// # Returns
    /// Encrypted message with ciphertext, nonce, and authentication tag
    async fn encrypt(
        &self,
        key_id: &EncryptionKeyId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage, CryptoError>;

    /// Decrypt and authenticate ciphertext
    ///
    /// # Arguments
    /// * `encrypted` - Encrypted message with metadata
    ///
    /// # Returns
    /// Original plaintext if authentication succeeds
    ///
    /// # Errors
    /// Returns AuthenticationFailed if message has been tampered with
    async fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Sign message for integrity verification (without encryption)
    ///
    /// # Arguments
    /// * `key_id` - Identifier for signing key
    /// * `data` - Data to sign
    ///
    /// # Returns
    /// HMAC signature of data
    async fn sign(
        &self,
        key_id: &EncryptionKeyId,
        data: &[u8],
    ) -> Result<Signature, CryptoError>;

    /// Verify message signature
    ///
    /// # Arguments
    /// * `key_id` - Identifier for verification key
    /// * `data` - Data that was signed
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// Ok(()) if signature is valid, error otherwise
    async fn verify(
        &self,
        key_id: &EncryptionKeyId,
        data: &[u8],
        signature: &Signature,
    ) -> Result<(), CryptoError>;
}
```

---

### KeyProvider Trait

**Responsibilities**:

- Knows: Encryption keys, key metadata, key rotation schedule
- Does: Retrieves keys by ID, validates key access, manages key lifecycle

**Collaborators**:

- CryptoProvider (provides keys for encryption/decryption)
- Application secret stores (Azure Key Vault, AWS Secrets Manager, etc.)

**Roles**:

- Key Store: Manages cryptographic key material
- Access Control: Enforces key usage policies
- Rotation Manager: Supports multiple active keys for rotation

**Operations**:

```rust
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Retrieve encryption key by ID
    ///
    /// # Arguments
    /// * `key_id` - Identifier of key to retrieve
    ///
    /// # Returns
    /// Raw key material for encryption/decryption
    ///
    /// # Security
    /// Keys MUST be protected in memory (use zeroizing types)
    /// Keys MUST NOT be logged or exposed in error messages
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey, CryptoError>;

    /// Get current active key ID for new messages
    ///
    /// # Returns
    /// Key ID to use for encrypting new messages
    ///
    /// # Rotation
    /// Returns newest key during rotation, enabling smooth key rollover
    async fn current_key_id(&self) -> Result<EncryptionKeyId, CryptoError>;

    /// List all valid key IDs (for decryption of old messages)
    ///
    /// # Returns
    /// All key IDs that can decrypt messages (current + historical)
    async fn valid_key_ids(&self) -> Result<Vec<EncryptionKeyId>, CryptoError>;
}
```

---

### EncryptedMessage Type

**Responsibilities**:

- Knows: Ciphertext, encryption metadata, authentication tag
- Does: Serializes to wire format, deserializes from wire format

**Structure**:

```rust
pub struct EncryptedMessage {
    /// Key ID used for encryption (for decryption key lookup)
    pub key_id: EncryptionKeyId,

    /// Encrypted message body
    pub ciphertext: Vec<u8>,

    /// Nonce used for encryption (required for decryption)
    pub nonce: Nonce,

    /// Authentication tag proving integrity
    pub auth_tag: AuthenticationTag,

    /// Timestamp when message was encrypted (for freshness validation)
    pub encrypted_at: i64, // Unix timestamp

    /// Version of encryption format (for future upgrades)
    pub version: u8,
}
```

**Operations**:

```rust
impl EncryptedMessage {
    /// Serialize to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8>;

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError>;

    /// Check if message is within freshness window
    pub fn is_fresh(&self, max_age: Duration) -> bool;
}
```

---

### EncryptionKey Type

**Responsibilities**:

- Knows: Raw key material, key metadata
- Does: Provides key bytes for cryptographic operations

**Security Properties**:

- Key material zeroed on drop (use `zeroize` crate)
- Never serialized or logged
- Debug implementation redacted

**Structure**:

```rust
use zeroize::Zeroizing;

pub struct EncryptionKey {
    /// Key ID for identification
    id: EncryptionKeyId,

    /// Raw key material (256-bit for AES-256-GCM)
    key_material: Zeroizing<Vec<u8>>,

    /// Key creation timestamp
    created_at: i64,

    /// Optional key expiration
    expires_at: Option<i64>,
}

impl EncryptionKey {
    /// Get key ID
    pub fn id(&self) -> &EncryptionKeyId;

    /// Get key material as bytes
    pub fn as_bytes(&self) -> &[u8];

    /// Check if key is expired
    pub fn is_expired(&self) -> bool;
}

impl Debug for EncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("id", &self.id)
            .field("key_material", &"<REDACTED>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}
```

---

## Message Integration

### Message Envelope Format

Messages support both encrypted and plaintext bodies with automatic detection:

**Envelope Structure**:

```rust
pub struct MessageEnvelope {
    /// Encryption indicator magic bytes (first 4 bytes of body)
    /// Value: "QRE1" (Queue Runtime Encrypted, version 1)
    /// Presence indicates encrypted message
    const ENCRYPTION_MARKER: [u8; 4] = *b"QRE1";
}
```

**Wire Format**:

- **Encrypted Message**: `["QRE1"][version][encrypted_message_bytes]`
- **Plaintext Message**: `[raw_payload_bytes]` (no marker)

**Detection Algorithm**:

```rust
fn is_encrypted(body: &[u8]) -> bool {
    body.len() >= 4 && &body[0..4] == b"QRE1"
}
```

### Secure Message Envelope

When encryption is enabled, messages are wrapped in encrypted envelope:

```rust
pub struct SecureMessage {
    /// Encryption marker ("QRE1")
    pub marker: [u8; 4],

    /// Original message metadata (session ID, correlation ID, properties)
    pub metadata: MessageMetadata,

    /// Encrypted message body
    pub encrypted_body: EncryptedMessage,
}

impl SecureMessage {
    /// Serialize to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.marker);  // "QRE1"
        bytes.push(1);  // Version
        bytes.extend_from_slice(&self.encrypted_body.to_bytes());
        bytes
    }

    /// Deserialize from wire format
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < 5 || &data[0..4] != b"QRE1" {
            return Err(CryptoError::InvalidEnvelope);
        }
        let version = data[4];
        if version != 1 {
            return Err(CryptoError::UnsupportedVersion { version });
        }
        let encrypted_body = EncryptedMessage::from_bytes(&data[5..])?;
        Ok(Self {
            marker: *b"QRE1",
            metadata: MessageMetadata::default(),
            encrypted_body,
        })
    }
}
```

**Processing Flow**:

1. **Sending with Encryption Enabled**:
   - Application creates `Message` with plaintext body
   - QueueClient checks if crypto enabled in config
   - If enabled: Encrypts body using `CryptoProvider`, prepends "QRE1" marker
   - If disabled: Sends plaintext body (no marker)
   - Logs encryption status (encrypted=true/false)
   - Emits metric: `queue_messages_sent{encrypted="true|false"}`

2. **Receiving with Encryption Detection**:
   - QueueClient receives message from queue
   - Checks first 4 bytes for "QRE1" marker
   - **If marker present (encrypted)**:
     - Validates message freshness (timestamp check)
     - Decrypts body using `CryptoProvider`
     - Logs: `message received (encrypted=true)`
     - Emits metric: `queue_messages_received{encrypted="true"}`
   - **If no marker (plaintext)**:
     - Logs WARNING: `message received without encryption (encrypted=false)`
     - Emits metric: `queue_messages_received{encrypted="false"}`
     - Returns plaintext body as-is (backward compatibility)
   - Returns `Message` with plaintext body to application

3. **Mixed Environment Support**:
   - Sender can disable encryption (debug mode)
   - Receiver auto-detects and handles both formats
   - Warnings logged when plaintext messages received
   - Metrics enable monitoring of encryption adoption

---

## Algorithm Specifications

### Default: AES-256-GCM

**Algorithm**: AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)

**Properties**:

- **Authenticated Encryption**: Provides both confidentiality and integrity
- **Nonce-Based**: Requires unique nonce per encryption
- **Associated Data**: Can authenticate metadata without encrypting it
- **Performance**: Hardware-accelerated on most modern CPUs

**Parameters**:

- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)
- Authentication tag: 128 bits (16 bytes)

**Associated Data**:

- Message ID (prevents ciphertext substitution)
- Session ID (binds encryption to session)
- Timestamp (prevents replay attacks)

**Implementation**:

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce};
use aes_gcm::aead::{Aead, KeyInit};

pub struct AesGcmCryptoProvider {
    key_provider: Arc<dyn KeyProvider>,
}

impl AesGcmCryptoProvider {
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Self {
        Self { key_provider }
    }
}

#[async_trait]
impl CryptoProvider for AesGcmCryptoProvider {
    async fn encrypt(
        &self,
        key_id: &EncryptionKeyId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage, CryptoError> {
        // Get encryption key
        let key = self.key_provider.get_key(key_id).await?;

        // Generate random nonce
        let nonce = Nonce::random();

        // Create cipher
        let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        // Encrypt with associated data
        let ciphertext = cipher
            .encrypt(AesNonce::from_slice(nonce.as_bytes()),
                     aes_gcm::aead::Payload {
                         msg: plaintext,
                         aad: associated_data,
                     })
            .map_err(|e| CryptoError::EncryptionFailed {
                reason: e.to_string()
            })?;

        // Extract authentication tag (last 16 bytes)
        let tag_start = ciphertext.len() - 16;
        let auth_tag = AuthenticationTag::from_bytes(&ciphertext[tag_start..])?;
        let ciphertext = ciphertext[..tag_start].to_vec();

        Ok(EncryptedMessage {
            key_id: key_id.clone(),
            ciphertext,
            nonce,
            auth_tag,
            encrypted_at: current_timestamp(),
            version: 1,
        })
    }

    async fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
    ) -> Result<Vec<u8>, CryptoError> {
        // Validate version
        if encrypted.version != 1 {
            return Err(CryptoError::UnsupportedVersion {
                version: encrypted.version
            });
        }

        // Get decryption key
        let key = self.key_provider.get_key(&encrypted.key_id).await?;

        // Create cipher
        let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);

        // Reconstruct ciphertext with auth tag
        let mut ciphertext_with_tag = encrypted.ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(encrypted.auth_tag.as_bytes());

        // Decrypt and verify
        let plaintext = cipher
            .decrypt(
                AesNonce::from_slice(encrypted.nonce.as_bytes()),
                ciphertext_with_tag.as_slice()
            )
            .map_err(|_| CryptoError::AuthenticationFailed {
                reason: "Decryption failed - message may be tampered".to_string(),
            })?;

        Ok(plaintext)
    }
}
```

---

## Replay Protection

### Freshness Validation

**Problem**: Attacker replays old valid encrypted messages.

**Solution**: Timestamp-based freshness check with configurable window.

**Configuration**:

```rust
pub struct CryptoConfig {
    /// Maximum age for messages (default: 5 minutes)
    pub max_message_age: Duration,

    /// Enable freshness validation
    pub validate_freshness: bool,
}
```

**Implementation**:

```rust
impl EncryptedMessage {
    pub fn is_fresh(&self, max_age: Duration) -> bool {
        let now = current_timestamp();
        let age = now - self.encrypted_at;
        age >= 0 && age <= max_age.as_secs() as i64
    }
}

// In receive path
if config.validate_freshness && !encrypted_msg.is_fresh(config.max_message_age) {
    return Err(CryptoError::MessageExpired {
        encrypted_at: encrypted_msg.encrypted_at,
        max_age: config.max_message_age,
    });
}
```

### Nonce Tracking (Optional)

For extremely high-security scenarios, track used nonces to detect replays:

```rust
pub trait NonceStore: Send + Sync {
    /// Check if nonce has been used and mark as used
    async fn check_and_mark(&self, nonce: &Nonce, key_id: &EncryptionKeyId)
        -> Result<bool, CryptoError>;
}
```

**Trade-off**: Adds storage overhead but provides strongest replay protection.

---

## Key Rotation Strategy

### Multi-Key Support

**Scenario**: Rotate encryption keys without breaking existing messages.

**Strategy**:

1. Application adds new key with new key ID
2. New messages encrypted with new key
3. Old messages still decrypt with old key
4. After TTL expires, remove old key

**Implementation**:

```rust
pub struct MultiKeyProvider {
    keys: HashMap<EncryptionKeyId, EncryptionKey>,
    current: EncryptionKeyId,
}

#[async_trait]
impl KeyProvider for MultiKeyProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey, CryptoError> {
        self.keys.get(key_id)
            .cloned()
            .ok_or_else(|| CryptoError::KeyNotFound {
                key_id: key_id.clone()
            })
    }

    async fn current_key_id(&self) -> Result<EncryptionKeyId, CryptoError> {
        Ok(self.current.clone())
    }

    async fn valid_key_ids(&self) -> Result<Vec<EncryptionKeyId>, CryptoError> {
        Ok(self.keys.keys().cloned().collect())
    }
}
```

**Rotation Process**:

```rust
// 1. Add new key
key_provider.add_key(new_key);

// 2. Set as current
key_provider.set_current(new_key_id);

// 3. Wait for old messages to expire (queue TTL)
tokio::time::sleep(queue_ttl).await;

// 4. Remove old key
key_provider.remove_key(old_key_id);
```

---

## Observability and Monitoring

### Encryption Status Logging

**Send Path**:

```rust
// Log when sending encrypted message
tracing::info!(
    message_id = %msg.id(),
    session_id = ?msg.session_id(),
    encrypted = true,
    key_id = %key_id,
    "Message sent with encryption"
);

// Log WARNING when sending plaintext (crypto disabled)
tracing::warn!(
    message_id = %msg.id(),
    session_id = ?msg.session_id(),
    encrypted = false,
    "Message sent WITHOUT encryption - crypto disabled in config"
);
```

**Receive Path**:

```rust
// Log when receiving encrypted message
tracing::info!(
    message_id = %msg.id(),
    session_id = ?msg.session_id(),
    encrypted = true,
    key_id = %encrypted.key_id,
    "Message received with encryption"
);

// Log WARNING when receiving plaintext
tracing::warn!(
    message_id = %msg.id(),
    session_id = ?msg.session_id(),
    encrypted = false,
    "Message received WITHOUT encryption - sent by legacy/debug sender"
);
```

### Encryption Metrics

**Counter Metrics**:

```rust
// Messages sent (labeled by encryption status)
queue_messages_sent_total{queue="my-queue", encrypted="true"}
queue_messages_sent_total{queue="my-queue", encrypted="false"}

// Messages received (labeled by encryption status)
queue_messages_received_total{queue="my-queue", encrypted="true"}
queue_messages_received_total{queue="my-queue", encrypted="false"}

// Encryption failures
queue_crypto_errors_total{queue="my-queue", error_type="encryption_failed"}
queue_crypto_errors_total{queue="my-queue", error_type="authentication_failed"}
queue_crypto_errors_total{queue="my-queue", error_type="key_not_found"}
queue_crypto_errors_total{queue="my-queue", error_type="message_expired"}
```

**Histogram Metrics**:

```rust
// Encryption operation latency
queue_crypto_encrypt_duration_seconds{queue="my-queue"}

// Decryption operation latency
queue_crypto_decrypt_duration_seconds{queue="my-queue"}
```

**Gauge Metrics**:

```rust
// Current encryption configuration status
queue_crypto_enabled{queue="my-queue"} = 1.0  // Enabled
queue_crypto_enabled{queue="my-queue"} = 0.0  // Disabled
```

### Alerting Recommendations

**Production Alerts**:

1. **Unencrypted Messages in Production**:

   ```promql
   # Alert if >1% of messages are unencrypted
   rate(queue_messages_received_total{encrypted="false"}[5m])
   / rate(queue_messages_received_total[5m]) > 0.01
   ```

2. **Encryption Disabled**:

   ```promql
   # Alert if crypto disabled in production environment
   queue_crypto_enabled{environment="production"} == 0
   ```

3. **High Encryption Error Rate**:

   ```promql
   # Alert if >5% of operations fail
   rate(queue_crypto_errors_total[5m])
   / rate(queue_messages_sent_total[5m]) > 0.05
   ```

4. **Key Rotation Needed**:

   ```promql
   # Alert if same key used for >90 days
   time() - queue_crypto_key_created_timestamp > 7776000
   ```

### Debug Mode Configuration

**Temporary Encryption Disable for Debugging**:

```rust
// Development/debugging configuration
let config = CryptoConfig {
    enabled: false,  // Disable encryption temporarily
    ..Default::default();
};

// Logs WARNING on every send:
// "Message sent WITHOUT encryption - crypto disabled in config"

// Receiver still accepts both encrypted and plaintext messages
```

**Environment-Based Configuration**:

```rust
// Disable in dev, enable in prod
let crypto_enabled = std::env::var("ENVIRONMENT")
    .map(|e| e == "production" || e == "staging")
    .unwrap_or(false);

let config = CryptoConfig {
    enabled: crypto_enabled,
    ..Default::default()
};
```

---

## Error Types

```rust
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },

    #[error("Key not found: {key_id:?}")]
    KeyNotFound { key_id: EncryptionKeyId },

    #[error("Message expired: encrypted at {encrypted_at}, max age {max_age:?}")]
    MessageExpired { encrypted_at: i64, max_age: Duration },

    #[error("Unsupported encryption version: {version}")]
    UnsupportedVersion { version: u8 },

    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize { expected: usize, actual: usize },

    #[error("Invalid message envelope: missing or corrupt encryption marker")]
    InvalidEnvelope,

    #[error("Key provider error: {source}")]
    KeyProviderError { source: Box<dyn std::error::Error + Send + Sync> },
}
```

---

## Configuration

### Crypto Configuration

```rust
pub struct CryptoConfig {
    /// Enable message encryption on send
    pub enabled: bool,

    /// Policy for receiving unencrypted messages
    pub plaintext_policy: PlaintextPolicy,

    /// Maximum message age (freshness validation)
    pub max_message_age: Duration,

    /// Validate message freshness
    pub validate_freshness: bool,

    /// Enable nonce tracking (replay detection)
    pub track_nonces: bool,

    /// Nonce cache TTL (if tracking enabled)
    pub nonce_cache_ttl: Duration,
}

/// Policy for handling plaintext (unencrypted) messages on receive
pub enum PlaintextPolicy {
    /// Accept plaintext messages (backward compatibility mode)
    /// Logs WARNING for each plaintext message
    Allow,

    /// Reject plaintext messages with error (strict security mode)
    /// Returns QueueError::UnencryptedMessage
    Reject,

    /// Accept but require operator acknowledgment
    /// Increments error metric, logs ERROR, but processes message
    AllowWithAlert,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in for backward compatibility
            plaintext_policy: PlaintextPolicy::Allow, // Accept plaintext by default
            max_message_age: Duration::from_secs(300), // 5 minutes
            validate_freshness: true,
            track_nonces: false, // Opt-in for high security
            nonce_cache_ttl: Duration::from_secs(600), // 10 minutes
        }
    }
}
```

### Queue Client Integration

```rust
pub struct QueueClientConfig {
    // ... existing fields ...

    /// Cryptography configuration
    pub crypto: CryptoConfig,

    /// Key provider for encryption/decryption
    pub key_provider: Option<Arc<dyn KeyProvider>>,
}

impl QueueClient {
    pub async fn send(&self, msg: Message) -> Result<MessageId, QueueError> {
        let msg = if self.config.crypto.enabled {
            // Encrypt message body
            self.encrypt_message(msg).await?
        } else {
            msg
        };

        self.provider.send(msg).await
    }

    pub async fn receive(&self) -> Result<ReceivedMessage, QueueError> {
        let msg = self.provider.receive().await?;

        if self.config.crypto.enabled {
            // Decrypt message body
            self.decrypt_message(msg).await
        } else {
            Ok(msg)
        }
    }
}
```

---

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_round_trip() {
        let key_provider = create_test_key_provider();
        let crypto = AesGcmCryptoProvider::new(key_provider);

        let plaintext = b"sensitive webhook payload";
        let associated_data = b"message-id-12345";

        let encrypted = crypto.encrypt(
            &EncryptionKeyId::new("test-key"),
            plaintext,
            associated_data,
        ).await.unwrap();

        let decrypted = crypto.decrypt(&encrypted).await.unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[tokio::test]
    async fn test_tampering_detection() {
        let key_provider = create_test_key_provider();
        let crypto = AesGcmCryptoProvider::new(key_provider);

        let mut encrypted = create_test_encrypted_message();

        // Tamper with ciphertext
        encrypted.ciphertext[0] ^= 0xFF;

        let result = crypto.decrypt(&encrypted).await;

        assert!(matches!(result, Err(CryptoError::AuthenticationFailed { .. })));
    }

    #[tokio::test]
    async fn test_freshness_validation() {
        let mut encrypted = create_test_encrypted_message();

        // Set timestamp to 10 minutes ago
        encrypted.encrypted_at = current_timestamp() - 600;

        assert!(!encrypted.is_fresh(Duration::from_secs(300)));
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let key_provider = MultiKeyProvider::new();

        // Add initial key
        key_provider.add_key(create_key("key-v1"));
        key_provider.set_current("key-v1");

        let crypto = AesGcmCryptoProvider::new(Arc::new(key_provider.clone()));

        // Encrypt with key v1
        let encrypted_v1 = crypto.encrypt(
            &key_provider.current_key_id().await.unwrap(),
            b"message 1",
            b"",
        ).await.unwrap();

        // Rotate to key v2
        key_provider.add_key(create_key("key-v2"));
        key_provider.set_current("key-v2");

        // Encrypt with key v2
        let encrypted_v2 = crypto.encrypt(
            &key_provider.current_key_id().await.unwrap(),
            b"message 2",
            b"",
        ).await.unwrap();

        // Both should decrypt successfully
        assert_eq!(crypto.decrypt(&encrypted_v1).await.unwrap(), b"message 1");
        assert_eq!(crypto.decrypt(&encrypted_v2).await.unwrap(), b"message 2");
    }

    #[tokio::test]
    async fn test_encryption_detection() {
        // Test encrypted message detection
        let encrypted_body = b"QRE1\x01encrypted_data_here";
        assert!(is_encrypted(encrypted_body));

        // Test plaintext message detection
        let plaintext_body = b"plain message data";
        assert!(!is_encrypted(plaintext_body));
    }

    #[tokio::test]
    async fn test_mixed_messages() {
        let client = create_test_client_with_crypto();

        // Send encrypted message
        let encrypted_msg = Message::new(b"encrypted payload".to_vec());
        client.send(encrypted_msg).await.unwrap();

        // Manually send plaintext (simulating old sender)
        let plaintext_msg = b"plaintext payload";
        send_raw_to_queue(plaintext_msg).await;

        // Receive encrypted - should auto-decrypt
        let msg1 = client.receive().await.unwrap();
        assert_eq!(msg1.body(), b"encrypted payload");

        // Receive plaintext - should handle gracefully
        let msg2 = client.receive().await.unwrap();
        assert_eq!(msg2.body(), b"plaintext payload");
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_encrypted_message_through_queue() {
    let key_provider = create_test_key_provider();

    let client = QueueClientBuilder::new()
        .with_memory_provider()
        .with_crypto(CryptoConfig::default())
        .with_key_provider(key_provider)
        .build()
        .await
        .unwrap();

    // Send encrypted message
    let msg = Message::new(b"secret payload".to_vec());
    let msg_id = client.send(msg).await.unwrap();

    // Receive and auto-decrypt
    let received = client.receive().await.unwrap();

    assert_eq!(received.body(), b"secret payload");
}

#[tokio::test]
async fn test_multi_service_with_different_keys() {
    // Simulate sender with multiple clients
    let key_provider_a = create_key_provider("key-a");
    let key_provider_b = create_key_provider("key-b");

    let sender_client_a = QueueClientBuilder::new()
        .with_memory_provider()
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(key_provider_a.clone()))
        .build().await.unwrap();

    let sender_client_b = QueueClientBuilder::new()
        .with_memory_provider()
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(key_provider_b.clone()))
        .build().await.unwrap();

    // Send messages with different keys
    sender_client_a.send(Message::new(b"for service A".to_vec())).await.unwrap();
    sender_client_b.send(Message::new(b"for service B".to_vec())).await.unwrap();

    // Receiver A (with key-a)
    let receiver_a = QueueClientBuilder::new()
        .with_memory_provider()
        .with_key_provider(Arc::new(key_provider_a))
        .build().await.unwrap();

    let msg_a = receiver_a.receive().await.unwrap();
    assert_eq!(msg_a.body(), b"for service A");

    // Receiver B (with key-b)
    let receiver_b = QueueClientBuilder::new()
        .with_memory_provider()
        .with_key_provider(Arc::new(key_provider_b))
        .build().await.unwrap();

    let msg_b = receiver_b.receive().await.unwrap();
    assert_eq!(msg_b.body(), b"for service B");
}

#[tokio::test]
async fn test_wrong_key_fails_decryption() {
    let key_provider_a = create_key_provider("key-a");
    let key_provider_b = create_key_provider("key-b");

    // Send with key-a
    let sender = QueueClientBuilder::new()
        .with_memory_provider()
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(key_provider_a))
        .build().await.unwrap();

    sender.send(Message::new(b"secret".to_vec())).await.unwrap();

    // Try to receive with key-b (wrong key)
    let receiver = QueueClientBuilder::new()
        .with_memory_provider()
        .with_key_provider(Arc::new(key_provider_b))
        .build().await.unwrap();

    let result = receiver.receive().await;

    // Should fail with authentication error
    assert!(matches!(result, Err(QueueError::CryptoError(
        CryptoError::AuthenticationFailed { .. }
    ))));
}
```

---

## Multi-Service Architecture Patterns

### Pattern 1: One Sender, Multiple Receivers with Different Keys

**Use Case**: Webhook router distributes events to different services, each with isolated encryption keys.

```rust
// Sender maintains multiple clients
struct WebhookRouter {
    service_a_client: QueueClient,  // Encrypts with key-a
    service_b_client: QueueClient,  // Encrypts with key-b
    service_c_client: QueueClient,  // Encrypts with key-c
}

impl WebhookRouter {
    async fn new() -> Result<Self> {
        Ok(Self {
            service_a_client: QueueClientBuilder::new()
                .with_azure_provider(config_a)
                .with_crypto(CryptoConfig { enabled: true, .. })
                .with_key_provider(Arc::new(create_key_provider("key-a")))
                .build().await?,

            service_b_client: QueueClientBuilder::new()
                .with_azure_provider(config_b)
                .with_crypto(CryptoConfig { enabled: true, .. })
                .with_key_provider(Arc::new(create_key_provider("key-b")))
                .build().await?,

            service_c_client: QueueClientBuilder::new()
                .with_azure_provider(config_c)
                .with_crypto(CryptoConfig { enabled: true, .. })
                .with_key_provider(Arc::new(create_key_provider("key-c")))
                .build().await?,
        })
    }

    async fn route_event(&self, event: WebhookEvent) -> Result<()> {
        match event.service {
            "A" => self.service_a_client.send(event.into()).await?,
            "B" => self.service_b_client.send(event.into()).await?,
            "C" => self.service_c_client.send(event.into()).await?,
            _ => return Err("Unknown service"),
        };
        Ok(())
    }
}

// Each receiver only has its own key
async fn service_a_receiver() -> QueueClient {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_key_provider(Arc::new(create_key_provider("key-a")))
        .build().await.unwrap()
}

async fn service_b_receiver() -> QueueClient {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_key_provider(Arc::new(create_key_provider("key-b")))
        .build().await.unwrap()
}
```

**Security**: Service A cannot decrypt Service B's messages (different keys).

### Pattern 2: Mixed Encryption - Some Queues Encrypted, Others Not

**Use Case**: Production queues encrypted, debug queues plaintext for troubleshooting.

```rust
struct MultiEnvironmentSender {
    prod_client: QueueClient,    // Encrypted
    debug_client: QueueClient,   // Plaintext
}

impl MultiEnvironmentSender {
    async fn new() -> Result<Self> {
        Ok(Self {
            prod_client: QueueClientBuilder::new()
                .with_azure_provider(prod_config)
                .with_crypto(CryptoConfig {
                    enabled: true,
                    plaintext_policy: PlaintextPolicy::Reject,
                    ..Default::default()
                })
                .with_key_provider(Arc::new(prod_key_provider))
                .build().await?,

            debug_client: QueueClientBuilder::new()
                .with_azure_provider(debug_config)
                .with_crypto(CryptoConfig {
                    enabled: false,  // Plaintext for debugging
                    ..Default::default()
                })
                .build().await?,
        })
    }

    async fn send(&self, env: Environment, msg: Message) -> Result<()> {
        match env {
            Environment::Production => {
                // Sends with "QRE1" marker (encrypted)
                self.prod_client.send(msg).await?;
            }
            Environment::Debug => {
                // Sends without marker (plaintext)
                // Logs WARNING: "Message sent WITHOUT encryption"
                self.debug_client.send(msg).await?;
            }
        }
        Ok(())
    }
}

// Receiver auto-detects both
async fn universal_receiver() -> QueueClient {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_key_provider(Arc::new(key_provider))
        .build().await.unwrap()
}

async fn process_messages(client: &QueueClient) {
    loop {
        let msg = client.receive().await.unwrap();
        // Auto-detects: encrypted (QRE1) or plaintext
        process(msg.body()).await;
        client.complete(msg.receipt()).await.unwrap();
    }
}
```

**Flexibility**: Can disable encryption for debugging without code changes on receiver.

### Pattern 3: Receiver Auto-Detection Only

**Use Case**: Receiver doesn't know sender configuration, handles both encrypted and plaintext.

```rust
// Receiver configured to accept both
async fn flexible_receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_crypto(CryptoConfig {
            plaintext_policy: PlaintextPolicy::Allow,  // Accept both
            ..Default::default()
        })
        .with_key_provider(Arc::new(key_provider))
        .build().await
}

async fn process_all_messages(client: &QueueClient) {
    loop {
        let msg = client.receive().await.unwrap();

        // Library automatically:
        // - Checks for "QRE1" marker
        // - If present: decrypts with key_provider
        // - If absent: returns plaintext, logs WARNING

        let body = msg.body();  // Always plaintext here
        process_event(body).await;
        client.complete(msg.receipt()).await.unwrap();
    }
}
```

**No Coordination**: Receiver works with any sender configuration.

---

## Performance Considerations

### Encryption Overhead

**AES-256-GCM Performance** (hardware-accelerated):

- ~1-2 microseconds per message (typical webhook payload size)
- Minimal impact on throughput (<1% for most workloads)

**Optimization Strategies**:

1. **Batch encryption**: Encrypt multiple messages in parallel
2. **Hardware acceleration**: Use AES-NI CPU instructions (enabled by default in `aes-gcm` crate)
3. **Connection pooling**: Reuse crypto provider instances (they are thread-safe)

### Key Caching

Cache encryption keys in memory to avoid repeated secret store lookups:

```rust
pub struct CachedKeyProvider {
    inner: Arc<dyn KeyProvider>,
    cache: Arc<RwLock<HashMap<EncryptionKeyId, EncryptionKey>>>,
    cache_ttl: Duration,
}
```

**Trade-off**: Memory overhead vs. secret store latency (typically 10-50ms per lookup).

---

## Security Properties

### Guarantees

1. **Confidentiality**: Message content encrypted with AES-256 (industry standard)
2. **Integrity**: Authentication tag prevents undetected tampering
3. **Authenticity**: Only parties with correct key can create valid messages
4. **Freshness**: Timestamp validation prevents replay of old messages
5. **Key Rotation**: Supports seamless key updates without service interruption

### Limitations

1. **Metadata Visibility**: Message ID, session ID, correlation ID remain in cleartext (required for routing)
2. **Timing Attacks**: Decryption timing may reveal information about key validity
3. **Key Management**: Security depends on application's key storage (library cannot enforce)
4. **Replay Window**: Messages within freshness window can be replayed (use nonce tracking for mitigation)

### Compliance

- **FIPS 140-2**: AES-256-GCM is FIPS-approved cipher
- **PCI DSS**: Meets encryption requirements for cardholder data
- **GDPR**: Provides encryption for personal data in transit and at rest
- **HIPAA**: Satisfies encryption requirements for protected health information

---

## Migration Path

### Phase 1: Opt-In (Current)

- Crypto disabled by default
- Applications explicitly enable with configuration
- No impact on existing deployments

### Phase 2: Deprecation Warning (Future)

- Log warnings when crypto is disabled
- Update documentation recommending crypto for all deployments

### Phase 3: Default Enable (Future)

- Crypto enabled by default
- Applications must explicitly disable (not recommended)

### Phase 4: Mandatory (Future, Breaking Change)

- Remove ability to disable crypto
- All messages encrypted (major version bump)

---

## Example Usage

### Basic Setup

```rust
use queue_runtime::{QueueClient, CryptoConfig, MultiKeyProvider, EncryptionKey};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create key provider
    let key_provider = MultiKeyProvider::new();
    key_provider.add_key(EncryptionKey::from_bytes(
        "my-key-2026",
        &load_key_from_secret_store()?,
    ));
    key_provider.set_current("my-key-2026");

    // Configure queue client with encryption
    let client = QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_crypto(CryptoConfig {
            enabled: true,
            max_message_age: Duration::from_secs(300),
            validate_freshness: true,
            ..Default::default()
        })
        .with_key_provider(Arc::new(key_provider))
        .build()
        .await?;

    // Send encrypted message (transparent to application)
    let msg = Message::new(b"sensitive data".to_vec());
    client.send(msg).await?;

    // Receive and decrypt (transparent to application)
    let received = client.receive().await?;
    println!("Decrypted: {}", String::from_utf8_lossy(received.body()));

    Ok(())
}
```

### With Azure Key Vault

```rust
use azure_security_keyvault::KeyvaultClient;

pub struct AzureKeyVaultProvider {
    client: KeyvaultClient,
    vault_name: String,
}

#[async_trait]
impl KeyProvider for AzureKeyVaultProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey, CryptoError> {
        let secret = self.client
            .get_secret(key_id.as_str())
            .await
            .map_err(|e| CryptoError::KeyProviderError {
                source: Box::new(e)
            })?;

        let key_bytes = base64::decode(secret.value())?;
        Ok(EncryptionKey::from_bytes(key_id.as_str(), &key_bytes))
    }

    async fn current_key_id(&self) -> Result<EncryptionKeyId, CryptoError> {
        // Fetch "current-encryption-key" metadata from vault
        let current_id = self.client
            .get_secret_metadata("current-encryption-key")
            .await?;

        Ok(EncryptionKeyId::new(current_id))
    }
}
```

### With AWS Secrets Manager

```rust
use aws_sdk_secretsmanager::Client as SecretsManagerClient;

pub struct AwsSecretsManagerProvider {
    client: SecretsManagerClient,
    secret_prefix: String,
}

#[async_trait]
impl KeyProvider for AwsSecretsManagerProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey, CryptoError> {
        let secret_name = format!("{}/{}", self.secret_prefix, key_id.as_str());

        let response = self.client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|e| CryptoError::KeyProviderError {
                source: Box::new(e)
            })?;

        let key_bytes = response.secret_binary()
            .ok_or_else(|| CryptoError::KeyProviderError {
                source: "Secret is not binary".into()
            })?;

        Ok(EncryptionKey::from_bytes(key_id.as_str(), key_bytes.as_ref()))
    }
}
```
