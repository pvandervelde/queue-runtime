# MITM Protection Architecture Summary

**Version**: 1.0
**Date**: January 15, 2026
**Status**: Architecture Complete - Ready for Interface Design

---

## Executive Summary

This document summarizes the architectural design for man-in-the-middle (MITM) protection in the queue-runtime library. The solution provides end-to-end message encryption and authentication to prevent tampering, eavesdropping, and replay attacks on messages stored in cloud queues.

### Key Design Decisions

1. **Hybrid Approach**: Library enforces encryption/authentication, applications provide keys
2. **Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity
3. **Transparent API**: Encryption/decryption automatic, no API changes for applications
4. **Key Rotation**: Support multiple active keys for zero-downtime rotation
5. **Opt-In**: Encryption disabled by default for backward compatibility
6. **Replay Protection**: Timestamp-based freshness validation with optional nonce tracking

---

## Problem Statement

**Threat**: Malicious actor with access to queue infrastructure (Azure Service Bus, AWS SQS) can:

- Read message contents (eavesdropping)
- Modify message payloads (tampering)
- Inject fake messages (forgery)
- Replay old messages (replay attacks)
- Substitute entire messages (substitution)

**Impact**: Compromise of private repository data, webhook payload integrity, and application logic correctness.

**Existing Protection**: TLS protects network transit, but not storage at rest or provider-internal access.

**Solution**: End-to-end encryption with authenticated encryption (AEAD), protecting messages even if queue infrastructure is compromised.

---

## Architecture Overview

### Encryption Algorithm: Symmetric AES-256-GCM

**Choice**: Symmetric encryption (not asymmetric/public-private key)

**Rationale**:

- **Performance**: 100-1000x faster than RSA/ECC asymmetric encryption (~1-2μs vs 100+μs)
- **Message Size**: No size limits (RSA limited to ~190 bytes with 2048-bit key)
- **Standard Practice**: Industry standard for bulk data encryption (what TLS uses internally)
- **Hardware Acceleration**: AES-NI CPU instructions on modern processors

**Alternative Considered: Asymmetric (Public/Private Key)**:

- ❌ Much slower for message-sized payloads
- ❌ Size limitations requiring hybrid approach anyway
- ✅ Only beneficial if different services with different keys

### Cryptography Module

New module providing message-level security through:

1. **CryptoProvider Trait**: Abstraction for encryption/decryption operations
2. **KeyProvider Trait**: Abstraction for loading encryption keys from secret stores
3. **EncryptedMessage Type**: Container for ciphertext, nonce, auth tag, and metadata
4. **EncryptionKey Type**: Secure key material with automatic memory zeroing
5. **Encryption Detection**: Magic marker (\"QRE1\") enables receiver to detect encrypted vs plaintext messages

See [cryptography module specification](./modules/cryptography.md) for complete details.

### Algorithm: AES-256-GCM

**Algorithm**: AES-256-GCM (Advanced Encryption Standard, 256-bit key, Galois/Counter Mode)

**Type**: Symmetric encryption (same key for encryption and decryption)

**Properties**:

- **Authenticated Encryption**: Provides both confidentiality (encryption) and integrity (authentication)
- **Nonce-Based**: Requires unique 96-bit nonce per encryption operation
- **Associated Data**: Authenticates message ID, session ID, timestamp without encrypting
- **Performance**: Hardware-accelerated on modern CPUs (~1-2μs per message)
- **Compliance**: FIPS 140-2 approved, meets GDPR/PCI DSS/HIPAA requirements

**Security Guarantees**:

- 256-bit key security (industry standard)
- 128-bit authentication tag (prevents tampering)
- Ciphertext indistinguishability (prevents information leakage)

---

## Symmetric vs Asymmetric Encryption Analysis

### Why Symmetric (AES-256-GCM)?

**Use Case**: One sender service distributes to multiple receiver services within **trusted system boundary**

- **Sender**: Webhook router service receives GitHub webhooks, enqueues messages to different queues
- **Receivers**: Multiple bot services (Task Tactician, Merge Warden, Spec Sentinel, etc.) each consuming from their own queues
- All services are **trusted** (part of your application ecosystem)
- All services have access to shared secret store (Azure Key Vault / AWS Secrets Manager)
- Each queue can use a unique symmetric key shared between sender and its designated receiver(s)

**Performance Comparison**:

| Operation | AES-256-GCM (Symmetric) | RSA-2048 (Asymmetric) |
|-----------|--------------------------|------------------------|
| Encryption | ~1-2 microseconds | ~100-500 microseconds |
| Decryption | ~1-2 microseconds | ~1000-3000 microseconds |
| Throughput Impact | <1% | 10-50% |
| Hardware Acceleration | Yes (AES-NI) | Limited |

**Message Size**:

- **Symmetric**: No practical limit (can encrypt gigabytes)
- **Asymmetric**: RSA-2048 limited to ~190 bytes, RSA-4096 to ~450 bytes
  - Requires hybrid approach (RSA to encrypt symmetric key, AES for data)
  - What TLS/HTTPS does internally anyway

**Key Management**:

- **Symmetric**: Keys stored in shared secret manager (Azure Key Vault / AWS Secrets Manager)
  - Webhook router and bot services both retrieve keys for their respective queues
  - IAM roles/managed identities control access to specific keys
  - Simple key rotation via secret store updates
- **Asymmetric**: Public key distribution, private key protection, certificate management, PKI infrastructure
  - Only needed if services don't trust each other
  - Unnecessary complexity for trusted service ecosystem

**Industry Standard**: This is exactly what TLS/HTTPS does:

1. Use asymmetric (RSA/ECDH) for initial key exchange
2. Use symmetric (AES-GCM) for all actual data encryption
3. We skip step 1 since all services are trusted and share access to secret store

### When Would Asymmetric Be Needed?

**Scenario**: Different services with **different trust boundaries** (zero-trust architecture)

Example:

- **Service A** (third-party webhook receiver) sends to queue
- **Service B** (your event processor) receives from queue
- Service A is **untrusted** (different organization, security domain)
- Service B should **not** trust Service A to protect encryption keys
- Service A could be compromised without affecting B

**Solution**:

- Service A has Service B's **public key** (can encrypt, cannot decrypt)
- Service B has private key (can decrypt)
- Even if Service A is compromised, attacker cannot decrypt messages in queue

**For Your Use Case**: **Not needed** because:

- Webhook router and all bot services are **part of your trusted system**
- All services deployed and managed by your organization
- All services authenticate to same secret store (Azure Key Vault / AWS Secrets Manager)
- Symmetric encryption provides sufficient security within trusted boundary
- Much simpler key management and significantly better performance

### Hybrid Approach (If Needed in Future)

If you later need different senders/receivers:

```rust
// Sender: Encrypt with recipient's public key
let data_key = generate_random_symmetric_key();  // 256-bit AES key
let encrypted_data = aes_gcm_encrypt(data_key, message_body);
let encrypted_key = rsa_encrypt(recipient_public_key, data_key);

// Receiver: Decrypt with private key
let data_key = rsa_decrypt(recipient_private_key, encrypted_key);
let message_body = aes_gcm_decrypt(data_key, encrypted_data);
```

**Trade-offs**:

- ✅ Different keys for sender/receiver
- ❌ ~100x slower than pure symmetric
- ❌ More complex key management
- ❌ Still uses symmetric for actual data (hybrid)

**Recommendation**: Stick with symmetric unless you have cross-service encryption requirements.

---

## Algorithm Specifications

### Default: AES-256-GCM

### 1. CryptoProvider Trait

```rust
#[async_trait]
pub trait CryptoProvider: Send + Sync {
    async fn encrypt(
        &self,
        key_id: &EncryptionKeyId,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<EncryptedMessage, CryptoError>;

    async fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
    ) -> Result<Vec<u8>, CryptoError>;
}
```

**Default Implementation**: `AesGcmCryptoProvider` using `aes-gcm` crate.

### 2. KeyProvider Trait

```rust
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn get_key(&self, key_id: &EncryptionKeyId)
        -> Result<EncryptionKey, CryptoError>;
    async fn current_key_id(&self) -> Result<EncryptionKeyId, CryptoError>;
    async fn valid_key_ids(&self) -> Result<Vec<EncryptionKeyId>, CryptoError>;
}
```

**Applications Implement**: Integration with Azure Key Vault, AWS Secrets Manager, or custom key stores.

### 3. EncryptedMessage Type

```rust
pub struct EncryptedMessage {
    pub key_id: EncryptionKeyId,        // For key lookup
    pub ciphertext: Vec<u8>,            // Encrypted body
    pub nonce: Nonce,                   // 96-bit nonce
    pub auth_tag: AuthenticationTag,    // 128-bit tag
    pub encrypted_at: i64,              // Unix timestamp
    pub version: u8,                    // Format version
}
```

### 4. Message Flow

**Sending**:

1. Application creates `Message` with plaintext body
2. `QueueClient::send()` checks if crypto enabled in config
3. **If encryption enabled**:
   - Encrypts body using `CryptoProvider`
   - Prepends \"QRE1\" marker to encrypted bytes
   - Logs: `Message sent with encryption (encrypted=true)`
   - Emits metric: `queue_messages_sent{encrypted="true"}`
4. **If encryption disabled** (debug mode):
   - Sends plaintext body without marker
   - Logs WARNING: `Message sent WITHOUT encryption (encrypted=false)`
   - Emits metric: `queue_messages_sent{encrypted="false"}`
5. Sends message to queue (metadata remains cleartext)

**Receiving**:

1. `QueueClient::receive()` retrieves message from queue
2. Checks first 4 bytes for \"QRE1\" encryption marker
3. **If marker present (encrypted message)**:
   - Validates message freshness (timestamp check)
   - Decrypts body using `CryptoProvider`
   - Logs: `Message received with encryption (encrypted=true)`
   - Emits metric: `queue_messages_received{encrypted="true"}`
   - Returns plaintext to application
4. **If no marker (plaintext message)**:
   - Checks `plaintext_policy` configuration:
     - **Allow**: Logs WARNING, processes message
     - **Reject**: Returns error, rejects message
     - **AllowWithAlert**: Logs ERROR, processes message
   - Emits metric: `queue_messages_received{encrypted="false"}`
   - Returns plaintext body as-is (backward compatibility)

**Key Benefits**:

- Encryption/decryption transparent to application code
- Auto-detection enables mixed encrypted/plaintext environments
- Debug mode: Disable encryption on sender, receiver still works
- Metrics and logs enable monitoring of encryption adoption

---

## Security Properties

### Confidentiality

- Message body encrypted with AES-256 (256-bit key strength)
- Ciphertext indistinguishable from random data
- Only parties with correct key can decrypt

### Integrity

- 128-bit authentication tag prevents undetected modification
- Tag covers ciphertext + associated data (message ID, session ID, timestamp)
- Constant-time verification prevents timing attacks

### Authenticity

- Only parties with correct key can create valid encrypted messages
- Authentication tag proves message originated from legitimate sender

### Freshness

- Timestamp included in encrypted message
- Configurable maximum age (default: 5 minutes)
- Rejects messages older than threshold (replay protection)

### Replay Protection

**Timestamp-Based** (Default):

- Simple, stateless, no storage overhead
- Allows replays within freshness window (acceptable for most use cases)

**Nonce Tracking** (Opt-In):

- Tracks used nonces in cache/database
- Strongest replay protection (detects duplicate nonces)
- Opt-in for high-security scenarios

---

## Key Management

### Application Responsibilities

1. **Key Storage**: Store keys in Azure Key Vault, AWS Secrets Manager, or equivalent
2. **Key Rotation**: Rotate keys every 90 days (recommended)
3. **Access Control**: Restrict key access to authorized services
4. **Multi-Environment**: Separate keys for dev/staging/prod

### Library Responsibilities

1. **Key Protection**: Zero key material from memory on drop (using `zeroize` crate)
2. **Logging Safety**: Never log keys, redact in Debug implementations
3. **Multi-Key Support**: Support multiple active keys during rotation
4. **Async Loading**: Async key retrieval from secret stores

### Key Rotation Process

```rust
// 1. Add new key to key provider
key_provider.add_key(new_key);

// 2. Set as current (new messages use this key)
key_provider.set_current(new_key_id);

// 3. Wait for old messages to expire (queue TTL)
tokio::time::sleep(queue_ttl).await;

// 4. Remove old key
key_provider.remove_key(old_key_id);
```

**Zero Downtime**: New messages encrypt with new key, old messages still decrypt with old key.

---

## Configuration

### Crypto Configuration

```rust
pub struct CryptoConfig {
    pub enabled: bool,                   // Default: false (opt-in)
    pub plaintext_policy: PlaintextPolicy, // Default: Allow
    pub max_message_age: Duration,       // Default: 5 minutes
    pub validate_freshness: bool,        // Default: true
    pub track_nonces: bool,              // Default: false (opt-in)
    pub nonce_cache_ttl: Duration,       // Default: 10 minutes
}

pub enum PlaintextPolicy {
    Allow,            // Accept plaintext, log WARNING
    Reject,           // Reject plaintext, return error
    AllowWithAlert,   // Accept plaintext, log ERROR
}
```

### Queue Client Integration

**Production Configuration** (encryption enabled):

```rust
let client = QueueClientBuilder::new()
    .with_azure_provider(config)
    .with_crypto(CryptoConfig {
        enabled: true,
        plaintext_policy: PlaintextPolicy::AllowWithAlert, // Gradual rollout
        max_message_age: Duration::from_secs(300),
        validate_freshness: true,
        ..Default::default()
    })
    .with_key_provider(Arc::new(my_key_provider))
    .build()
    .await?;

// Encryption transparent to application
let msg = Message::new(b"sensitive data".to_vec());
client.send(msg).await?;  // Automatically encrypted with "QRE1" marker

let received = client.receive().await?;  // Automatically decrypted
println!("{}", String::from_utf8_lossy(received.body()));
```

**Debug Configuration** (encryption disabled for troubleshooting):

```rust
let client = QueueClientBuilder::new()
    .with_azure_provider(config)
    .with_crypto(CryptoConfig {
        enabled: false,  // Disable encryption for debugging
        plaintext_policy: PlaintextPolicy::Allow,
        ..Default::default()
    })
    .build()
    .await?;

// WARNING logged on every send: "Message sent WITHOUT encryption"
client.send(msg).await?;  // Sent as plaintext (no marker)

// Receiver still accepts message (plaintext policy: Allow)
let received = client.receive().await?;
// WARNING logged: "Message received WITHOUT encryption"
```

### Observability

**Metrics**:

```rust
// Counters (labeled by encryption status)
queue_messages_sent_total{queue="my-queue", encrypted="true"}
queue_messages_sent_total{queue="my-queue", encrypted="false"}

queue_messages_received_total{queue="my-queue", encrypted="true"}
queue_messages_received_total{queue="my-queue", encrypted="false"}

// Gauge (encryption configuration)
queue_crypto_enabled{queue="my-queue"} = 1.0  // Enabled
queue_crypto_enabled{queue="my-queue"} = 0.0  // Disabled

// Crypto errors
queue_crypto_errors_total{error_type="authentication_failed"}
queue_crypto_errors_total{error_type="key_not_found"}
```

**Alerting**:

```promql
# Alert if >1% of messages unencrypted in production
rate(queue_messages_received_total{encrypted="false"}[5m])
/ rate(queue_messages_received_total[5m]) > 0.01

# Alert if encryption disabled in production
queue_crypto_enabled{environment="production"} == 0
```

---

## Performance Impact

### Encryption Overhead

**AES-256-GCM Performance** (hardware-accelerated):

- Encryption: ~1-2 microseconds per message (typical webhook size)
- Throughput impact: <1% for most workloads
- Hardware acceleration: AES-NI instructions (modern CPUs)

### Optimization Strategies

1. **Batch Encryption**: Parallelize encryption of multiple messages
2. **Hardware Acceleration**: Use AES-NI CPU instructions (automatic in `aes-gcm` crate)
3. **Connection Pooling**: Reuse `CryptoProvider` instances (thread-safe)
4. **Key Caching**: Cache keys in memory to avoid repeated secret store lookups

**Recommendation**: Performance overhead negligible compared to network and queue latency.

---

## Behavioral Assertions

Key behavioral specifications (see [assertions.md](./assertions.md) for complete list):

- **Assertion 24**: Encryption round-trip preserves plaintext
- **Assertion 25**: Tampered messages detected and rejected
- **Assertion 26**: Freshness validation rejects old messages
- **Assertion 27**: Key rotation supports old and new keys simultaneously
- **Assertion 28**: Missing keys produce clear errors
- **Assertion 29**: Nonce tracking prevents replay attacks
- **Assertion 30**: Metadata remains cleartext (session ID, correlation ID)
- **Assertion 31**: Key material zeroed from memory
- **Assertion 32**: Encryption disabled by default (opt-in)
- **Assertion 33**: Algorithm versioning for future upgrades
- **Assertion 34**: Constant-time verification prevents timing attacks

---

## Migration Path

### Phase 1: Opt-In (Current Architecture)

- Crypto disabled by default (`enabled: false`)
- Applications explicitly enable with configuration
- No impact on existing deployments
- Fully backward compatible

### Phase 2: Deprecation Warning (Future)

- Log warnings when crypto disabled in production
- Update documentation recommending crypto for all deployments
- Provide migration guides

### Phase 3: Default Enable (Future)

- Crypto enabled by default (`enabled: true`)
- Applications must explicitly disable (not recommended)
- Requires key provider configuration

### Phase 4: Mandatory (Future, Breaking Change)

- Remove ability to disable crypto
- All messages encrypted (major version bump: 2.0)
- Strongest security posture

---

## Integration Examples

### Multi-Service Architecture Patterns

#### Pattern 1: One Sender, Multiple Receivers with Different Keys

**Scenario**: Webhook router sends to different queues, each receiver has its own encryption key.

```rust
// ===== SENDER SERVICE (Webhook Router) =====

// Create separate clients for each destination queue
async fn setup_sender() -> Result<Vec<QueueClient>> {
    // Client for Service A (uses key-a)
    let client_a = QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-a"))
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(create_key_provider("key-a")))
        .build().await?;

    // Client for Service B (uses key-b)
    let client_b = QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-b"))
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(create_key_provider("key-b")))
        .build().await?;

    // Client for Service C (uses key-c)
    let client_c = QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-c"))
        .with_crypto(CryptoConfig { enabled: true, .. })
        .with_key_provider(Arc::new(create_key_provider("key-c")))
        .build().await?;

    Ok(vec![client_a, client_b, client_c])
}

// Route webhook to appropriate queue
async fn route_webhook(event: WebhookEvent, clients: &[QueueClient]) {
    match event.event_type {
        "pull_request" => clients[0].send(event.into()).await?, // → Service A
        "issue" => clients[1].send(event.into()).await?,        // → Service B
        "push" => clients[2].send(event.into()).await?,         // → Service C
        _ => {}
    }
}

// ===== RECEIVER SERVICES =====

// Service A: Has key-a
async fn service_a_receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-a"))
        .with_key_provider(Arc::new(create_key_provider("key-a")))
        .build().await
}

// Service B: Has key-b
async fn service_b_receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-b"))
        .with_key_provider(Arc::new(create_key_provider("key-b")))
        .build().await
}

// Service C: Has key-c
async fn service_c_receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(azure_config("queue-service-c"))
        .with_key_provider(Arc::new(create_key_provider("key-c")))
        .build().await
}

// Each receiver auto-detects and decrypts with its own key
async fn process_messages(client: &QueueClient) -> Result<()> {
    loop {
        let msg = client.receive().await?;
        // Auto-decrypted if "QRE1" marker present
        // Uses key from this client's KeyProvider
        process(msg.body()).await?;
        client.complete(msg.receipt()).await?;
    }
}
```

**Key Isolation**: Each service has its own encryption key. Compromise of one key doesn't affect other services.

---

#### Pattern 2: Mixed Encryption - Some Queues Encrypted, Others Plaintext

**Scenario**: Production queues encrypted, debug/test queues plaintext.

```rust
// ===== SENDER SERVICE =====

struct QueueRouter {
    prod_client: QueueClient,      // Encrypted
    staging_client: QueueClient,   // Encrypted
    debug_client: QueueClient,     // Plaintext
}

async fn setup_router() -> Result<QueueRouter> {
    // Production: Encryption enforced
    let prod_client = QueueClientBuilder::new()
        .with_azure_provider(azure_config("prod-queue"))
        .with_crypto(CryptoConfig {
            enabled: true,
            plaintext_policy: PlaintextPolicy::Reject,  // Strict
            ..Default::default()
        })
        .with_key_provider(Arc::new(prod_key_provider))
        .build().await?;

    // Staging: Encryption enabled
    let staging_client = QueueClientBuilder::new()
        .with_azure_provider(azure_config("staging-queue"))
        .with_crypto(CryptoConfig {
            enabled: true,
            plaintext_policy: PlaintextPolicy::AllowWithAlert,
            ..Default::default()
        })
        .with_key_provider(Arc::new(staging_key_provider))
        .build().await?;

    // Debug: Encryption disabled (for troubleshooting)
    let debug_client = QueueClientBuilder::new()
        .with_azure_provider(azure_config("debug-queue"))
        .with_crypto(CryptoConfig {
            enabled: false,  // Plaintext messages
            ..Default::default()
        })
        .build().await?;

    Ok(QueueRouter { prod_client, staging_client, debug_client })
}

async fn send_event(router: &QueueRouter, env: Environment, event: Event) {
    match env {
        Environment::Production => {
            // Sends encrypted with "QRE1" marker
            router.prod_client.send(event).await?;
        }
        Environment::Staging => {
            // Sends encrypted with "QRE1" marker
            router.staging_client.send(event).await?;
        }
        Environment::Debug => {
            // Sends plaintext (no marker)
            // Logs WARNING: "Message sent WITHOUT encryption"
            router.debug_client.send(event).await?;
        }
    }
}

// ===== RECEIVER =====

// Receiver auto-detects both encrypted and plaintext
async fn receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_key_provider(Arc::new(key_provider))
        .build().await
}

async fn process_loop(client: &QueueClient) {
    loop {
        let msg = client.receive().await?;

        // Auto-detection:
        // - If "QRE1" present → decrypts
        // - If no marker → plaintext (logs WARNING)

        println!("Received: {}", String::from_utf8_lossy(msg.body()));
        client.complete(msg.receipt()).await?;
    }
}
```

**Flexibility**: Production enforces encryption, debug allows plaintext for troubleshooting.

---

#### Pattern 3: Zero-Configuration Receiver (Auto-Detection Only)

**Scenario**: Receiver doesn't know sender's encryption status, handles both automatically.

```rust
// ===== RECEIVER SERVICE =====

// Receiver handles both encrypted and plaintext automatically
async fn universal_receiver() -> Result<QueueClient> {
    QueueClientBuilder::new()
        .with_azure_provider(config)
        .with_crypto(CryptoConfig {
            // Note: enabled not specified here, just provide key provider
            plaintext_policy: PlaintextPolicy::Allow,  // Accept both
            ..Default::default()
        })
        .with_key_provider(Arc::new(key_provider))
        .build().await
}

async fn process_messages(client: &QueueClient) {
    loop {
        let msg = client.receive().await?;

        // Library checks first 4 bytes automatically:
        // [Q][R][E][1] → encrypted, decrypt with key_provider
        // [anything else] → plaintext, log warning

        // Application just uses plaintext body
        let body = msg.body();
        process_event(body).await?;

        client.complete(msg.receipt()).await?;
    }
}

// ===== MULTIPLE SENDERS (Mixed) =====

// Sender 1: Encrypted
let sender1 = QueueClientBuilder::new()
    .with_azure_provider(config)
    .with_crypto(CryptoConfig { enabled: true, .. })
    .with_key_provider(key_provider)
    .build().await?;

sender1.send(msg).await?;  // Sends: [Q][R][E][1][encrypted_data]

// Sender 2: Plaintext (debug)
let sender2 = QueueClientBuilder::new()
    .with_azure_provider(config)
    .with_crypto(CryptoConfig { enabled: false, .. })
    .build().await?;

sender2.send(msg).await?;  // Sends: [raw_data]

// Receiver handles both correctly without configuration changes
```

**Key Benefit**: Receiver doesn't need coordination with sender. Detection is message-based, not config-based.

---

### Key Management Per Service

Each service accesses its own key from secret store:

```rust
// Service A: Key from Azure Key Vault
pub struct ServiceAKeyProvider {
    vault_client: KeyvaultClient,
}

impl KeyProvider for ServiceAKeyProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey> {
        // Loads "service-a-encryption-key" from vault
        let secret = self.vault_client
            .get_secret("service-a-encryption-key")
            .await?;
        let key_bytes = base64::decode(secret.value())?;
        Ok(EncryptionKey::from_bytes("service-a-key", &key_bytes))
    }

    async fn current_key_id(&self) -> Result<EncryptionKeyId> {
        Ok(EncryptionKeyId::new("service-a-key"))
    }
}

// Service B: Key from AWS Secrets Manager
pub struct ServiceBKeyProvider {
    secrets_client: SecretsManagerClient,
}

impl KeyProvider for ServiceBKeyProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId) -> Result<EncryptionKey> {
        // Loads "service-b-encryption-key" from secrets manager
        let response = self.secrets_client
            .get_secret_value()
            .secret_id("service-b-encryption-key")
            .send()
            .await?;
        let key_bytes = response.secret_binary().unwrap();
        Ok(EncryptionKey::from_bytes("service-b-key", key_bytes.as_ref()))
    }

    async fn current_key_id(&self) -> Result<EncryptionKeyId> {
        Ok(EncryptionKeyId::new("service-b-key"))
    }
}
```

**Isolation**: Each service's IAM role/managed identity only has access to its own key in the secret store.

---

### Multi-Service Security Model

```
                    ┌──────────────────────────────────┐
                    │   Azure Key Vault / AWS Secrets  │
                    │   key-a │ key-b │ key-c          │
                    └────┬─────────┬─────────┬─────────┘
                         │         │         │
     ┌───────────────────┼─────────┼─────────┼────────────────┐
     │ Webhook Router (Sender Service)                         │
     │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
     │  │ QueueClient  │  │ QueueClient  │  │ QueueClient  │ │
     │  │ + key-a      │  │ + key-b      │  │ + key-c      │ │
     │  │ (encrypts)   │  │ (encrypts)   │  │ (encrypts)   │ │
     │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
     └─────────┼──────────────────┼──────────────────┼────────┘
               │                  │                  │
               │ [QRE1+data]      │ [QRE1+data]      │ [QRE1+data]
               ↓                  ↓                  ↓
          ┌─────────┐        ┌─────────┐        ┌─────────┐
          │ Queue A │        │ Queue B │        │ Queue C │
          │(PR events)       │(issues)  │        │(pushes) │
          └────┬────┘        └────┬────┘        └────┬────┘
               │                  │                  │
               ↓                  ↓                  ↓
     ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
     │ Task Tactician   │  │ Merge Warden     │  │ Spec Sentinel    │
     │ (Receiver)       │  │ (Receiver)       │  │ (Receiver)       │
     │ + key-a          │  │ + key-b          │  │ + key-c          │
     │ (decrypts)       │  │ (decrypts)       │  │ (decrypts)       │
     └──────────────────┘  └──────────────────┘  └──────────────────┘
               ↑                  ↑                  ↑
               └──────────────────┼──────────────────┘
                                  │
                    ┌─────────────┴──────────────┐
                    │ Shared Secret Store Access │
                    │ (via IAM roles/identities) │
                    └────────────────────────────┘
```

**Security Properties**:

- **Sender** (webhook router): Receives GitHub webhooks, encrypts messages for each queue with appropriate key
- **Receivers** (bot services): Each retrieves its queue's key from shared secret store
- **Key Isolation**: Each queue has unique encryption key
- **Compromise Isolation**: Compromise of one key doesn't affect other queues
- **Trusted Boundary**: All services trust each other (same organization/deployment)
- **IAM Controls**: Access to keys controlled by Azure AD/AWS IAM roles
- **Auto-Detection**: Receivers auto-detect encrypted messages (no coordination needed)

**Why Symmetric Works Here**:

- Webhook router and bot services are all **trusted** (your services)
- All authenticate to same secret store using managed identities/IAM roles
- Key sharing is **within trusted boundary**, not across organizations
- Much simpler than asymmetric PKI infrastructure
- Better performance for high-throughput webhook processing

---

## Summary: Multi-Service Capabilities

### ✅ Supported Scenarios

1. **Multiple Keys Per Sender**:
   - ✅ Create separate `QueueClient` instances with different `KeyProvider`s
   - ✅ Each destination queue can have its own encryption key
   - ✅ Sender manages multiple clients, routes messages appropriately

2. **Mixed Encryption**:
   - ✅ Some `QueueClient` instances with `enabled: true` (encrypted)
   - ✅ Some `QueueClient` instances with `enabled: false` (plaintext)
   - ✅ Same sender can use both patterns for different queues

3. **Receiver Auto-Detection**:
   - ✅ Receiver checks first 4 bytes for "QRE1" marker
   - ✅ No configuration needed on receiver about sender's encryption status
   - ✅ Handles both encrypted and plaintext messages automatically
   - ✅ Logs and metrics distinguish encrypted vs plaintext

### 🔑 Key Design Benefits

- **Message-Based Detection**: Encryption status embedded in message (marker), not configuration
- **No Coordination Needed**: Receiver doesn't need to know sender's config
- **Per-Queue Encryption**: Each queue can have different encryption settings
- **Key Isolation**: Each service can have its own encryption key
- **Gradual Rollout**: Can enable encryption queue-by-queue, service-by-service
- **Debug Friendly**: Can disable encryption temporarily without breaking receivers

---

## Integration Examples (continued)

### With Azure Key Vault

```rust
pub struct AzureKeyVaultProvider {
    client: KeyvaultClient,
    vault_name: String,
}

#[async_trait]
impl KeyProvider for AzureKeyVaultProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId)
        -> Result<EncryptionKey, CryptoError> {
        let secret = self.client.get_secret(key_id.as_str()).await?;
        let key_bytes = base64::decode(secret.value())?;
        Ok(EncryptionKey::from_bytes(key_id.as_str(), &key_bytes))
    }

    async fn current_key_id(&self) -> Result<EncryptionKeyId, CryptoError> {
        let current = self.client
            .get_secret_metadata("current-encryption-key")
            .await?;
        Ok(EncryptionKeyId::new(current))
    }
}
```

### With AWS Secrets Manager

```rust
pub struct AwsSecretsManagerProvider {
    client: SecretsManagerClient,
    secret_prefix: String,
}

#[async_trait]
impl KeyProvider for AwsSecretsManagerProvider {
    async fn get_key(&self, key_id: &EncryptionKeyId)
        -> Result<EncryptionKey, CryptoError> {
        let secret_name = format!("{}/{}", self.secret_prefix, key_id.as_str());
        let response = self.client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await?;
        let key_bytes = response.secret_binary().unwrap();
        Ok(EncryptionKey::from_bytes(key_id.as_str(), key_bytes.as_ref()))
    }
}
```

---

## Dependencies

### New Crate Dependencies

- **`aes-gcm`**: AES-GCM authenticated encryption (hardware-accelerated)
- **`zeroize`**: Secure memory zeroing for key material
- **`rand`**: Cryptographically secure random number generation (nonces)
- **`subtle`**: Constant-time comparison functions (timing attack prevention)

### Optional Dependencies

- **`azure-security-keyvault`**: Azure Key Vault integration (example implementation)
- **`aws-sdk-secretsmanager`**: AWS Secrets Manager integration (example implementation)

---

## Testing Strategy

### Unit Tests

- Encryption/decryption round-trip
- Tampering detection (ciphertext, auth tag, associated data)
- Freshness validation
- Key rotation scenarios
- Error handling (missing keys, expired messages, unsupported versions)

### Integration Tests

- Encrypted messages through queue (send → receive)
- Key provider integration (Azure Key Vault, AWS Secrets Manager)
- Performance benchmarks (throughput with encryption enabled)

### Contract Tests

- Crypto behavior consistent across providers (Azure, AWS, in-memory)
- Encrypted messages portable between environments

---

## Constraints Summary

From [constraints.md](./constraints.md):

- Keys MUST be zeroed from memory on drop
- Keys MUST NEVER be logged (even in debug/trace)
- Debug implementations MUST redact key material
- Use constant-time comparison for cryptographic verification
- Default to AES-256-GCM (FIPS 140-2 approved)
- Nonce generation MUST use cryptographically secure RNG
- Authentication tag verification before returning plaintext
- Support key rotation without service interruption
- Timestamp-based freshness validation configurable
- Encrypted message format includes version field

---

## Next Steps for Interface Designer

The architecture is complete. Interface designer should:

1. **Define Concrete Types**:
   - `EncryptionKeyId`, `Nonce`, `AuthenticationTag` types
   - `EncryptedMessage` struct with serialization
   - `EncryptionKey` with `zeroize` integration

2. **Create Trait Definitions**:
   - `CryptoProvider` trait with encrypt/decrypt operations
   - `KeyProvider` trait with key retrieval operations

3. **Define Error Types**:
   - `CryptoError` enum (EncryptionFailed, AuthenticationFailed, KeyNotFound, MessageExpired, UnsupportedVersion)
   - Error context for debugging

4. **Integration Points**:
   - Update `QueueClient::send()` to encrypt messages when crypto enabled
   - Update `QueueClient::receive()` to decrypt messages when crypto enabled
   - Add `CryptoConfig` to `QueueClientConfig`
   - Add `key_provider` field to `QueueClientBuilder`

5. **Generate Stubs**:
   - `src/crypto.rs`: Module with types and traits
   - `src/crypto_tests.rs`: Test file structure
   - `src/providers/aes_gcm.rs`: Default crypto provider implementation
   - Update `src/client.rs` with crypto integration points

6. **Documentation**:
   - Rustdoc for all public crypto types and traits
   - Examples showing encryption setup
   - Security considerations in module docs

---

## Summary

This architecture provides production-grade MITM protection for queue-runtime:

✅ **Confidentiality**: AES-256 encryption protects message content
✅ **Integrity**: Authentication tags prevent tampering
✅ **Authenticity**: Only parties with keys can create valid messages
✅ **Freshness**: Timestamp validation prevents replay attacks
✅ **Transparency**: Automatic encryption/decryption, no API changes
✅ **Flexibility**: Application-provided keys via KeyProvider abstraction
✅ **Performance**: Minimal overhead (<1% throughput impact)
✅ **Migration**: Opt-in, backward compatible, clear upgrade path
✅ **Compliance**: FIPS 140-2, GDPR, PCI DSS, HIPAA ready

The design follows clean architecture principles:

- Business logic (cryptography) separated from infrastructure (key storage)
- Dependency inversion (library depends on KeyProvider abstraction)
- Type safety (branded types for key IDs, nonces, tags)
- Production-ready (comprehensive error handling, testing, observability)

Architecture complete and ready for interface design phase.
