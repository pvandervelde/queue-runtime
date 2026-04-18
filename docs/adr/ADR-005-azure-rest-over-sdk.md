# ADR-005: Azure Service Bus — REST API Transport Over Azure SDK

**Status**: Accepted
**Date**: 2026-04-18
**Deciders**: queue-runtime maintainers

---

## Context

`docs/spec/modules/azure.md` states:

> Azure Service Bus SDK for message operations (send, receive, complete, abandon, dead letter)

The natural interpretation is the official [`azure_servicebus`](https://crates.io/crates/azure-servicebus)
(or equivalent) crate, which is backed by AMQP and first-class Azure SDK support.

When implementing the Azure provider the following constraints were encountered:

1. **No stable Rust SDK for Service Bus**: The Rust Azure SDK (`azure_sdk_for_rust`) provides
   crates for storage, identity, and messaging foundations, but no production-ready
   `azure_servicebus` crate that encapsulates the session receiver lifecycle. The equivalent
   Java/C#/Python SDKs are not Rust-native.

2. **AMQP complexity**: Using raw AMQP (via `lapin` or `fe2o3-amqp`) to replicate the
   session-accept lifecycle would require implementing the Azure AMQP CBS (Claim-Based Security)
   token refresh protocol, session filter links, and management link operations from scratch —
   substantially more complexity than the REST API.

3. **REST API covers all required operations**: Azure Service Bus exposes a well-documented
   REST API over HTTPS that supports all operations specified in the interface:
   send, receive (PeekLock), complete, abandon, dead-letter, session receive, and lock renewal.

---

## Decision

Implement the Azure Service Bus provider using the Azure Service Bus **REST API** over HTTPS
(via `reqwest`) rather than a native AMQP SDK client.

### Consequences

**Positive**

- No dependency on an unstable or unavailable Rust Azure SDK crate.
- Straightforward HTTP transport that is easy to test (mock HTTP responses, inspect requests).
- All required operations are covered by the REST API.
- Simpler dependency tree; consistent with the approach used by the AWS SQS provider.

**Negative / Limitations**

- **Throughput**: REST/HTTP has higher per-request overhead than AMQP's multiplexed binary
  framing. For high-throughput workloads (thousands of messages/second), the AMQP SDK is
  preferred if a stable Rust crate becomes available.

- **Session accept without explicit ID**: The Azure REST API uses the
  `DELETE …/sessions/$acceptnext/messages/head` endpoint to atomically acquire the next
  available session. This is an undocumented-but-stable shorthand; the AMQP SDK exposes
  this as `AcceptNextSessionAsync()`. If the broker stops honouring `$acceptnext` this
  call will fail with a 404 or 400.

- **Session lock release**: The REST API provides no explicit endpoint to release a session
  lock before it expires. Callers must either let the lock expire naturally (safe but slow
  hand-off) or configure a short session lock duration on the queue entity. `close_session()`
  clears only the local lock-token cache.

- **Message lock duration**: The REST API returns no field indicating the broker's configured
  message lock duration. `ReceiptHandle::expires_at` is set to `Utc::now() + session_timeout`
  as a conservative estimate. Applications must not rely on this value for precise
  scheduling.

### Spec Alignment

The spec requirement ("use the Azure Service Bus SDK") is satisfied in intent — all
SDK-documented operations are implemented. The transport layer is REST rather than AMQP,
which is an implementation detail not visible to trait consumers.

When a stable, production-quality Rust AMQP SDK for Azure Service Bus becomes available,
the `AzureServiceBusProvider` and `AzureSessionProvider` can be refactored to use it
without changing any public API. The migration path is to replace the `reqwest` call sites
inside those structs while keeping the `QueueProvider` / `SessionProvider` trait impls
unchanged.

---

## Alternatives Considered

| Option | Reason not chosen |
|---|---|
| `azure_servicebus` crate (hypothetical) | Does not exist as a stable Rust crate |
| Raw AMQP via `fe2o3-amqp` | Requires implementing CBS auth, session filter links, management links — disproportionate complexity |
| Raw AMQP via `lapin` (RabbitMQ-focused) | Not compatible with Azure AMQP extensions |
| Blocking/synchronous HTTP | Violates ADR-003 (async-first) |

---

## References

- `docs/spec/modules/azure.md` — Core requirements
- `docs/spec/assertions.md` — Assertion 7 (session ordering)
- ADR-003: Async-first design
- ADR-004: Runtime provider selection
- Azure Service Bus REST API: <https://learn.microsoft.com/en-us/rest/api/servicebus/>
- GHSA-965h-392x-2mh5, GHSA-xgp8-3hg3-c2mh (rustls-webpki advisories patched in Cargo.lock)
