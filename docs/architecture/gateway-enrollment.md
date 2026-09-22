# Gateway enrollment implementation contract

This slice implements authenticated process identity and telemetry, not provisioning, routing, policy enforcement, workload probes or Core HA. Proxmox remains read-only. Existing lab VMs remain external. The transport is outbound HTTPS JSON with a separate strict mTLS heartbeat listener; the future workload command protocol remains separate.

## Protocol v1

Management routes use the existing infrastructure credential. `POST /v1/gateways/:id/enrollment-token` returns `{installationId, resourceId, generation, token, expiresAt}` for an existing owned gateway. `GET /v1/gateways/:id/identity` returns a redacted identity/heartbeat summary. `POST /v1/gateways/:id/revoke-identity` revokes that generation's identity. Issuance and revocation are audited, atomic and serialized with gateway admission. Issuance never creates or adopts a provider resource.

Enrollment and recovery run on a server-authenticated HTTPS listener. Heartbeat runs on another TLS listener with client certificates required and verified. Neither accepts forwarded certificate headers. Clients verify a configured trust root and hostname, require TLS 1.3, disable redirects, and never accept replacement trust roots from a response.

| Path | Request | Response |
| --- | --- | --- |
| `POST /v1/gateway/enroll` | `{installationId,resourceId,generation,token,publicKeyPem,signature}` | `{deviceId,certificatePem,certificateExpiresAt,nextSequence}` |
| `POST /v1/gateway/challenge` | `{deviceId}` | `{challengeId,nonce,expiresAt}` |
| `POST /v1/gateway/renew` | `{deviceId,challengeId,nonce,signature}` | Same certificate response as enrollment |
| `POST /v1/gateway/heartbeat` | `{deviceId,sequence,services,policy,reservation}` | `{accepted:true,nextSequence}` |

`services`, `policy` and `reservation` are `PASS`, `FAIL` or `UNKNOWN`. Sequence numbers range from 1 through 2147483646. The heartbeat timestamp comes from Core. Device samples never supply provider ownership, VM configuration attestation or canary success. Go reports policy/reservation UNKNOWN in this slice; configured local service checks are read-only observations, not proof of firewall rules.

Keys are ECDSA P-256; public keys use canonical PKIX/SPKI PEM. Signatures are base64-encoded ASN.1 ECDSA signatures over SHA-256 of UTF-8 text. Each text below has newline separators and no final newline. Validate bounded fields and reject newline/control characters in identifiers. No untrusted CSR subjects or extensions are parsed.

Enrollment proof lines: `kiln-gateway-enroll-v1`, installationId, resourceId, generation, token, lowercase hex SHA-256 of canonical public-key SPKI DER.

Renewal proof lines: `kiln-gateway-renew-v1`, installationId, resourceId, generation, deviceId, challengeId, nonce.

Core assigns certificate subject, URI SAN, clientAuth usage and lifetime. Defaults: enrollment token 10 minutes, certificate 24 hours, renewal after 12 hours, challenge 60 seconds, heartbeat every 5 seconds, stale heartbeat after 30 seconds. Certificate dates use whole seconds. Core rejects enrollment when the issuer cannot cover the full configured leaf lifetime. Test clocks/lifetimes may be injected; clients do not select certificate validity.

## Persistence and recovery

Store only a hash of the random 256-bit bootstrap token. Bind it to installation, gateway and generation. Consume it atomically with identity/certificate registration and an event. Narrow replay permits retrieving exactly the same certificate for the same still-unexpired token and proven public key; it never creates another identity, renews validity or permits a different key. This handles a lost enrollment response. Outside that window, fail closed and require explicit administrative recovery.

A still-authorized device may renew after its leaf certificate expires by signing a fresh server challenge with its previously enrolled key. Bind the single-use challenge to the identity, generation and renewal purpose. Repeated challenge requests return the same pending challenge until it expires, rather than invalidating an in-flight proof. At most one pending challenge exists per identity. Consuming it and registering the new certificate/event are atomic. Kiln retains at most one previous certificate for the shorter of its expiry or a 10-minute renewal-response grace period. A later renewal removes an older previous certificate. Revocation, a changed generation, quarantine or ownership failure rejects both certificates. Same-key renewal only; rekeying is deferred.

Every heartbeat and renewal rechecks current installation, resource ownership/state, gateway generation, identity and revocation/quarantine. Token issuance/enrollment also inspect independent provider ownership. Unknown, external, retired or quarantined resources cannot gain device authority. A copied valid client certificate alone does not establish provider ownership.

The CA private key is an explicit private file in Core, never passed to a gateway. Bind its certificate fingerprint to the installation durably; fail startup on mismatch. Do not silently generate a replacement CA during restart. TLS server identity and gateway-issuing CA have separate purposes. Production CA rotation and HA secret replication are later qualification work.

Go `kilnd gateway --config <path>` reads explicit enrollment and heartbeat HTTPS base URLs, server CA path, installation/resource/generation, a bootstrap-token file and a private state directory. It persists its key before enrollment and its certificate/device/sequence state atomically with restrictive permissions. It survives interrupted responses and restarts without silently changing keys. It uses bounded request timeouts and reconnect backoff, and opens no administrative listener. Never put tokens on the command line or in logs.

## Monitoring and proof

Authenticated identity state is a separate input to the monitor. It cannot replace provider configuration evidence or workload probes. Enabling enrollment for a fake gateway must stop trusting simulated heartbeat success. Until independent probes exist, enrolled gateways cannot claim complete network readiness from telemetry alone. Doctor exposes identity and heartbeat status without secrets and preserves existing provider/quarantine holds.

Tests must exercise actual TLS and Go-to-Core interoperability, token/nonce replay, wrong keys/generations/installations, untrusted or expired certificates, revocation on existing connections, stale samples, certificate expiry and recovery, atomic audit failures, PostgreSQL restart persistence, and Core restart followed by automatic reconnection. A first enrollment outage that outlives the token requires an administrator to issue a replacement token. No real Proxmox mutations are authorized by this contract.
