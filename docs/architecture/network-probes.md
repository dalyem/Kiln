# Temporary network probes

## Problem and scope

A gateway heartbeat identifies a process, but cannot prove what a workload can reach. Add a short-lived diagnostic job intended to run as `kilnd probe` on the workload network. This slice cannot verify where that process actually ran. Core stores its plan, receipt and result, then cleans up its recorded resource through the existing ownership boundary.

This slice supports fake compute placement and real Go network checks against controlled test endpoints. It does not create Proxmox VMs, adopt the external lab fixtures, qualify network isolation, set the gateway canary to PASS or unblock workload admission. Real gateway/probe provisioning follows a durable provider task journal, image provenance and independent VM/NIC placement checks. Those prerequisites cannot be bypassed by enabling a flag on the read-only provider.

## Options and decision

- Gateway-local checks are cheap but test the router's path, not a workload's path. Keep them separate.
- A temporary probe with a narrowly scoped report token gives a complete diagnostic path without sharing gateway identity. Use this now.
- A probe-specific mTLS identity plus real VM provisioning would also require image distribution, attachment provenance and unknown-task recovery. Build that after the diagnostic contract is tested.

The report token proves possession of a bootstrap secret, not VM placement. Results therefore remain diagnostic. Profiles are operator-configured in Core; requesters select a profile ID and cannot supply destinations, commands or scripts.

## Profile and wire contract v1

Core loads an explicit array of profiles from `KILN_PROBE_PROFILES_FILE`. No profiles means no available probe jobs; there is no automatic network scan. Validate the complete configuration at startup and reject duplicates/unknown fields. A profile has `{id, ttlSeconds, checks}`; IDs match `[a-zA-Z0-9_-]{1,64}`, TTL is 60..600 seconds, and there are 1..8 uniquely named checks. Each timeout is 100..5000 ms; combined check budgets cannot exceed 30000 ms.

Checks are one of:

- `{id, kind:"dns", hostname, resolverAddress, resolverPort, timeoutMs}`. Resolver is an explicit IP address, port 1..65535. Resolve IPv4 A records through that resolver, without system fallback.
- `{id, kind:"https", url, expectedStatus, caPem?, timeoutMs}`. HTTPS only, port must be valid, no URL credentials, query, fragment or redirects. Use verified server certificates and optional operator-provided public CA PEM. `caPem` must contain exactly one parseable public certificate, never a private key or other PEM block. No proxy environment. Validate response headers/status and close the body without reading it. Expected status is 200..299; content validation is outside this check.
- `{id, kind:"tcp", address, port, expect:"reachable"|"blocked", timeoutMs}`. Target is an explicit IP, never a hostname. This is a single connection, not a port scan. A failed connection to a blocked target is UNKNOWN: failure to connect does not prove isolation.

The plan is `{schemaVersion:1, probeId, installationId, gatewayId, gatewayGeneration, gatewayConfigFingerprint, profileId, profileDigest, expiresAt, checks}`. Hash canonical normalized profile JSON with SHA-256; bind the complete plan with `planDigest`. gatewayConfigFingerprint is the recorded gateway metadata.expectedFingerprint, not a device-certificate fingerprint. Digests are opaque to the Go client: it echoes the received planDigest without independently reserializing the plan.

Management API, infrastructure credential for mutations:

- `POST /v1/gateways/:id/probes`, `{profileId}`, required `Idempotency-Key`: creates one `network_probe` resource and durable job on the gateway's recorded node. Fake provider only. Ordinary workload admission does not block this diagnostic-only creation. Ownership, generation and node checks still apply. Duplicate requests return the same record and never recreate infrastructure.
- `POST /v1/network-probes/:id/token`: issues/replaces a random 256-bit token for a pending live job, valid no longer than its job expiry. Store only its SHA-256 hash, never log it. Rotation does not extend the job.
- `GET /v1/network-probes/:id`: returns the plan and redacted job/result. No token hashes or raw secrets.

The existing server-authenticated HTTPS enrollment listener also serves these probe routes; probes never reuse gateway certificates:

- `GET /v1/probes/:id/plan`, bearer token: returns `{plan, planDigest}`.
- `POST /v1/probes/:id/result`, bearer token: accepts `{planDigest, results:[{id, code, durationMs}]}` and returns `{accepted:true, probeId, resultDigest}`.

Result codes: `DNS_ANSWER`, `DNS_EMPTY`, `DNS_ERROR`, `HTTPS_EXPECTED`, `HTTPS_UNEXPECTED`, `HTTPS_REDIRECT`, `HTTPS_ERROR`, `TCP_CONNECTED`, `TCP_FAILED`, `TIMEOUT`. Require exactly one result for each planned check, no extra IDs, compatible codes, integer duration 0..30000 and bounded request sizes. Core derives PASS/FAIL/UNKNOWN from each code and the profile; a client cannot declare readiness. TIMEOUT and blocked-target TCP failure are UNKNOWN. A completed diagnostic with FAIL/UNKNOWN observations is still a completed job.

| Check | PASS | FAIL | UNKNOWN |
| --- | --- | --- | --- |
| DNS | `DNS_ANSWER` | `DNS_EMPTY`, `DNS_ERROR` | `TIMEOUT` |
| HTTPS | `HTTPS_EXPECTED` | `HTTPS_UNEXPECTED`, `HTTPS_REDIRECT`, `HTTPS_ERROR` | `TIMEOUT` |
| TCP reachable | `TCP_CONNECTED` | `TCP_FAILED` | `TIMEOUT` |
| TCP blocked | none | `TCP_CONNECTED` | `TCP_FAILED`, `TIMEOUT` |

| Code | Core diagnostic outcome |
| --- | --- |
| DNS_ANSWER, HTTPS_EXPECTED | PASS |
| DNS_EMPTY, DNS_ERROR, HTTPS_UNEXPECTED, HTTPS_REDIRECT, HTTPS_ERROR | FAIL |
| TCP_CONNECTED with reachable expectation | PASS |
| TCP_CONNECTED with blocked expectation | FAIL |
| TCP_FAILED with reachable expectation | FAIL |
| TCP_FAILED with blocked expectation, TIMEOUT | UNKNOWN |

Tokens and results are bound to the stored installation, probe resource, gateway generation/configuration, node, profile and plan. Recheck current resource ownership and gateway binding before accepting a new result. Changed ownership, generation, profile, expiry or a stopped/deleted resource denies new reports. A matching already-saved report may return its original acknowledgement before credential expiry, without adding another event or changing evidence. For this historical replay only, check the token and current gateway/profile binding before returning the saved acknowledgement, but do not require the already-cleaned-up probe resource to remain alive. A different report is a conflict. This replay never authorizes a provider operation.

## Persistence, lifecycle and safety

Add a `network_probes` table linked to `resources`; retain plan, profile digest, job state, token hash/expiry, report digest/results and Core receipt time. Job states are PENDING, COMPLETED, TIMED_OUT, INVALIDATED and CANCELLED. Resource lifecycle remains separate. A creation intent and audit record must be durable before the provider is called. A partial/uncertain create is never retried as a new VM. PostgreSQL transactions and per-job locks make report acceptance and its event atomic. Mirror that atomic visibility in MemoryStore.

`network_probe` is not allowed through generic resource creation. Its targeted diagnostic creation does not confer gateway or workload authority. Existing generic ownership-checked stop/destroy can retire it. NetworkProbeService owns expiry and is always constructed, even when profiles or TLS listeners are disabled; generic ResourceService.expire skips network probes. A periodic probe cleanup pass marks expired pending jobs TIMED_OUT and calls the same guarded ResourceService destruction for completed or expired jobs. Completed jobs are eligible for guarded cleanup immediately after their report; their persisted report remains available for the narrow identical acknowledgement replay. Missing provider observation, changed tags or an uncertain operation leaves cleanup pending or quarantined; never claim deletion. Every cleanup begins at the exact persisted resource record. Report acceptance takes the same resource-ID lock as generic lifecycle mutation. Cleanup records the terminal job under that lock, releases it, then invokes the normal guarded mutation path; terminal jobs reject new reports. This avoids a nested acquisition of the same lock.

Every redacted job/result and doctor summary includes `placement: "UNVERIFIED"`. Doctor must identify results as diagnostic-only with unverified origin, even when all individual checks pass. Doctor adds diagnostic probe checks: pending, result summary, stale or timed out. A PASS diagnostic cannot clear existing holds, quarantine or canary UNKNOWN. Completed evidence is current only until the earlier of job expiry and 30 seconds after Core receipt, and becomes stale immediately on binding drift. Preserve completed reports as historical data after that window. Core receipt time and stored binding determine freshness; guest timestamps are not trusted. A missing report is a probe timeout, not proof that the gateway or Internet failed.

## Go client

`kilnd probe --config <path>` is a one-shot outbound client. Configuration is `{coreUrl, serverCaFile, probeId, tokenFile}`. Token files must be private regular files; never put tokens in argv. Require HTTPS/TLS 1.3, verified hostname/root, bounded responses, no proxy environment or redirects. Fetch the immutable plan, execute checks serially within their total budget, and submit one bounded report. Retry only the same report bytes within the deadline. Do not rerun checks to replace a lost acknowledgement. Open no administrative listener and never execute shell commands. A restart can safely fail; automatic crash replay is deferred.

## Verification and rollout

Use fake providers to test creation/idempotency, generation and ownership mismatch, external cleanup denial, token expiry/rotation, concurrent identical/conflicting reports, audit rollback, TTL cleanup and diagnostic-only admission. Use real local DNS, HTTPS and TCP servers for Go checks, redirect denial, bad TLS roots, timeouts and bounded output. A permanent opt-in PostgreSQL + actual Go-to-Core TLS test must prove report persistence across Core/store restart and unchanged admission holds. No public endpoint or Proxmox cluster is required.

Rollback disables profiles and probe scheduling while retaining persisted reports and guarded cleanup. Additive migration introduces no resource adoption or infrastructure writes. Backup/restore and replicated Core remain separate milestones.
