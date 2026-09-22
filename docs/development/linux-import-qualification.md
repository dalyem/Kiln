# Linux import qualification evidence

KILN-25 implementation qualification passed on 2026-09-22. The checks below do not
qualify Linux provisioning on real Proxmox. KILN-26 owns that separate lab run.

## Local HTTP and historical database check

On 2026-09-22, the lead restored the completed BIOS qualification database into
disposable local PostgreSQL. Migration 0008 was applied twice. Row counts and
SHA-256 checksums of every row in all 23 historical tables remained unchanged.
The restored installation retained its completed run, ten completed phases and
explicit retained pool allocation.

A real HTTP client streamed the signed development disk through the Linux
staging endpoint. Core verified the staged image and signed raw build metadata,
then created a Linux import intent using the restored pool ownership history.
The injected provider rejected all calls; no provider call occurred.

- Artifact size: 1,686,634,496 bytes.
- Artifact SHA-256: `db9d5ed652fffb94d002e605433b61b17cffb0b8c45dcc9c21e2ce357ea02cd1`.
- Peak process RSS: 203,276 KiB, approximately 199 MiB.
- Unauthorized upload: denied before staging a file.
- Repeated import request: same run ID, HTTP 200 replay.
- Reloaded PostgreSQL plan: canonical digest matched.
- Staging and run responses: no private server path.
- Phase journal: empty, because this check intentionally performed no provider operation.

The initial staging directory under `~/.local` was rejected because its
ancestors were group-writable. The successful check used a private directory
under root-owned sticky `/tmp`. No existing directory permissions were changed.

The BIOS Core service, BIOS provider, BIOS parser and Linux image build recipe
matched their pre-task checksums after this check.

Private logs and the local test driver are under
`/home/daly/.local/state/kiln/kiln25-6yd7k0oz`. The upload directory is
`/tmp/kiln-large-ingress-6yd7k0oz`. These are qualification evidence, not release
artifacts or appliance configuration.

## Core lifecycle and restart check

A second isolated database was restored from the same historical backup. The
lead created a Linux import through `LinuxImageImportService` using the real
staged image and a local provider receipt fixture, then called `advance` through
all nine phases. The PostgreSQL store and Core service were recreated after
each completed phase, followed by installation recovery.

The run completed with exactly nine provider dispatches and nine inspections.
Both resource records became `DESTROYED`; template and clone disk allocations
became `DESTROYED`; the staging allocation remained `RETAINED`. This exercises
Core's ownership and phase-order checks, not only the store's update methods.
It does not exercise PVE HTTP requests, guest boot or in-flight task recovery.

Evidence is in `core-lifecycle-evidence.json` and `core-lifecycle.log` under the
private qualification directory above.

## Final regression and review

The final PostgreSQL-enabled run passed all 286 tests in 30 files with
`npm test -- --maxWorkers=2`. The full `npm run build` passed. An unrestricted
test run concurrent with the build hit three existing five-second database test
timeouts; the bounded run used unchanged source and passed all tests.

Coverage includes 17 Linux provider HTTP fixture tests, ten staging tests,
16 Core service tests and four PostgreSQL journal tests. Recovery tests cover
saved receipts, missing receipts, deadlines, uncertain outcomes, corrupted
proofs and per-run isolation. Explicit PostgreSQL reopen checks confirm unknown
import and clone destruction quarantine the affected resource and retain UNKNOWN
allocation state. Independent review found no remaining material findings.

A second actual 1.6 GiB HTTP upload verified idempotent staging, sanitized status
and persisted staging-requested/completed audit events. Its private evidence
check initially queried the wrong event column; a corrected database query
verified both events. No PVE calls occurred. All four protected source hashes
still matched after final verification.

KILN-85 qualifies the contributor Compose stack separately. Real PVE import,
guest boot, networking, workspace transport and preview routing are not claimed
here. The KILN-26 nested run completed import, boot, restart recovery, and cleanup;
see [Linux PVE qualification](linux-pve-qualification.md).
