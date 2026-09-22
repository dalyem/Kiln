# Workspace qualification

The local Development Lease workspace increment was qualified on Linux on
2026-09-21. It reconstructs Git working state through the compiled `kiln` and
`kilnd` commands. It does not yet transfer that state to a VM.

## Checks completed

- `go test ./...` passed.
- `go test -race ./...` passed.
- `go vet ./...` passed.
- Fresh Linux CLI and daemon builds passed the binary qualification below.
- `GOOS=darwin GOARCH=arm64 go build ./cmd/kiln` passed with its output outside
  the repository. Workspace capture and materialization remain Linux-only.

The independent verifier's local evidence is in
`/tmp/kiln-workspace-final.yJWEfj`. Its `source-fingerprint.sha256` covers the
workspace package, CLI/daemon entry points and adapters, and `go.mod`; the
manifest SHA-256 is
`d0315e09b6ebcd9d7803e637d7b7947c80690d3b3bd231ab50b051451901ca21`.
The lead checked every source fingerprint, compared the saved original/restored
outputs, and independently restored the earlier fixture using final source.
Temporary evidence directories are local artifacts, not a durable release archive.

## Behavioral evidence

The binary fixture contains two commits, separate staged and unstaged edits,
staged and unstaged deletions, a rename, binary content, an executable, a safe
symlink and an ignored secret fixture. Capture, inspect and materialize run
without a reachable Kiln API or client credentials.

Qualification compares the original and restored HEAD, porcelain status,
cached binary diff and uncached binary diff. It also checks file bytes and
modes, detached HEAD, successful `git fsck --full`, absence of the exact parent
object, and absence of source remotes and configuration. The snapshot is mode
0600 and the restored repository root is mode 0700.
All comparisons passed, including the recursive HEAD tree. Restored regular
and executable files had modes 0644 and 0755 respectively.

Negative cases cover existing destinations, malformed and tampered snapshots,
unsafe paths and links, unsupported index flags, semantic Git environment
overrides, source changes between observations, size and entry limits, and
FIFO input. Git hook and fsmonitor sentinels must remain absent. A nested
`a/inside` and `a.txt` fixture exercises native Git tree ordering.
All rejection cases passed. The tests also reject same-size source blob bytes
that do not match their requested Git object ID; that index-only regression was
observed failing before the integrity check and passing afterward.

## Scope

These are local process and filesystem tests with real Git, not Proxmox or
network qualification. No provider credentials, resources or networking were
changed. Existing Core behavior and its database schema are unchanged.

Capture and materialization currently require Linux. Cross-compiling the CLI
for macOS verifies build compatibility only; it does not enable capture there.
Version 1 supports bounded SHA1 repositories and intentionally omits parent
history, remotes, local Git configuration and unsupported Git features. See
[workspace usage and limits](workspaces.md).

Two matching observations detect ordinary concurrent edits; they are not an
atomic filesystem snapshot. Root and processes running as the same user are
trusted. Ignore rules do not identify all secrets.

The remaining [Development Lease work](../architecture/development-lease.md)
includes a signed Linux image, qualified managed networking, workload
enrollment and transport, preview routing, and real lease expiration cleanup.
