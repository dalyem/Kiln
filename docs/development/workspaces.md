# Local workspace snapshots

This increment adds a local capture and restore check. It does not upload a
workspace, create a lease, start a listener, or run project commands.
See the [qualification record](workspace-qualification.md) for tested behavior.

```sh
kiln workspace capture --repo /path/to/repo --output /private/snapshot.json
kiln workspace inspect --input /private/snapshot.json
kilnd workspace materialize --input /private/snapshot.json --destination /private/workspace
```

Each command writes a JSON summary with a snapshot digest, HEAD ID, entry
counts, blob count, and policy name. It never prints file data or commit text.
`capture` creates a new mode-0600 output file and refuses to overwrite one.
The output file must be outside the repository.

## What capture preserves

Version 1 supports SHA1 Git working trees with a committed HEAD. It records
the raw HEAD commit and its tree, the stage-zero index, and the actual working
files. These are separate views. A staged edit followed by an unstaged edit,
staged deletion, untracked binary file, executable bit, and safe relative
symlink retain their separate state after materialization.

The reconstructed repository has a detached HEAD. For a commit with parents,
the repository marks that commit shallow because parent objects are not copied.
It does not copy source history, branches, remotes, configuration, hooks, or
credentials. Empty directories are not recorded.

Capture uses Git's standard exclusion rules for untracked files. That includes
the configured global excludes file. Ignore rules are not secret scanning.
Tracked content is captured even when the working-tree copy is deleted, and
unignored files can contain secrets.

## Safety and limits

The receiver treats the JSON as untrusted. It rejects unknown or duplicate
JSON keys, trailing data, invalid hashes, unused or missing blobs, duplicate
paths, file-directory conflicts, path traversal, `.git` paths, unsafe links,
and invalid commit or tree bindings before it creates a destination.

The current limits are 96 MiB encoded JSON, 64 MiB unique raw content including
the raw HEAD commit,
16 MiB per blob, 10,000 entries across all three views, and 4 KiB paths or
symlink targets. A destination must be absent, absolute, and directly under a
private directory owned by the current user. Materialization builds in a
private sibling directory, runs `git fsck --full`, then publishes with Linux
`renameat2(RENAME_NOREPLACE)`.

Version 1 rejects SHA256 repositories, linked worktrees, partial clones,
sparse checkouts, conflict stages, assume-unchanged and skip-worktree entries,
intent-to-add entries, gitlinks, special files, unsafe symlinks, LFS pointers, and LFS-attributed
paths. It disables Git hooks, fsmonitor, replacement objects, optional locks,
network protocols, and `GIT_*` environment injection. It does not run filters
or fetch missing objects.

Capture rejects semantic Git environment overrides such as `GIT_CONFIG_COUNT`,
`GIT_CONFIG_GLOBAL`, `GIT_DIR`, and `GIT_WORK_TREE`. Use normal Git
configuration for global excludes. The command keeps that configuration for
standard ignore handling, but refuses environment values that could redirect
the repository or alter what gets captured.

The package observes the repository twice and only publishes when both
manifests match. Pause editors and other writers before capture. Two matching
observations do not make the filesystem atomic and cannot rule out an
edit-and-revert race. The format preserves raw Git objects and bytes. It does
not preserve behavior that depends on source-local configuration such as custom
filters, attributes, or `core.autocrlf`.

Capture and materialization need Linux for descriptor-relative no-follow reads,
private-parent checks, and no-clobber publication. A trusted path contains only
root-owned or current-user-owned ancestors. Writable ancestors need the sticky
bit, and the direct output or destination parent is current-user-owned and not
group or world writable. Other platforms return an explicit unsupported error.
Modes are canonical Git modes 100644 and 100755. Other permission bits are not
preserved. Safe links are UTF-8 relative paths without empty, dot, parent, or
`.git` components.

The trusted-parent check does not defend against a malicious root process or a
malicious process running as the current user outside that directory boundary.
