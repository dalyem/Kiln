#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly debian13_base_sha512=8ea9faae810043a0b35b0149f05014f26705c2339ffb11ead308f33e844a87cc3ef46ec81d5262b38817b6a88af404874d48a5857ebe072ef6a31dfb6e371f50

usage() {
  cat >&2 <<'EOF'
usage: build.sh --base PATH --base-sha512 HEX --kiln PATH --kiln-sha256 HEX --kilnd PATH --kilnd-sha256 HEX --output-dir ABSENT_DIRECTORY

Builds an unsigned kiln-dev-base QCOW2 from explicit local inputs. Run as root
with LIBGUESTFS_BACKEND=direct. The output directory must not exist.
EOF
  exit 64
}

base=""; base_sha512=""; kiln=""; kiln_sha256=""; kilnd=""; kilnd_sha256=""; output_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --base) base=${2:-}; shift 2 ;;
    --base-sha512) base_sha512=${2:-}; shift 2 ;;
    --kiln) kiln=${2:-}; shift 2 ;;
    --kiln-sha256) kiln_sha256=${2:-}; shift 2 ;;
    --kilnd) kilnd=${2:-}; shift 2 ;;
    --kilnd-sha256) kilnd_sha256=${2:-}; shift 2 ;;
    --output-dir) output_dir=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[[ -n "$base" && -n "$base_sha512" && -n "$kiln" && -n "$kiln_sha256" && -n "$kilnd" && -n "$kilnd_sha256" && -n "$output_dir" ]] || usage
[[ $EUID -eq 0 ]] || { echo "build must run as root" >&2; exit 77; }
for command in qemu-img virt-resize virt-customize virt-cat git sha256sum python3 mktemp mkdir mv rm stat cmp install find sort sed grep awk realpath timeout; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 69; }
done
[[ $base_sha512 =~ ^[a-f0-9]{128}$ ]] || { echo "invalid base SHA-512 digest" >&2; exit 65; }
[[ $base_sha512 == "$debian13_base_sha512" ]] || { echo "base SHA-512 is not the pinned Debian 13 digest" >&2; exit 65; }
for value in "$kiln_sha256" "$kilnd_sha256"; do [[ $value =~ ^[a-f0-9]{64}$ ]] || { echo "invalid SHA-256 digest" >&2; exit 65; }; done
for path in "$base" "$kiln" "$kilnd"; do [[ -f "$path" && ! -L "$path" ]] || { echo "input must be a regular file: $path" >&2; exit 66; }; done

output_parent=$(realpath -e -- "$(dirname -- "$output_dir")")
output_dir="$output_parent/$(basename -- "$output_dir")"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] || { echo "refusing to overwrite output directory: $output_dir" >&2; exit 73; }
work=$(mktemp -d "$output_parent/.kiln-dev-build.XXXXXX")
capture_work=$(mktemp -d /var/tmp/kiln-dev-capture.XXXXXX)
trap 'rm -rf -- "$work" "$capture_work"' EXIT
inputs="$work/inputs"
mkdir -m 700 -- "$inputs"
base_copy="$inputs/debian-13-base.qcow2"
kiln_copy="$inputs/kiln"
kilnd_copy="$inputs/kilnd"
install -m 600 -- "$base" "$base_copy"
install -m 700 -- "$kiln" "$kiln_copy"
install -m 700 -- "$kilnd" "$kilnd_copy"
[[ $(sha512sum "$base_copy" | awk '{print $1}') == "$base_sha512" ]] || { echo "copied base SHA-512 mismatch" >&2; exit 65; }
[[ $(sha256sum "$kiln_copy" | awk '{print $1}') == "$kiln_sha256" ]] || { echo "copied kiln SHA-256 mismatch" >&2; exit 65; }
[[ $(sha256sum "$kilnd_copy" | awk '{print $1}') == "$kilnd_sha256" ]] || { echo "copied kilnd SHA-256 mismatch" >&2; exit 65; }
script_path=$(realpath -e -- "${BASH_SOURCE[0]}")
recipe_sha256=$(sha256sum "$script_path" | awk '{print $1}')
run_limited() { local seconds=$1; shift; timeout --preserve-status --kill-after=30s "$seconds" "$@"; }
fixture="$capture_work/fixture"; selftest="$capture_work/selftest"
mkdir -m 700 -- "$fixture" "$selftest"

clean_git_env=(env -i PATH=/usr/bin:/bin HOME="$capture_work/home" XDG_CONFIG_HOME="$capture_work/xdg")
mkdir -m 700 -- "$capture_work/home" "$capture_work/xdg"
"${clean_git_env[@]}" git -C "$fixture" init --quiet
"${clean_git_env[@]}" git -C "$fixture" config user.name "Kiln Image Fixture"
"${clean_git_env[@]}" git -C "$fixture" config user.email "kiln-image-fixture@example.invalid"
printf 'base\n' > "$fixture/tracked.txt"
printf '#!/bin/sh\nprintf fixture\n' > "$fixture/tool.sh"; chmod 755 "$fixture/tool.sh"
chmod 644 "$fixture/tracked.txt"
"${clean_git_env[@]}" git -C "$fixture" add tracked.txt tool.sh
"${clean_git_env[@]}" git -C "$fixture" commit --quiet -m fixture
printf 'staged\n' > "$fixture/tracked.txt"; "${clean_git_env[@]}" git -C "$fixture" add tracked.txt
printf 'unstaged\n' > "$fixture/tracked.txt"
printf '\000\001\002kiln-fixture\377\n' > "$fixture/untracked.bin"
chmod 644 "$fixture/tracked.txt" "$fixture/untracked.bin"
"${clean_git_env[@]}" "$kiln_copy" workspace capture --repo "$fixture" --output "$selftest/snapshot.json" >/dev/null
"${clean_git_env[@]}" git -C "$fixture" rev-parse HEAD > "$selftest/head"
"${clean_git_env[@]}" git -C "$fixture" status --porcelain=v1 > "$selftest/status"
"${clean_git_env[@]}" git -C "$fixture" diff --cached --no-ext-diff --binary > "$selftest/cached.diff"
"${clean_git_env[@]}" git -C "$fixture" diff --no-ext-diff --binary > "$selftest/worktree.diff"
(cd "$fixture" && sha256sum tracked.txt untracked.bin) > "$selftest/files.sha256"
(cd "$fixture" && stat -c '%a %n' tracked.txt tool.sh untracked.bin) > "$selftest/files.mode"
chmod 600 "$selftest/snapshot.json"

cat > "$work/image-selfcheck" <<'EOF'
#!/bin/sh
set -eu
exec >/dev/ttyS0 2>&1
fixture=/usr/lib/kiln/selftest
run=$(mktemp -d /run/kiln-image-selfcheck.XXXXXX)
workspace="$run/workspace"
cleanup() { rm -rf -- "$run"; }
trap cleanup EXIT HUP INT TERM
test -x /usr/local/bin/kilnd
command -v git >/dev/null; command -v python3 >/dev/null; command -v curl >/dev/null
grep -Eq '^[0-9a-f]{32}$' /etc/machine-id
test "$(cat /etc/machine-id)" != 00000000000000000000000000000000
awk -F: '$2 !~ /^(!|\*)/ { bad=1 } END { exit bad }' /etc/shadow
test ! -e /etc/kiln; test ! -e /etc/kilnd; test ! -e /var/lib/kiln; test ! -e /var/lib/kilnd
test -z "$(find /root /home -type f -name authorized_keys -print -quit 2>/dev/null)"
test -z "$(find /etc/ssh -maxdepth 1 -type f -name 'ssh_host_*' -print -quit)"
test "$(systemctl is-active ssh.service 2>/dev/null || :)" != active
test "$(systemctl is-active ssh.socket 2>/dev/null || :)" != active
test "$(systemctl is-active sshd-unix-local.socket 2>/dev/null || :)" != active
/usr/local/bin/kilnd workspace materialize --input "$fixture/snapshot.json" --destination "$workspace" >/dev/null
git -C "$workspace" rev-parse HEAD > "$run/head"
git -C "$workspace" status --porcelain=v1 > "$run/status"
git -C "$workspace" diff --cached --no-ext-diff --binary > "$run/cached.diff"
git -C "$workspace" diff --no-ext-diff --binary > "$run/worktree.diff"
cmp "$fixture/head" "$run/head"; cmp "$fixture/status" "$run/status"; cmp "$fixture/cached.diff" "$run/cached.diff"; cmp "$fixture/worktree.diff" "$run/worktree.diff"
(cd "$workspace" && sha256sum tracked.txt untracked.bin) > "$run/files.sha256"
cmp "$fixture/files.sha256" "$run/files.sha256"
(cd "$workspace" && stat -c '%a %n' tracked.txt tool.sh untracked.bin) > "$run/files.mode"
cmp "$fixture/files.mode" "$run/files.mode"
printf '%s\n' KILN_DEV_BASE_READY
EOF
chmod 755 "$work/image-selfcheck"
cat > "$work/image-selfcheck.service" <<'EOF'
[Unit]
Description=Kiln development image boot self-check
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/lib/kiln/image-selfcheck

[Install]
WantedBy=multi-user.target
EOF
cat > "$work/99-kiln-nocloud.cfg" <<'EOF'
datasource_list: [ NoCloud, None ]
network:
  config: disabled
ssh_pwauth: false
disable_root: true
EOF
cat > "$work/99-kiln-serial.cfg" <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT console=ttyS0,115200n8"
EOF

expanded="$work/expanded.qcow2"
run_limited 300 qemu-img create -f qcow2 -o compat=1.1,cluster_size=65536,lazy_refcounts=off,refcount_bits=16,compression_type=zlib "$expanded" 8G
run_limited 900 env LIBGUESTFS_BACKEND=direct virt-resize --expand /dev/sda1 "$base_copy" "$expanded"
run_limited 1800 env LIBGUESTFS_BACKEND=direct virt-customize -a "$expanded" --network \
  --install git,python3,ca-certificates,curl,build-essential \
  --mkdir /usr/local/lib/kiln --mkdir /usr/lib/kiln/selftest \
  --upload "$kilnd_copy:/usr/local/bin/kilnd" --upload "$work/image-selfcheck:/usr/local/lib/kiln/image-selfcheck" \
  --upload "$work/image-selfcheck.service:/etc/systemd/system/kiln-image-selfcheck.service" \
  --upload "$work/99-kiln-nocloud.cfg:/etc/cloud/cloud.cfg.d/99-kiln-nocloud.cfg" \
  --upload "$work/99-kiln-serial.cfg:/etc/default/grub.d/99-kiln-serial.cfg" \
  --copy-in "$selftest:/usr/lib/kiln" --chmod 0755:/usr/local/bin/kilnd --chmod 0755:/usr/local/lib/kiln/image-selfcheck \
  --run-command 'set -eu; ln -sf /dev/null /etc/systemd/system/ssh.service; ln -sf /dev/null /etc/systemd/system/ssh.socket; ln -sf /dev/null /etc/systemd/system/sshd-unix-local.socket; mkdir -p /etc/systemd/system-generators; ln -sf /dev/null /etc/systemd/system-generators/systemd-ssh-generator; touch /etc/cloud/cloud-init.disabled; systemctl enable kiln-image-selfcheck.service; update-grub; find /etc/ssh -maxdepth 1 -type f -name "ssh_host_*" -delete; find /root /home -type f \( -name authorized_keys -o -name .bash_history -o -name .python_history \) -delete 2>/dev/null || true; rm -rf /etc/kiln /etc/kilnd /var/lib/kiln /var/lib/kilnd /var/lib/cloud/instances /var/lib/cloud/instance /var/lib/cloud/seed /var/lib/cloud/data /var/log/cloud-init* /var/lib/systemd/random-seed /var/lib/apt/lists/* /var/cache/apt/archives/*.deb; : > /etc/machine-id; rm -f /var/lib/dbus/machine-id; ln -s /etc/machine-id /var/lib/dbus/machine-id; awk -F: '\''$2 !~ /^(!|\*)/ {print $1}'\'' /etc/shadow | xargs -r -n1 passwd -l; find /var/log -type f -delete; dpkg-query -W -f='\''${Package}\t${Version}\n'\'' | LC_ALL=C sort > /usr/local/share/kiln-image-packages.tsv'
run_limited 300 qemu-img check "$expanded" >/dev/null
info=$(run_limited 60 qemu-img info --output=json "$expanded")
python3 - "$info" <<'PY'
import json, sys
info = json.loads(sys.argv[1]); data = info.get("format-specific", {}).get("data", {})
if info.get("format") != "qcow2" or info.get("virtual-size") != 8 * 1024**3 or info.get("cluster-size") != 65536 or data.get("compat") != "1.1" or data.get("refcount-bits") != 16 or data.get("compression-type") != "zlib" or data.get("lazy-refcounts") is not False or data.get("extended-l2") is not False or info.get("backing-filename"):
    raise SystemExit("output is not the required standalone QCOW2 profile")
PY
packages=$(run_limited 300 env LIBGUESTFS_BACKEND=direct virt-cat -a "$expanded" /usr/local/share/kiln-image-packages.tsv)
artifact_sha256=$(sha256sum "$expanded" | awk '{print $1}')
[[ $(stat -c '%s' "$expanded") -le $((2 * 1024 * 1024 * 1024)) ]] || { echo "output exceeds the 2 GiB file verification limit" >&2; exit 65; }
python3 - "$work/build-metadata.json" "$base_sha512" "$kilnd_sha256" "$artifact_sha256" "$recipe_sha256" "$packages" <<'PY'
import json, sys
path, base_sha512, kilnd_sha256, artifact_sha256, recipe_sha256, packages = sys.argv[1:]
with open(path, "w", encoding="utf-8") as output:
    json.dump({"schemaVersion": 1, "name": "kiln-dev-base", "arch": "amd64", "profile": "debian13-nic-free-development-v1", "recipe": "images/dev/build.sh", "recipeSha256": recipe_sha256, "baseSha512": base_sha512, "kilndSha256": kilnd_sha256, "artifactSha256": artifact_sha256, "packages": packages.splitlines(), "reproducible": False}, output, sort_keys=True, separators=(",", ":")); output.write("\n")
PY
publish="$work/publish"
mkdir -m 700 -- "$publish"
mv -- "$expanded" "$publish/kiln-dev-base.qcow2"
mv -- "$work/build-metadata.json" "$publish/kiln-dev-base.metadata.json"
python3 - "$publish" "$output_dir" <<'PY'
import ctypes
import os
import sys

at_fdcwd = -100
rename_noreplace = 1
libc = ctypes.CDLL(None, use_errno=True)
rename = libc.renameat2
rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
rename.restype = ctypes.c_int
result = rename(at_fdcwd, os.fsencode(sys.argv[1]), at_fdcwd, os.fsencode(sys.argv[2]), rename_noreplace)
if result != 0:
    error = ctypes.get_errno()
    raise OSError(error, f"publish output directory {sys.argv[2]}")
PY
printf '%s  %s\n' "$artifact_sha256" "$output_dir/kiln-dev-base.qcow2"
