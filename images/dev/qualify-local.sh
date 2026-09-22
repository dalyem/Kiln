#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# -ne 3 || $2 != --evidence-dir ]]; then
  echo "usage: $0 PATH_TO_KILN_DEV_BASE_QCOW2 --evidence-dir ABSENT_DIRECTORY" >&2
  exit 64
fi
image=$(realpath -e -- "$1")
evidence_dir=$3
[[ -f "$image" && ! -L "$image" ]] || { echo "image must be a regular file" >&2; exit 66; }
[[ ! -e "$evidence_dir" && ! -L "$evidence_dir" ]] || { echo "refusing to overwrite evidence directory" >&2; exit 73; }
for command in qemu-img qemu-system-x86_64 sha256sum mktemp grep kill sleep realpath mkdir mv cp; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 69; }
done
original_sha256=$(sha256sum "$image" | awk '{print $1}')
work=$(mktemp -d "${TMPDIR:-/tmp}/kiln-dev-qualify.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'rm -rf -- "$work"; exit 130' HUP INT TERM
boot_image="$work/kiln-dev-base.qcow2"
cp --reflink=auto -- "$image" "$boot_image"
[[ $(sha256sum "$boot_image" | awk '{print $1}') == "$original_sha256" ]] || { echo "private boot copy digest does not match source artifact" >&2; exit 65; }
[[ $(sha256sum "$image" | awk '{print $1}') == "$original_sha256" ]] || { echo "source artifact changed while copying" >&2; exit 65; }
qemu-img check "$boot_image" >/dev/null
overlay="$work/boot-overlay.qcow2"
serial="$work/serial.log"
pid=""
qemu_start=""
result=FAILED
mkdir -m 700 -- "$evidence_dir"
reap_qemu() {
  if [[ -z "$pid" ]]; then return; fi
  for _ in $(seq 1 30); do
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid" 2>/dev/null || true; pid=""; return; fi
    if [[ -n "$qemu_start" && -r "/proc/$pid/stat" ]] && [[ $(awk '{print $22}' "/proc/$pid/stat") != "$qemu_start" ]]; then pid=""; return; fi
    sleep 1
  done
  if [[ -r "/proc/$pid/stat" ]] && [[ $(awk '{print $22}' "/proc/$pid/stat") == "$qemu_start" ]]; then kill -KILL "$pid" 2>/dev/null || true; fi
  wait "$pid" 2>/dev/null || true
  pid=""
}
cleanup() {
  if [[ -n "$pid" && -r "/proc/$pid/stat" ]] && [[ $(awk '{print $22}' "/proc/$pid/stat") == "$qemu_start" ]]; then kill -TERM "$pid" 2>/dev/null || true; fi
  reap_qemu
  if [[ -f "$serial" ]]; then mv -- "$serial" "$evidence_dir/serial.log"; fi
  {
    printf 'result %s\n' "$result"
    printf 'sourceSha256 %s\n' "$original_sha256"
    printf 'bootedCopySha256 %s\n' "$(sha256sum "$boot_image" | awk '{print $1}')"
    printf 'sourcePath %s\n' "$image"
  } > "$evidence_dir/artifact.sha256"
  rm -rf -- "$work"
}
on_signal() { trap - EXIT; cleanup; exit 130; }
trap cleanup EXIT
trap on_signal HUP INT TERM
qemu-img create -f qcow2 -F qcow2 -b "$boot_image" "$overlay" >/dev/null
qemu-system-x86_64 -enable-kvm -m 2048 -smp 2 -display none -monitor none -serial "file:$serial" -drive "file=$overlay,format=qcow2,if=virtio" -nic none -no-reboot &
pid=$!
qemu_start=$(awk '{print $22}' "/proc/$pid/stat")
for _ in $(seq 1 180); do
  if tr -d '\r' < "$serial" 2>/dev/null | grep -Fqx 'KILN_DEV_BASE_READY'; then
    if [[ -r "/proc/$pid/stat" ]] && [[ $(awk '{print $22}' "/proc/$pid/stat") == "$qemu_start" ]]; then kill -TERM "$pid" 2>/dev/null || true; fi
    reap_qemu
    [[ $(sha256sum "$image" | awk '{print $1}') == "$original_sha256" ]] || { echo "golden image changed during qualification" >&2; exit 65; }
    [[ $(sha256sum "$boot_image" | awk '{print $1}') == "$original_sha256" ]] || { echo "booted copy changed during qualification" >&2; exit 65; }
    result=PASSED
    printf 'qualified %s\n' "$image"
    exit 0
  fi
  if [[ ! -r "/proc/$pid/stat" ]] || [[ $(awk '{print $22}' "/proc/$pid/stat") != "$qemu_start" ]]; then
    wait "$pid" 2>/dev/null || true
    pid=""
    echo "QEMU exited before readiness marker" >&2
    exit 65
  fi
  sleep 1
done
echo "timed out waiting for KILN_DEV_BASE_READY" >&2
exit 124
