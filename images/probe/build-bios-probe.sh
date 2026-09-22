#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 64
fi

output_directory=$1
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

for command in as ld objcopy objdump qemu-img dd truncate cmp grep od stat sha256sum tr mkdir mktemp mv rm; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 69
  }
done

mkdir -p -- "$output_directory"
build_directory=$(mktemp -d "${TMPDIR:-/tmp}/kiln-bios-probe.XXXXXX")
trap 'rm -rf -- "$build_directory"' EXIT

boot_object="$build_directory/boot.o"
boot_elf="$build_directory/boot.elf"
boot_sector="$build_directory/boot.bin"
raw_image="$output_directory/kiln-stage2-bios-probe.raw"
qcow_image="$output_directory/kiln-stage2-bios-probe.qcow2"
raw_build_image="$build_directory/kiln-stage2-bios-probe.raw"
qcow_build_image="$build_directory/kiln-stage2-bios-probe.qcow2"
roundtrip_image="$build_directory/roundtrip.raw"

for output in "$raw_image" "$qcow_image"; do
  if [[ -e "$output" || -L "$output" ]]; then
    echo "refusing to overwrite existing output: $output" >&2
    exit 73
  fi
done

as --32 -o "$boot_object" "$script_directory/boot.S"
ld -m elf_i386 -Ttext 0x7c00 -o "$boot_elf" "$boot_object"
if objdump -r "$boot_elf" | grep -q 'R_'; then
  echo "linked boot image contains unresolved relocations" >&2
  exit 65
fi
objcopy -O binary -j .text "$boot_elf" "$boot_sector"

[[ $(stat -c '%s' "$boot_sector") -eq 512 ]] || {
  echo "boot sector is not exactly 512 bytes" >&2
  exit 65
}

truncate -s 4M "$raw_build_image"
dd if="$boot_sector" of="$raw_build_image" conv=notrunc status=none
qemu-img convert -f raw -O qcow2 -o cluster_size=512,compat=1.1,lazy_refcounts=off \
  "$raw_build_image" "$qcow_build_image"
qemu-img check "$qcow_build_image" >/dev/null
qemu-img convert -f qcow2 -O raw "$qcow_build_image" "$roundtrip_image"
cmp -n 512 "$boot_sector" "$roundtrip_image"

signature=$(od -An -tx1 -j 510 -N 2 "$roundtrip_image" | tr -d '[:space:]')
[[ "$signature" == "55aa" ]] || {
  echo "round-tripped boot signature was $signature, expected 55aa" >&2
  exit 65
}
grep -aq 'KILN-PROBE-READY' "$roundtrip_image"

qcow_size=$(stat -c '%s' "$qcow_build_image")
[[ "$qcow_size" -le 131072 ]] || {
  echo "QCOW2 is $qcow_size bytes, above the 131072 byte Stage 1 fixture limit" >&2
  exit 65
}

# Finish all validation before publishing either artifact.
qcow_digest=$(sha256sum "$qcow_build_image")
qcow_digest=${qcow_digest%% *}
qcow_info=$(qemu-img info --output=json "$qcow_build_image")

for output in "$raw_image" "$qcow_image"; do
  if [[ -e "$output" || -L "$output" ]]; then
    echo "refusing to overwrite output published during build: $output" >&2
    exit 73
  fi
done

mv -n -- "$raw_build_image" "$raw_image"
mv -n -- "$qcow_build_image" "$qcow_image"
[[ ! -e "$raw_build_image" && ! -e "$qcow_build_image" ]] || {
  echo "refusing to overwrite an output published during finalization" >&2
  exit 73
}

printf '%s  %s\n' "$qcow_digest" "$qcow_image"
printf '%s\n' "$qcow_info"
echo "built $qcow_image ($qcow_size bytes)"
