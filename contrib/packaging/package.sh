#!/usr/bin/env bash
# Packs a published tswap into dist/tswap-<rid>.tar.gz (Linux and macOS; the Windows zip is made in release.yml).
#   package.sh <rid> <publish-dir> <dist-dir> [--smoke]
# macOS: libtswapse.dylib (the Secure Enclave shim) goes next to tswap, where the shim's resolver looks for it
# (AppContext.BaseDirectory), so the archive works unpacked in place, without the install script (issue #238).
# A missing dylib, or a rid this script doesn't know, fails the packaging rather than shipping a wrong archive.
# --smoke: unpack the archive into an empty folder and run what is in it (the shipped bytes and permissions):
# `tswap prompt-hash` (needs no vault) and, on macOS, a Secure Enclave vault in a throwaway config folder (init with
# no touch, password or recovery prompt, then `names` to unlock it): that loads the shipped dylib through tswap's own
# resolver. Needs a Mac with a Secure Enclave (GitHub's macOS runners have one, see ci.yml's probe).
# On Linux, --smoke also checks that libpcsclite is used when present and never required (YubiKey SDK, design
# docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md "Constraints"): `readelf -d` of the unpacked tswap
# has no libpcsclite entry, and tswap runs `prompt-hash` once more in a bubblewrap sandbox where every path
# `ldconfig -p` lists for libpcsclite.so.1 is /dev/null (TswapCli/Native/pcsc-loader.c then takes its stand-in).
# Without bwrap or without the library, or when bwrap can't make its sandbox (nested user namespaces), that run is
# skipped with a loud "SKIP: stand-in run (<reason>)" line.
# Make the archive on the binary's own platform: upload-artifact doesn't keep the execute bit.
set -euo pipefail

if [ $# -lt 3 ] || [ $# -gt 4 ] || { [ $# -eq 4 ] && [ "$4" != --smoke ]; }; then
  echo "usage: $0 <rid> <publish-dir> <dist-dir> [--smoke]" >&2
  exit 2
fi
rid=$1 publish=$2 dist=$3 smoke=${4:-}

case "$rid" in
  linux-x64 | linux-arm64) files=(tswap) ;;
  osx-arm64 | osx-x64) files=(tswap libtswapse.dylib) ;;
  *)
    echo "package.sh: unknown rid '$rid' (expected linux-x64, linux-arm64, osx-arm64 or osx-x64)" >&2
    exit 2
    ;;
esac
for f in "${files[@]}"; do
  if [ ! -f "$publish/$f" ]; then
    echo "package.sh: $publish/$f is missing; a $rid archive without it would not work" >&2
    exit 1
  fi
done

mkdir -p -- "$dist"
archive="$dist/tswap-$rid.tar.gz"
chmod +x "$publish/tswap"
# Written under a temporary name and renamed, so an interrupted run never leaves a partial archive under the real name.
tar czf "$archive.partial" -C "$publish" "${files[@]}"
mv -f "$archive.partial" "$archive"
echo "packed $archive: ${files[*]}"

# Linux: the unpacked tswap needs no libpcsclite, and starts with it hidden.
linux_pcsc_smoke() {
  local bin=$1 dynamic
  if ! dynamic=$(readelf -d "$bin" 2>&1); then
    echo "package.sh: readelf -d failed on $bin: $dynamic" >&2
    exit 1
  fi
  if grep -q 'libpcsclite' <<<"$dynamic"; then
    echo "package.sh: $bin has a NEEDED entry for libpcsclite; without pcsc-lite installed it would not start:" >&2
    grep 'libpcsclite' <<<"$dynamic" >&2
    exit 1
  fi
  echo "no NEEDED entry for libpcsclite: $(grep -o 'Shared library: \[[^]]*\]' <<<"$dynamic" | tr '\n' ' ')"

  local ldconfig libs=() hide=() lib
  ldconfig=$(command -v ldconfig || command -v /sbin/ldconfig || true)
  if [ -n "$ldconfig" ]; then
    # A read loop, not mapfile: the tests run this function on macOS too, whose bash is 3.2.
    while IFS= read -r lib; do libs+=("$lib"); done < <("$ldconfig" -p | awk '$1 == "libpcsclite.so.1" { print $NF }' | LC_ALL=C sort -u)
  fi
  if ! command -v bwrap > /dev/null; then
    echo "SKIP: stand-in run (bwrap is not installed)"
    return
  fi
  if [ -z "$ldconfig" ]; then
    echo "SKIP: stand-in run (no ldconfig to list libpcsclite.so.1)"
    return
  fi
  if [ ${#libs[@]} -eq 0 ]; then
    echo "SKIP: stand-in run (ldconfig -p lists no libpcsclite.so.1: the run above already had no library)"
    return
  fi
  if ! bwrap --dev-bind / / -- true 2> /dev/null; then
    echo "SKIP: stand-in run (bwrap can't create its sandbox here, e.g. nested user namespaces)"
    return
  fi
  for lib in "${libs[@]}"; do
    hide+=(--ro-bind /dev/null "$lib")
  done
  # Inside the sandbox, every listed path must read as empty, or the run below proves nothing.
  # shellcheck disable=SC2016 # the script runs inside the sandbox, with the paths as its arguments
  if ! bwrap --dev-bind / / "${hide[@]}" -- sh -c 'for f; do [ ! -s "$f" ] || exit 1; done' sh "${libs[@]}"; then
    echo "package.sh: bwrap did not hide ${libs[*]}" >&2
    exit 1
  fi
  bwrap --dev-bind / / "${hide[@]}" -- "$bin" prompt-hash
  echo "stand-in run passed: prompt-hash with ${libs[*]} hidden"
}

if [ "$smoke" = --smoke ]; then
  check=$(mktemp -d)
  trap 'rm -rf "$check"' EXIT
  tar xzf "$archive" -C "$check"
  "$check/tswap" prompt-hash
  case "$rid" in
    linux-*)
      linux_pcsc_smoke "$check/tswap"
      ;;
    osx-*)
      mkdir -m 700 "$check/config"
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" init --secure-enclave --no-touch --no-password --no-recovery
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" names
      echo "Secure Enclave vault made and unlocked by the unpacked tswap (libtswapse.dylib loaded from the archive)"
      ;;
  esac
fi
