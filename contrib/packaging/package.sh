#!/usr/bin/env bash
# Packs a published tswap into dist/tswap-<rid>.tar.gz (Linux and macOS; the Windows zip is made in release.yml).
#   package.sh <rid> <publish-dir> <dist-dir> [--smoke]
# macOS: libtswapse.dylib (the Secure Enclave shim) goes next to tswap, where the shim's resolver looks for it
# (AppContext.BaseDirectory), so the archive works unpacked in place, without the install script (issue #238).
# A missing dylib fails the packaging rather than shipping an archive without the Secure Enclave.
# --smoke: unpack the archive into an empty folder and run what is in it (the shipped bytes and permissions):
# `tswap prompt-hash` (needs no vault) and, on macOS, load the shipped dylib and resolve the shim's entry point.
# Make the archive on the binary's own platform: upload-artifact doesn't keep the execute bit.
set -euo pipefail

if [ $# -lt 3 ] || [ $# -gt 4 ] || { [ $# -eq 4 ] && [ "$4" != --smoke ]; }; then
  echo "usage: $0 <rid> <publish-dir> <dist-dir> [--smoke]" >&2
  exit 2
fi
rid=$1 publish=$2 dist=$3 smoke=${4:-}

files=(tswap)
case "$rid" in
  osx-*) files+=(libtswapse.dylib) ;;
esac
for f in "${files[@]}"; do
  if [ ! -f "$publish/$f" ]; then
    echo "package.sh: $publish/$f is missing; a $rid archive without it would not work" >&2
    exit 1
  fi
done

mkdir -p "$dist"
archive="$dist/tswap-$rid.tar.gz"
chmod +x "$publish/tswap"
tar czf "$archive" -C "$publish" "${files[@]}"
echo "packed $archive: ${files[*]}"

if [ "$smoke" = --smoke ]; then
  check=$(mktemp -d)
  trap 'rm -rf "$check"' EXIT
  tar xzf "$archive" -C "$check"
  "$check/tswap" prompt-hash
  case "$rid" in
    osx-*)
      # dlopen + dlsym of the shipped dylib: a missing, unsigned or wrong-architecture library fails here.
      python3 -c 'import ctypes, sys; ctypes.CDLL(sys.argv[1]).tswap_se_available' "$check/libtswapse.dylib"
      echo "loaded $check/libtswapse.dylib (tswap_se_available resolved)"
      ;;
  esac
fi
