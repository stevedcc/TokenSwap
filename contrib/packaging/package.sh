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

if [ "$smoke" = --smoke ]; then
  check=$(mktemp -d)
  trap 'rm -rf "$check"' EXIT
  tar xzf "$archive" -C "$check"
  "$check/tswap" prompt-hash
  case "$rid" in
    osx-*)
      mkdir -m 700 "$check/config"
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" init --secure-enclave --no-touch --no-password --no-recovery
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" names
      echo "Secure Enclave vault made and unlocked by the unpacked tswap (libtswapse.dylib loaded from the archive)"
      ;;
  esac
fi
