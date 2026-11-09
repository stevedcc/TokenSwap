#!/usr/bin/env bash
# Packs a published tswap into dist/tswap-<rid>.tar.gz (Linux and macOS; the Windows zip is made in release.yml).
#   package.sh <rid> <publish-dir> <dist-dir> [--smoke]
# macOS: libtswapse.dylib (the Secure Enclave shim) goes next to tswap, where the shim's resolver looks for it
# (AppContext.BaseDirectory), so the archive works unpacked in place, without the install script (issue #238).
# A missing dylib, or a rid this script doesn't know, fails the packaging rather than shipping a wrong archive.
# --smoke: unpack the archive into an empty folder and run what is in it (the shipped bytes and permissions):
# first `tswap --version`, whose whole stdout must be `tswap $TSWAP_EXPECT_VERSION` and one line ending (`\n` or
# `\r\n`) (brief T18: the workflow sets it, the tag without its v or the csproj's <Version>;
# --smoke without it fails before packing), then `tswap prompt-hash` (needs no vault) and, on macOS, a Secure Enclave vault in a throwaway config folder (init with
# no touch, password or recovery prompt, then `names` to unlock it): that loads the shipped dylib through tswap's own
# resolver. Needs a Mac with a Secure Enclave (GitHub's macOS runners have one, see ci.yml's probe).
# On Linux, --smoke also checks that libpcsclite is used when present and never required (YubiKey SDK, design
# docs/superpowers/specs/2026-11-04-yubikey-sdk-portable-design.md "Constraints"): `readelf -d` of the unpacked tswap
# has no libpcsclite entry, and tswap runs `prompt-hash` once more in a bubblewrap sandbox where every path
# `ldconfig -p` lists for libpcsclite.so.1 is /dev/null (TswapCli/Native/pcsc-loader.c then takes its stand-in).
# Without bwrap or without the library, or when bwrap can't make its sandbox (nested user namespaces), that run is
# skipped with a loud "SKIP: stand-in run (<reason>)" line.
# Every --smoke also runs `tswap yubikey setup --touch --serial 2147483647` (YubiKey SDK stage 1, task 4): 2147483647
# is outside the range YubiKey serials use (assumed), so it can never select, let alone program, a key that happens to
# be plugged in, and the smoke never passes --replace. Its only expected outcome is the refusal "YubiKey 2147483647 is
# not plugged in" (a per-OS explanation may follow), which also proves the --serial path is consulted and the YubiKey
# SDK starts in the shipped binary. On Linux it runs again with -v, whose PC/SC strategy line must name the system
# library when ldconfig lists libpcsclite.so.1 (the stand-in otherwise), and in the sandbox, where it must name the
# stand-in.
# macOS, always (every PR, unsigned too; issues #240 and #265): the dylib `tswap installscript` writes (decoded from
# its script) must be byte-for-byte the archive's libtswapse.dylib, and both Mach-Os must declare the same minimum
# macOS as TswapCore.csproj's SecureEnclaveShimMinOS (read from the csproj itself: one source).
# macOS with TSWAP_EXPECT_TEAM_ID set (release.yml's signing job only): per file codesign --verify --strict, the team,
# the runtime flag; Apple's notarisation check for "other code" (codesign -vvvv --test-requirement='=notarized'
# --check-notarization), asked again every TSWAP_NOTARY_CHECK_INTERVAL seconds (20) while it answers 3 (the ticket
# isn't visible yet), at most TSWAP_NOTARY_CHECK_TRIES times (30: ten minutes); the same check, once, on an ad-hoc
# re-signed copy that must fail (the control); then a simulated browser download (the archive quarantined, unpacked
# with tar, each file marked as Archive Utility would if tar didn't) run from Terminal where Gatekeeper assessments
# are enabled, else a SKIP line. The notarisation checks are
# report-only until TSWAP_MACOS_GATE_RUNNER_CHECKS=1 (macos/runner-checks.sh).
# Make the archive on the binary's own platform: upload-artifact doesn't keep the execute bit.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

if [ $# -lt 3 ] || [ $# -gt 4 ] || { [ $# -eq 4 ] && [ "$4" != --smoke ]; }; then
  echo "usage: $0 <rid> <publish-dir> <dist-dir> [--smoke]" >&2
  exit 2
fi
rid=$1 publish=$2 dist=$3 smoke=${4:-}

if [ "$smoke" = --smoke ] && [ -z "${TSWAP_EXPECT_VERSION:-}" ]; then
  echo "package.sh: --smoke needs TSWAP_EXPECT_VERSION, the version the binary must report (the tag without its v, or the csproj's <Version>)" >&2
  exit 2
fi

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

# Brief T18: `tswap --version` prints exactly `tswap $TSWAP_EXPECT_VERSION` and one line ending (\n, or \r\n as on
# Windows), nothing else. The x after it keeps $(...) from stripping trailing newlines, so a blank line after the
# version is seen (review F4).
version_smoke() {
  local bin=$1 out status=0 want="tswap $TSWAP_EXPECT_VERSION"
  out=$("$bin" --version && printf x) || status=$?
  out=${out%x}
  if [ "$status" -ne 0 ] || { [ "$out" != "$want"$'\n' ] && [ "$out" != "$want"$'\r\n' ]; }; then
    out=${out%$'\n'}
    out=${out%$'\r'}
    echo "package.sh: 'tswap --version' printed '$out' (exit $status), expected 'tswap $TSWAP_EXPECT_VERSION'" >&2
    exit 1
  fi
  echo "tswap --version: $want"
}

# Runs "$@" yubikey setup --touch --serial 2147483647 ("$@": the binary, or bwrap ... -- binary, then tswap's global
# flags) and requires the refusal; with $1 set to an expected PC/SC strategy, also that strategy line.
yubikey_smoke() {
  local strategy=$1 out status=0
  shift
  out=$("$@" yubikey setup --touch --serial 2147483647 2>&1) || status=$?
  printf '%s\n' "$out"
  if [ "$status" -eq 0 ] || ! grep -qF 'YubiKey 2147483647 is not plugged in' <<<"$out"; then
    echo "package.sh: 'tswap yubikey setup --touch --serial 2147483647' should refuse with 'YubiKey 2147483647 is not plugged in' (exit $status)" >&2
    exit 1
  fi
  if [ -n "$strategy" ] && ! grep -qF "PC/SC (smart-card) access: $strategy" <<<"$out"; then
    echo "package.sh: expected the PC/SC strategy '$strategy' in the -v output above" >&2
    exit 1
  fi
}

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
  # Without ldconfig there is no telling whether the loader finds the library: any strategy line will do.
  local expected=
  if [ -n "$ldconfig" ]; then
    if [ ${#libs[@]} -gt 0 ]; then expected='system library'; else expected='stand-in'; fi
  fi
  yubikey_smoke "$expected" "$bin" -v
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
  yubikey_smoke 'stand-in' bwrap --dev-bind / / "${hide[@]}" -- "$bin" -v
  echo "stand-in run passed: prompt-hash and yubikey setup with ${libs[*]} hidden"
}

# macOS, always: the dylib installscript embeds is the shipped one, and the minimum macOS is the same everywhere (#265).
macos_smoke_bytes() {
  local dir=$1 script blob csproj want tswap_minos dylib_minos
  # shellcheck source=macos/macho.sh
  . "$here/macos/macho.sh"
  script=$("$dir/tswap" installscript)
  # shellcheck disable=SC2016 # $DYLIB_TMP is the generated script's own text
  blob=$(printf '%s\n' "$script" | sed -n 's/^ *echo "\([A-Za-z0-9+/=]*\)" | base64 -D > "\$DYLIB_TMP"$/\1/p')
  if [ -z "$blob" ]; then
    echo "package.sh: '$dir/tswap installscript' wrote no Secure Enclave dylib step" >&2
    exit 1
  fi
  printf '%s' "$blob" | base64 --decode > "$dir.installscript-dylib"
  if ! cmp -s "$dir.installscript-dylib" "$dir/libtswapse.dylib"; then
    echo "package.sh: the dylib installscript writes is not the archive's (was the shim signed after it was embedded?)" >&2
    exit 1
  fi
  echo "the dylib installscript writes is the archive's libtswapse.dylib"

  csproj="$here/../../TswapCore/TswapCore.csproj"
  csproj=$(cd "$(dirname "$csproj")" && pwd)/$(basename "$csproj")
  want=$(sed -n 's:.*<SecureEnclaveShimMinOS>\([^<]*\)</SecureEnclaveShimMinOS>.*:\1:p' "$csproj" 2> /dev/null || true)
  if [ -z "$want" ] || [ "$(printf '%s\n' "$want" | grep -c .)" -ne 1 ]; then
    echo "package.sh: no <SecureEnclaveShimMinOS> in $csproj (or more than one)" >&2
    exit 1
  fi
  tswap_minos=$(macho_minos "$dir/tswap")
  dylib_minos=$(macho_minos "$dir/libtswapse.dylib")
  if [ -z "$tswap_minos" ] || [ "$tswap_minos" != "$want" ] || [ "$dylib_minos" != "$want" ]; then
    echo "package.sh: minos: tswap ${tswap_minos:-unknown}, libtswapse.dylib ${dylib_minos:-unknown}, SecureEnclaveShimMinOS $want: they must be equal (#265)" >&2
    exit 1
  fi
  echo "minos $want: tswap, libtswapse.dylib and SecureEnclaveShimMinOS agree"
}

# notarisation_check <file> <tries>: sets check_code, check_tries and check_answer (the last answer).
notarisation_check() {
  local file=$1 tries=$2 interval=${TSWAP_NOTARY_CHECK_INTERVAL:-20}
  check_tries=0
  while :; do
    check_tries=$((check_tries + 1))
    check_code=0
    # The long option with a leading '=': requirement text, not a file path (never -R, which takes '==notarized').
    check_answer=$(codesign -vvvv --test-requirement='=notarized' --check-notarization "$file" 2>&1) || check_code=$?
    if [ "$check_code" -ne 3 ] || [ "$check_tries" -ge "$tries" ]; then
      return 0
    fi
    echo "$(basename "$file"): the notarisation ticket isn't visible yet (attempt $check_tries of $tries); asking again in ${interval}s"
    sleep "$interval"
  done
}

# macOS with TSWAP_EXPECT_TEAM_ID: the signature, team and runtime flag of each file, and notarisation.
macos_smoke_signing() {
  local dir=$1 f d team flags control status
  # shellcheck source=macos/runner-checks.sh
  . "$here/macos/runner-checks.sh"
  for f in tswap libtswapse.dylib; do
    if ! codesign --verify --strict --verbose=2 "$dir/$f"; then
      echo "package.sh: $f: codesign --verify --strict failed" >&2
      exit 1
    fi
    d=$(codesign -dvvv "$dir/$f" 2>&1)
    team=$(printf '%s\n' "$d" | sed -n 's/^TeamIdentifier=//p' | head -n 1)
    if [ "$team" != "$TSWAP_EXPECT_TEAM_ID" ]; then
      echo "package.sh: $f: TeamIdentifier is ${team:-missing}, expected $TSWAP_EXPECT_TEAM_ID" >&2
      exit 1
    fi
    flags=0
    printf '%s\n' "$d" | grep -qE 'flags=0x[0-9a-fA-F]+\(([^)]*,)?runtime(,[^)]*)?\)' || flags=1
    if [ "$f" = libtswapse.dylib ]; then
      runner_check dylib-runtime "$flags" "$f: flags= does not name runtime" || exit 1
    elif [ "$flags" != 0 ]; then
      echo "package.sh: $f: flags= does not name runtime (the hardened runtime)" >&2
      exit 1
    fi
    echo "$f: signed by team $team with the hardened runtime"
  done
  for f in tswap libtswapse.dylib; do
    notarisation_check "$dir/$f" "${TSWAP_NOTARY_CHECK_TRIES:-30}"
    [ "$check_code" -eq 0 ] || printf '%s\n' "$check_answer"
    runner_check notarisation "$check_code" "$f: codesign --check-notarization exit $check_code after $check_tries attempts" || exit 1
  done
  # The control: an unnotarised copy (re-signed ad hoc) must fail the same check, or the check proves nothing.
  control="$dir.unnotarised-control"
  cp "$dir/tswap" "$control"
  codesign --force --sign - "$control"
  notarisation_check "$control" 1
  printf '%s\n' "$check_answer"
  echo "the unnotarised control: exit $check_code (3 expected; 1 if the ad-hoc signature fails --verify first)"
  status=0
  [ "$check_code" -ne 0 ] || status=1
  runner_check notarisation-control "$status" "the check passed an unnotarised binary: it proves nothing" || exit 1
}

# macOS with TSWAP_EXPECT_TEAM_ID: the archive as a browser download (quarantined), unpacked and run from Terminal.
macos_smoke_quarantine() {
  local q f status mark
  q="$check.download"
  mkdir -p "$q/quarantined"
  cp "$archive" "$q/download.tar.gz"
  mark="0083;$(printf '%x' "$(date +%s)");Safari;"
  xattr -w com.apple.quarantine "$mark" "$q/download.tar.gz"
  tar xzf "$q/download.tar.gz" -C "$q/quarantined"
  for f in tswap libtswapse.dylib; do
    # Archive Utility (a double-click in Finder) gives every unpacked file the archive's mark; tar may not. Where it
    # didn't, mark the file as Archive Utility would, so the run below is a quarantined download's either way.
    if ! xattr -p com.apple.quarantine "$q/quarantined/$f" > /dev/null 2>&1; then
      echo "tar did not carry the quarantine mark to $f; marking the unpacked files, as Archive Utility does"
      xattr -w com.apple.quarantine "$mark" "$q/quarantined/$f"
    fi
    if ! xattr -p com.apple.quarantine "$q/quarantined/$f" > /dev/null 2>&1; then
      echo "package.sh: $f carries no quarantine mark even after xattr -w" >&2
      exit 1
    fi
  done
  status=$(spctl --status 2>&1 || true)
  echo "spctl --status: $status"
  case "$status" in
    *enabled*) ;;
    *)
      echo "SKIP: Gatekeeper assessments are disabled on this runner"
      return
      ;;
  esac
  "$q/quarantined/tswap" prompt-hash
  mkdir -m 700 "$q/config"
  TSWAP_CONFIG_DIR="$q/config" "$q/quarantined/tswap" init --secure-enclave --no-touch --no-password --no-recovery
  TSWAP_CONFIG_DIR="$q/config" "$q/quarantined/tswap" names
  echo "the quarantined copy ran: prompt-hash and a Secure Enclave vault from a simulated browser download"
}

if [ "$smoke" = --smoke ]; then
  check=$(mktemp -d "${TMPDIR:-/tmp}/tswap-check.XXXXXX")
  trap 'rm -rf "$check" "$check".*' EXIT
  tar xzf "$archive" -C "$check"
  version_smoke "$check/tswap"
  "$check/tswap" prompt-hash
  yubikey_smoke '' "$check/tswap"
  case "$rid" in
    linux-*)
      linux_pcsc_smoke "$check/tswap"
      ;;
    osx-*)
      macos_smoke_bytes "$check"
      if [ -n "${TSWAP_EXPECT_TEAM_ID:-}" ]; then
        macos_smoke_signing "$check"
      fi
      mkdir -m 700 "$check/config"
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" init --secure-enclave --no-touch --no-password --no-recovery
      TSWAP_CONFIG_DIR="$check/config" "$check/tswap" names
      echo "Secure Enclave vault made and unlocked by the unpacked tswap (libtswapse.dylib loaded from the archive)"
      if [ -n "${TSWAP_EXPECT_TEAM_ID:-}" ]; then
        macos_smoke_quarantine
      fi
      ;;
  esac
fi
