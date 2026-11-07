#!/usr/bin/env bash
# Signs and notarises the macOS release's two Mach-O files (issue #240; plan
# docs/superpowers/plans/2026-11-07-macos-signing.md). Run by release.yml's build-macos job only, on a throwaway
# GitHub runner; bash 3.2 (macOS's own bash). Tested with fake tools by TswapTests/MacSigningScriptTests.cs.
#
#   sign-macos.sh keychain-setup          import both Developer ID identities into a throwaway keychain
#   sign-macos.sh sign <publish-dir>      sign tswap (the build signed libtswapse.dylib before embedding it)
#   sign-macos.sh verify <dir>            check both files' signatures, team, runtime, timestamp, minos
#   sign-macos.sh zip-for-notary <dir> <out.zip>   a zip of exactly tswap and libtswapse.dylib
#   sign-macos.sh notarise <file>         submit a zip or a pkg, wait, fetch and print the log; Accepted or fail
#   sign-macos.sh keychain-cleanup        delete the keychain and any decoded key material; never fails
#
# Secrets come from the environment only, never from arguments (nothing in ps or in the log's command echo), except
# `security import -P`, which has no other way to take the .p12 password, on an ephemeral runner VM. Never add set -x.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=macos/runner-checks.sh
. "$here/macos/runner-checks.sh"
# shellcheck source=macos/macho.sh
. "$here/macos/macho.sh"

keychain_name=tswap-signing.keychain-db

die() {
  echo "sign-macos.sh: $*" >&2
  exit 1
}

# require_env NAME...: every one set and non-empty, else name the missing ones (names only) and fail.
require_env() {
  local name missing=
  for name in "$@"; do
    [ -n "${!name:-}" ] || missing="$missing $name"
  done
  [ -z "$missing" ] || die "missing:$missing"
}

# codesign -d writes its report to stderr.
details() { codesign -dvvv "$1" 2>&1; }
field() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1; }

cmd_keychain_setup() {
  require_env MACOS_SIGN_APP_P12_BASE64 MACOS_SIGN_INSTALLER_P12_BASE64 MACOS_SIGN_P12_PASSWORD MACOS_TEAM_ID RUNNER_TEMP GITHUB_OUTPUT
  umask 077
  kc="$RUNNER_TEMP/$keychain_name"
  app_p12="$RUNNER_TEMP/tswap-app.p12"
  installer_p12="$RUNNER_TEMP/tswap-installer.p12"
  setup_done=
  # Its own trap: a failed or cancelled run leaves no decoded .p12 and no keychain, even if the job's cleanup step
  # never runs.
  trap setup_exit EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  printf '%s' "$MACOS_SIGN_APP_P12_BASE64" | base64 --decode > "$app_p12" || die "MACOS_SIGN_APP_P12_BASE64 is not base64"
  printf '%s' "$MACOS_SIGN_INSTALLER_P12_BASE64" | base64 --decode > "$installer_p12" || die "MACOS_SIGN_INSTALLER_P12_BASE64 is not base64"

  local kc_password p12 out
  kc_password=$(openssl rand -hex 24)
  echo "::add-mask::$kc_password"
  security create-keychain -p "$kc_password" "$kc"
  security set-keychain-settings -lut 21600 "$kc"
  security unlock-keychain -p "$kc_password" "$kc"
  for p12 in "$app_p12" "$installer_p12"; do
    # -T: only codesign and productsign may use the keys (not -A, which allows every program).
    if ! out=$(security import "$p12" -k "$kc" -f pkcs12 -P "$MACOS_SIGN_P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/productsign 2>&1); then
      printf '%s\n' "$out" >&2
      die "importing $(basename "$p12") failed. MAC verification failed means a wrong password or a .p12 not made with PBE-SHA1-3DES and a SHA-1 MAC (plan G2b)"
    fi
  done
  rm -f "$app_p12" "$installer_p12"
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kc_password" "$kc" > /dev/null

  # The keychain goes first on the user's search list (codesign's --keychain alone doesn't search it for the chain).
  local existing=() line
  while IFS= read -r line; do
    line=${line#*\"}
    line=${line%\"*}
    [ -n "$line" ] && existing+=("$line")
  done < <(security list-keychains -d user)
  security list-keychains -d user -s "$kc" "${existing[@]+"${existing[@]}"}"

  local app installer
  app=$(pick_identity codesigning "Developer ID Application") || exit 1
  installer=$(pick_identity basic "Developer ID Installer") || exit 1
  echo "Developer ID Application identity: $app"
  echo "Developer ID Installer identity: $installer"
  {
    echo "app_identity=${app%% *}"
    echo "installer_identity=${installer%% *}"
    echo "keychain=$kc"
  } >> "$GITHUB_OUTPUT"
  setup_done=1
}

setup_exit() {
  local status=$?
  rm -f "$app_p12" "$installer_p12"
  if [ -z "$setup_done" ] && [ -e "$kc" ]; then
    security delete-keychain "$kc" > /dev/null 2>&1 || rm -f "$kc"
  fi
  return "$status"
}

# pick_identity <policy> <kind>: the SHA-1 of the one "<kind>: … ($MACOS_TEAM_ID)" identity in the keychain; else
# fail, listing the subjects found (never a key).
pick_identity() {
  local policy=$1 kind=$2 listing matches count
  listing=$(security find-identity -v -p "$policy" "$kc")
  matches=$(printf '%s\n' "$listing" | grep -E "^ *[0-9]+\) [0-9A-F]{40} \"$kind: .*\\($MACOS_TEAM_ID\\)\"\$" || true)
  count=$(printf '%s' "$matches" | grep -c . || true)
  if [ "$count" -ne 1 ]; then
    echo "sign-macos.sh: expected exactly one \"$kind\" identity of team $MACOS_TEAM_ID, found $count. Identities in the keychain ($policy):" >&2
    printf '%s\n' "$listing" | sed -nE 's/^ *[0-9]+\) [0-9A-F]{40} (".*")$/  \1/p' >&2
    return 1
  fi
  # The hash and the subject (task 10 records the subjects); never a key.
  printf '%s\n' "$matches" | sed -E 's/^ *[0-9]+\) ([0-9A-F]{40}) (".*")$/\1 \2/'
}

cmd_sign() {
  local dir=${1:?usage: sign-macos.sh sign <publish-dir>} team
  require_env APP_IDENTITY KC MACOS_TEAM_ID
  [ -f "$dir/tswap" ] || die "$dir/tswap is missing"
  [ -f "$dir/libtswapse.dylib" ] || die "$dir/libtswapse.dylib is missing"
  # The dylib is embedded into tswap for installscript, so it must have been signed before that, by the build.
  team=$(field "$(details "$dir/libtswapse.dylib")" TeamIdentifier)
  [ "$team" = "$MACOS_TEAM_ID" ] \
    || die "libtswapse.dylib was not signed by the build (TswapMacSignIdentity): TeamIdentifier=${team:-none}, expected $MACOS_TEAM_ID"
  # --keychain before --sign, and --sign before --options: codesign(1) ignores options given before --sign.
  codesign --keychain "$KC" --sign "$APP_IDENTITY" --options runtime --timestamp --force --identifier dev.crawford.tswap "$dir/tswap"
  echo "signed $dir/tswap"
}

# verify_file <path> <identifier>: appends a line per failed field to $failures.
verify_file() {
  local path=$1 identifier=$2 name d value flags
  name=$(basename "$path")
  if [ ! -f "$path" ]; then
    failures="$failures"$'\n'"$name: missing"
    return
  fi
  codesign --verify --strict --verbose=2 "$path" || failures="$failures"$'\n'"$name: codesign --verify --strict failed"
  d=$(details "$path")
  printf '%s\n' "$d"
  value=$(field "$d" TeamIdentifier)
  [ "$value" = "$MACOS_TEAM_ID" ] || failures="$failures"$'\n'"$name: TeamIdentifier is ${value:-missing}, expected $MACOS_TEAM_ID"
  value=$(field "$d" Identifier)
  [ "$value" = "$identifier" ] || failures="$failures"$'\n'"$name: Identifier is ${value:-missing}, expected $identifier"
  value=$(field "$d" Authority)
  case "$value" in
    "Developer ID Application: "*) ;;
    *) failures="$failures"$'\n'"$name: the first Authority= is '${value:-missing}', expected Developer ID Application: …" ;;
  esac
  printf '%s\n' "$d" | grep -q '^Timestamp=' || failures="$failures"$'\n'"$name: no Timestamp= line (no secure timestamp)"
  # The token, not the hex: other flag bits may be set beside runtime.
  flags=0
  printf '%s\n' "$d" | grep -qE 'flags=0x[0-9a-fA-F]+\(([^)]*,)?runtime(,[^)]*)?\)' || flags=1
  if [ "$name" = libtswapse.dylib ]; then
    # Whether codesign records runtime on a library at all is what the first dry run shows (report-only until then).
    runner_check dylib-runtime "$flags" "$name: flags= does not name runtime" || failures="$failures"$'\n'"$name: flags= does not name runtime"
  elif [ "$flags" != 0 ]; then
    failures="$failures"$'\n'"$name: flags= does not name runtime (the hardened runtime)"
  fi
}

cmd_verify() {
  local dir=${1:?usage: sign-macos.sh verify <dir>} entitlements tswap_minos dylib_minos
  require_env MACOS_TEAM_ID
  failures=
  verify_file "$dir/libtswapse.dylib" dev.crawford.tswap.libtswapse
  verify_file "$dir/tswap" dev.crawford.tswap
  if [ -f "$dir/tswap" ]; then
    if ! entitlements=$(codesign -d --entitlements - "$dir/tswap" 2> /dev/null); then
      failures="$failures"$'\n'"tswap: codesign -d --entitlements failed"
    elif [ -n "$(printf '%s' "$entitlements" | tr -d '[:space:]')" ]; then
      printf '%s\n' "$entitlements"
      failures="$failures"$'\n'"tswap: has entitlements; it must have none"
    fi
  fi
  tswap_minos=$(macho_minos "$dir/tswap")
  dylib_minos=$(macho_minos "$dir/libtswapse.dylib")
  echo "minos: tswap ${tswap_minos:-unknown}, libtswapse.dylib ${dylib_minos:-unknown}"
  if [ -z "$tswap_minos" ] || [ "$tswap_minos" != "$dylib_minos" ]; then
    failures="$failures"$'\n'"minos differs: tswap ${tswap_minos:-unknown}, libtswapse.dylib ${dylib_minos:-unknown}"
  fi
  if [ -n "$failures" ]; then
    echo "sign-macos.sh: verify failed:$failures" >&2
    exit 1
  fi
  echo "verified $dir/tswap and $dir/libtswapse.dylib"
}

cmd_zip_for_notary() {
  local dir=${1:?usage: sign-macos.sh zip-for-notary <dir> <out.zip>} out=${2:?usage: sign-macos.sh zip-for-notary <dir> <out.zip>} f
  stage=$(mktemp -d)
  trap 'rm -rf "$stage"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  for f in tswap libtswapse.dylib; do
    [ -f "$dir/$f" ] || die "$dir/$f is missing"
    ditto "$dir/$f" "$stage/$f"
  done
  mkdir -p "$(dirname "$out")"
  ditto -c -k "$stage" "$out"
  echo "zipped tswap and libtswapse.dylib into $out"
}

cmd_notarise() {
  local file=${1:?usage: sign-macos.sh notarise <file>} name out err status=0 id result log
  require_env MACOS_NOTARY_KEY_P8_BASE64 MACOS_NOTARY_KEY_ID MACOS_NOTARY_ISSUER_ID RUNNER_TEMP
  [ -f "$file" ] || die "$file is missing"
  umask 077
  key_dir=$(mktemp -d "$RUNNER_TEMP/notary-key.XXXXXX")
  trap 'rm -rf "$key_dir"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  local key="$key_dir/AuthKey_$MACOS_NOTARY_KEY_ID.p8"
  printf '%s' "$MACOS_NOTARY_KEY_P8_BASE64" | base64 --decode > "$key" || die "MACOS_NOTARY_KEY_P8_BASE64 is not base64"
  local auth=(--key "$key" --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER_ID")

  # The whole file name: the zip and the pkg share the stem tswap-osx-arm64, and each keeps its own log.
  name=$(basename "$file")
  err="$key_dir/submit.err"
  echo "submitting $file to Apple's notary service (waits up to 40 minutes)"
  out=$(xcrun notarytool submit "$file" "${auth[@]}" --wait --timeout 40m --output-format json 2> "$err") || status=$?
  printf '%s\n' "$out"
  cat "$err" >&2
  # Apple's code, not any 1048 (a submission id can hold those digits): as a word of its own, outside the JSON's id.
  if grep -qE '(^|[^0-9A-Za-z-])1048([^0-9A-Za-z-]|$)' "$err" \
    || printf '%s\n' "$out" | sed 's/"id" *: *"[^"]*"//' | grep -qE '(^|[^0-9A-Za-z-])1048([^0-9A-Za-z-]|$)'; then
    echo "::error::notarytool answered error 1048: the Account Holder must accept Apple's current developer agreements at https://appstoreconnect.apple.com, then rerun the job"
  fi
  id=$(printf '%s\n' "$out" | sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' | head -n 1)
  result=$(printf '%s\n' "$out" | sed -n 's/.*"status" *: *"\([^"]*\)".*/\1/p' | head -n 1)
  if [ -n "$id" ]; then
    log="$RUNNER_TEMP/notary-log-$name.json"
    if xcrun notarytool log "$id" "${auth[@]}" "$log"; then
      echo "notary log ($log), issues:"
      sed -n '/"issues"/,$p' "$log"
    else
      echo "::warning::could not fetch the notary log of submission $id"
    fi
  fi
  if [ "$status" -ne 0 ] || [ "$result" != Accepted ]; then
    die "notarisation of $(basename "$file"): status ${result:-unknown} (submission ${id:-none}, notarytool exit $status)"
  fi
  echo "notarised $(basename "$file"): submission $id Accepted"
}

cmd_keychain_cleanup() {
  local temp=${RUNNER_TEMP:-} kc
  if [ -n "$temp" ]; then
    kc="$temp/$keychain_name"
    if [ -e "$kc" ]; then
      security delete-keychain "$kc" > /dev/null 2>&1 || true
      rm -f "$kc"
    fi
    rm -f "$temp/tswap-app.p12" "$temp/tswap-installer.p12"
    rm -rf "$temp"/notary-key.*
  fi
  echo "keychain and key material removed"
  exit 0
}

case "${1:-}" in
  keychain-setup) cmd_keychain_setup ;;
  sign) cmd_sign "${2:-}" ;;
  verify) cmd_verify "${2:-}" ;;
  zip-for-notary) cmd_zip_for_notary "${2:-}" "${3:-}" ;;
  notarise) cmd_notarise "${2:-}" ;;
  keychain-cleanup) cmd_keychain_cleanup ;;
  *)
    echo "usage: $0 keychain-setup | sign <publish-dir> | verify <dir> | zip-for-notary <dir> <out.zip> | notarise <file> | keychain-cleanup" >&2
    exit 2
    ;;
esac
