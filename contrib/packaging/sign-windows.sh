#!/usr/bin/env bash
# Signs the Windows release's tswap.exe with the owner's Certum code-signing key (issue #368, brief T44; maintainer's
# side: docs/windows-signing.md). Run by release.yml's sign-windows job only, on a throwaway ubuntu runner. Tested with
# a fake gh and a fake ssign by TswapTests/SignWindowsScriptTests.cs.
#
#   sign-windows.sh request <exe>              post a signing request on the private issue; print its comment id
#   sign-windows.sh sign <exe> <request-id>    wait for the owner's 6-digit code, delete it, mask it, sign in place
#
# The TOTP seed never comes near GitHub: the owner replies with one code. Only a reply by SIGNING_OWNER, newer than the
# request and every code already tried, holding exactly six digits counts; it is masked before anything else, deleted,
# and given to ssign through its environment only (never an argument), without GH_TOKEN. Never add set -x.
#
# Environment: SIGNING_REPO (default stevedcc/tswap-signing), SIGNING_ISSUE (1), SIGNING_OWNER (stevedcc), SSIGN (the
# ssign binary), SIGN_WAIT_SECONDS (600), SIGN_POLL_SECONDS (3), SIGN_MAX_ATTEMPTS (3), GH_TOKEN (the issue's PAT),
# CERTUM_EMAIL, GITHUB_SERVER_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID.
set -euo pipefail

SIGNING_REPO=${SIGNING_REPO:-stevedcc/tswap-signing}
SIGNING_ISSUE=${SIGNING_ISSUE:-1}
SIGNING_OWNER=${SIGNING_OWNER:-stevedcc}
SIGN_WAIT_SECONDS=${SIGN_WAIT_SECONDS:-600}
SIGN_POLL_SECONDS=${SIGN_POLL_SECONDS:-3}
SIGN_MAX_ATTEMPTS=${SIGN_MAX_ATTEMPTS:-3}

die() {
  echo "::error::$*" >&2
  exit 1
}

# require_env NAME...: every one set and non-empty, else name the missing ones (names only) and fail.
require_env() {
  local name missing=
  for name in "$@"; do
    [ -n "${!name:-}" ] || missing="$missing $name"
  done
  [ -z "$missing" ] || die "sign-windows.sh: missing:$missing"
}

command -v jq > /dev/null 2>&1 || die "jq is needed"

# The file's SHA-256, lower-case hex (sha256sum on Linux, shasum on macOS).
sha256() {
  local sum
  if command -v sha256sum > /dev/null 2>&1; then
    sum=$(sha256sum "$1")
  else
    sum=$(shasum -a 256 "$1")
  fi
  printf '%s\n' "${sum%% *}" | tr '[:upper:]' '[:lower:]'
}

run_url() { printf '%s/%s/actions/runs/%s' "$GITHUB_SERVER_URL" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID"; }

# post <body>: one comment on the signing issue; prints the new comment's id.
post() {
  gh api -X POST "repos/$SIGNING_REPO/issues/$SIGNING_ISSUE/comments" -f body="$1" | jq -r '.id'
}

# u_le <file> <offset> <bytes>: an unsigned little-endian integer read from the file (empty past its end).
u_le() {
  local value=0 shift_by=0 byte bytes
  bytes=$(od -An -tu1 -j "$2" -N "$3" "$1" | tr -s ' \n' ' ')
  set -- $bytes
  [ $# -gt 0 ] || return 1
  for byte in "$@"; do
    value=$((value + (byte << shift_by)))
    shift_by=$((shift_by + 8))
  done
  echo "$value"
}

# B11/C5: refuse an exe that already has a certificate table (PE data directory 4), so a re-run of a finished sign
# job never asks for a code or signs twice; refuse anything that isn't a PE file.
refuse_signed() {
  local exe=$1 lfanew magic dirs va size
  [ "$(head -c 2 "$exe")" = MZ ] || die "$exe is not a PE file"
  lfanew=$(u_le "$exe" 60 4) || die "$exe is not a PE file"
  [ "$(u_le "$exe" "$lfanew" 4 || true)" = 17744 ] || die "$exe is not a PE file"
  magic=$(u_le "$exe" $((lfanew + 24)) 2) || die "$exe is not a PE file"
  case $magic in
    267) dirs=$((lfanew + 24 + 96)) ;;
    523) dirs=$((lfanew + 24 + 112)) ;;
    *) die "$exe is not a PE file" ;;
  esac
  va=$(u_le "$exe" $((dirs + 32)) 4) || die "$exe is not a PE file"
  size=$(u_le "$exe" $((dirs + 36)) 4) || die "$exe is not a PE file"
  if [ "$va" -ne 0 ] || [ "$size" -ne 0 ]; then
    die "tswap.exe is already signed (a re-run of a finished sign job?)"
  fi
}

cmd_request() {
  [ $# -eq 1 ] || die "usage: sign-windows.sh request <exe>"
  local exe=$1 hash id
  [ -f "$exe" ] || die "no file $exe"
  require_env GH_TOKEN GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_RUN_ID
  hash=$(sha256 "$exe")
  id=$(post "Signing request: $(run_url) wants to sign tswap.exe, SHA-256 $hash. Reply with the 6-digit code.")
  [[ $id =~ ^[0-9]+$ ]] || die "the signing request was posted, but GitHub returned no comment id"
  echo "$id"
}

# The oldest counting comment, as "<id> <code>": by the owner, newer than the floor, six digits and nothing else but
# surrounding whitespace. --paginate prints one array per page, oldest first; the first match in the stream wins (C6).
next_code() {
  gh api "repos/$SIGNING_REPO/issues/$SIGNING_ISSUE/comments?per_page=100" --paginate \
    | jq -rn --arg owner "$SIGNING_OWNER" --argjson floor "$1" '
        first(inputs | .[]
          | select(.user.login == $owner and .id > $floor and ((.body // "") | test("\\A\\s*[0-9]{6}\\s*\\z"))))
        | "\(.id) \(.body | capture("(?<c>[0-9]{6})").c)"'
}

cmd_sign() {
  [ $# -eq 2 ] || die "usage: sign-windows.sh sign <exe> <request-id>"
  local exe=$1 floor=$2 deadline attempts=0 status found id code
  [ -f "$exe" ] || die "no file $exe"
  [[ $floor =~ ^[0-9]+$ ]] || die "the request id is not a number"
  require_env GH_TOKEN CERTUM_EMAIL SSIGN GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_RUN_ID
  refuse_signed "$exe"
  deadline=$(($(date +%s) + SIGN_WAIT_SECONDS))

  while :; do
    found=$(next_code "$floor")
    if [ -n "$found" ]; then
      read -r id code <<< "$found"
      unset found
      # Masked first: from here on the log shows *** wherever the code would appear.
      printf '::add-mask::%s\n' "$code"
      if ! gh api -X DELETE "repos/$SIGNING_REPO/issues/comments/$id" > /dev/null; then
        echo "::warning::could not delete the code comment $id"
        post "Could not delete comment $id; delete it by hand." > /dev/null
      fi
      # A code is tried once: whatever happens, this comment is the new floor.
      floor=$id
      attempts=$((attempts + 1))
      status=0
      CERTUM_EMAIL="$CERTUM_EMAIL" CERTUM_TOKEN="$code" env -u GH_TOKEN "$SSIGN" --timestamp-url http://time.certum.pl/ -n tswap -u https://github.com/stevedcc/TokenSwap "$exe" || status=$?
      # ssign has no logout: removing its session file ends local reuse (the token expires at Certum after ~30 min).
      rm -f "${XDG_RUNTIME_DIR:-$HOME/.cache}/ssign/session.json"
      unset code
      if [ "$status" -eq 0 ]; then
        post "Signed: $(run_url), SHA-256 $(sha256 "$exe")." > /dev/null
        exit 0
      fi
      if [ "$attempts" -ge "$SIGN_MAX_ATTEMPTS" ]; then
        post "Signing failed after $SIGN_MAX_ATTEMPTS attempts." > /dev/null
        echo "::error::Windows signing failed after $SIGN_MAX_ATTEMPTS attempts"
        exit 1
      fi
      post "Code not accepted (attempt $attempts of $SIGN_MAX_ATTEMPTS); reply with a new code." > /dev/null
      continue
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      post "Timed out waiting for a code; the run fails." > /dev/null
      echo "::error::no signing code within $SIGN_WAIT_SECONDS s"
      exit 1
    fi
    sleep "$SIGN_POLL_SECONDS"
  done
}

case "${1:-}" in
  request) shift; cmd_request "$@" ;;
  sign) shift; cmd_sign "$@" ;;
  *) die "usage: sign-windows.sh request <exe> | sign <exe> <request-id>" ;;
esac
