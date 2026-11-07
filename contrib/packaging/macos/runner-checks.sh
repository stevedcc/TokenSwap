# shellcheck shell=bash
# The report-only mechanism of the macOS release scripts (issue #240; plan
# docs/superpowers/plans/2026-11-07-macos-signing.md, "Report-only checks"). Sourced by sign-macos.sh, package.sh and
# package-pkg.sh; bash 3.2 (macOS's own bash).
#
# A few checks rest on what Apple's tools print or answer on GitHub's runner, which the first dry run shows for the
# first time (the notarisation check of a bare Mach-O, the dylib's runtime flag, pkgutil's timestamp wording). Until
# that run has been read and the strings copied into the checks, they report instead of failing, so the dry run
# doesn't go red one unknown string at a time. Setting TSWAP_MACOS_GATE_RUNNER_CHECKS=1 (release.yml's build-macos
# job, from the dry run's follow-up commit on) makes them gate like every other check.
#
#   runner_check <id> <status> <message>
#     status 0: passed, prints "<id>: ok".
#     otherwise, gated:      prints "::error::<id>: <message>" on stderr and returns 1 (the caller exits).
#     otherwise, not gated:  prints "REPORT-ONLY <id>: <message>" and a ::warning:: with the same text; returns 0.
runner_check() {
  local id=$1 status=$2 message=$3
  if [ "$status" = 0 ]; then
    echo "$id: ok"
    return 0
  fi
  if [ "${TSWAP_MACOS_GATE_RUNNER_CHECKS:-}" = 1 ]; then
    echo "::error::$id: $message" >&2
    return 1
  fi
  echo "REPORT-ONLY $id: $message"
  echo "::warning::REPORT-ONLY $id: $message"
  return 0
}
