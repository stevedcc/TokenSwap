#!/usr/bin/env bash
# Builds, notarises, checks and test-installs the macOS installer package, tswap-osx-arm64.pkg (issue #240; plan
# docs/superpowers/plans/2026-11-07-macos-signing.md, "The pkg"). Run by release.yml's build-macos job only, after
# sign-macos.sh signed and notarised the two Mach-Os and package.sh packed them; a fork's run (no signing) never calls
# it. bash 3.2 (macOS's own bash). Tested with fake tools by TswapTests/MacPkgScriptTests.cs.
#
#   package-pkg.sh build <publish-dir> <version> <dist-dir>   needs INSTALLER_IDENTITY and KC (keychain-setup's outputs)
#   package-pkg.sh notarise <pkg>                             sign-macos.sh notarise, then staple and validate
#   package-pkg.sh check <pkg> <tarball>                      signature, Gatekeeper, payload = the tarball's bytes
#   package-pkg.sh install-test <pkg>                         install, use, uninstall; a GitHub-hosted runner only
#
# The payload is /usr/local/bin/tswap and /usr/local/bin/libtswapse.dylib, root:wheel 0755; there are no scripts.
# Never add set -x.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=macos/runner-checks.sh
. "$here/macos/runner-checks.sh"
# shellcheck source=macos/macho.sh
. "$here/macos/macho.sh"

pkg_id=dev.crawford.tswap.pkg
pkg_name=tswap-osx-arm64.pkg
files="tswap libtswapse.dylib"

die() {
  echo "package-pkg.sh: $*" >&2
  exit 1
}

require_env() {
  local name missing=
  for name in "$@"; do
    [ -n "${!name:-}" ] || missing="$missing $name"
  done
  [ -z "$missing" ] || die "missing:$missing"
}

new_work() {
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
}

# The minimum macOS the distribution declares.
distribution_min_os() {
  sed -n 's/.*<os-version  *min="\([^"]*\)".*/\1/p' "$here/macos/distribution.xml" | head -n 1
}

cmd_build() {
  local publish=$1 version=$2 dist=$3 f root
  require_env INSTALLER_IDENTITY KC
  for f in $files; do
    [ -f "$publish/$f" ] || die "$publish/$f is missing; a pkg without it would not work"
  done
  # The version goes into the distribution with sed: digits, dots and a pre-release suffix only.
  printf '%s\n' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$' || die "not a version: '$version'"
  new_work
  root="$work/pkgroot"
  mkdir -p "$root/usr/local/bin"
  for f in $files; do
    ditto "$publish/$f" "$root/usr/local/bin/$f"
    chmod 0755 "$root/usr/local/bin/$f"
  done
  # --ownership recommended records root:wheel; no --scripts: nothing runs but Installer itself.
  pkgbuild --root "$root" --identifier "$pkg_id" --version "$version" --install-location / --ownership recommended "$work/component.pkg"
  sed "s/@VERSION@/$version/g" "$here/macos/distribution.xml" > "$work/distribution.xml"
  productbuild --distribution "$work/distribution.xml" --resources "$here/macos/resources" --package-path "$work" "$work/unsigned.pkg"
  productsign --timestamp --keychain "$KC" --sign "$INSTALLER_IDENTITY" "$work/unsigned.pkg" "$work/$pkg_name"
  mkdir -p "$dist"
  # Under a temporary name, then renamed: an interrupted run never leaves a partial pkg under the real name.
  mv -f "$work/$pkg_name" "$dist/$pkg_name.partial"
  mv -f "$dist/$pkg_name.partial" "$dist/$pkg_name"
  echo "built $dist/$pkg_name ($pkg_id $version)"
}

cmd_notarise() {
  local pkg=$1
  [ -f "$pkg" ] || die "$pkg is missing"
  bash "$here/sign-macos.sh" notarise "$pkg"
  xcrun stapler staple "$pkg"
  xcrun stapler validate "$pkg"
  echo "notarised, stapled and validated $pkg"
}

cmd_check() {
  local pkg=$1 tarball=$2 sig first status spctl_out listing entry boms bom payload f line want got
  require_env MACOS_TEAM_ID
  [ -f "$pkg" ] || die "$pkg is missing"
  [ -f "$tarball" ] || die "$tarball is missing"

  sig=$(pkgutil --check-signature "$pkg")
  printf '%s\n' "$sig"
  first=$(printf '%s\n' "$sig" | sed -n 's/^ *1\. //p' | head -n 1)
  case "$first" in
    "Developer ID Installer: "*"($MACOS_TEAM_ID)") ;;
    *) die "the pkg's first certificate is '${first:-missing}', expected Developer ID Installer: … ($MACOS_TEAM_ID)" ;;
  esac
  status=0
  printf '%s\n' "$sig" | grep -q 'Signed with a trusted timestamp' || status=1
  runner_check pkg-timestamp "$status" 'pkgutil --check-signature does not say "Signed with a trusted timestamp"' || exit 1

  spctl_out=$(spctl -a -t install -vv "$pkg" 2>&1) || { printf '%s\n' "$spctl_out"; die "spctl -a -t install rejected $pkg"; }
  printf '%s\n' "$spctl_out"
  if ! printf '%s\n' "$spctl_out" | grep -q ': accepted' || ! printf '%s\n' "$spctl_out" | grep -qx 'source=Notarized Developer ID'; then
    die "spctl -a -t install did not say accepted with source=Notarized Developer ID"
  fi

  # The payload: exactly the two files (and the folders above them).
  listing=$(pkgutil --payload-files "$pkg")
  while IFS= read -r entry; do
    case "$entry" in
      . | ./usr | ./usr/local | ./usr/local/bin | ./usr/local/bin/tswap | ./usr/local/bin/libtswapse.dylib) ;;
      *) die "the payload holds $entry; it must hold only tswap and libtswapse.dylib in /usr/local/bin" ;;
    esac
  done <<< "$listing"
  for f in $files; do
    printf '%s\n' "$listing" | grep -qx "./usr/local/bin/$f" || die "the payload has no ./usr/local/bin/$f"
  done

  new_work
  pkgutil --expand-full "$pkg" "$work/expanded"
  boms=$(find "$work/expanded" -name Bom -type f)
  [ "$(printf '%s\n' "$boms" | grep -c .)" -eq 1 ] || die "expected one component Bom in the expanded pkg, found: ${boms:-none}"
  bom=$boms
  payload="$(dirname "$bom")/Payload/usr/local/bin"
  mkdir "$work/tarball"
  tar xzf "$tarball" -C "$work/tarball"
  for f in $files; do
    cmp -s "$payload/$f" "$work/tarball/$f" || die "$f in the pkg is not the tarball's (both downloads must be the same signed bytes)"
    line=$(lsbom "$bom" | awk -v p="./usr/local/bin/$f" '$1 == p { print $2 " " $3 }')
    [ "$line" = "100755 0/0" ] || die "$f: the Bom says ${line:-nothing}, expected 100755 0/0"
  done
  echo "the payload is the tarball's two files, root:wheel 0755"

  bash "$here/sign-macos.sh" verify "$payload"
  want=$(distribution_min_os)
  got=$(macho_minos "$payload/tswap")
  [ -n "$want" ] && [ "$got" = "$want" ] || die "the payload's minos ${got:-unknown} is not the distribution's <os-version min=\"${want:-missing}\">"
  echo "checked $pkg: Developer ID Installer of $MACOS_TEAM_ID, notarised, payload = tarball, minos $want"
}

cmd_install_test() {
  local pkg=$1 bin owner f script
  # It installs into /usr/local/bin with sudo: only on a throwaway GitHub-hosted VM, never on someone's own Mac.
  if [ "${CI:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    die "install-test writes to /usr/local/bin with sudo: it runs only on a GitHub-hosted runner (CI=true, RUNNER_ENVIRONMENT=github-hosted)"
  fi
  [ -f "$pkg" ] || die "$pkg is missing"
  # TSWAP_PKG_TEST_ROOT: where the suite's fake installer puts the files; unset on a runner (the real /).
  bin="${TSWAP_PKG_TEST_ROOT:-}/usr/local/bin"
  [ ! -e "$bin/tswap" ] || die "/usr/local/bin/tswap already exists: the install test needs a runner without tswap"

  sudo installer -pkg "$pkg" -target /
  for f in $files; do
    owner=$(stat -f '%Su:%Sg %Lp' "$bin/$f")
    [ "$owner" = "root:wheel 755" ] || die "/usr/local/bin/$f is $owner, expected root:wheel 755"
  done
  pkgutil --pkg-info "$pkg_id"
  "$bin/tswap" prompt-hash

  t=$(mktemp -d) # global: the EXIT trap removes it
  trap 'rm -rf "$t"' EXIT
  mkdir -m 700 "$t/config" "$t/home"
  TSWAP_CONFIG_DIR="$t/config" "$bin/tswap" init --secure-enclave --no-touch --no-password --no-recovery
  TSWAP_CONFIG_DIR="$t/config" "$bin/tswap" names
  echo "Secure Enclave vault made and unlocked by the installed tswap"

  script=$("$bin/tswap" installscript)
  if printf '%s\n' "$script" | grep -q 'sudo' \
    || ! printf '%s\n' "$script" | grep -qF 'tswap is already installed at /usr/local/bin/tswap'; then
    printf '%s\n' "$script"
    die "the installed copy's installscript is not the per-user-only script (it must say so and call no sudo)"
  fi
  printf '%s\n' "$script" > "$t/installTswap.sh"
  env -u XDG_DATA_HOME HOME="$t/home" bash "$t/installTswap.sh"
  [ -f "$t/home/.agents/skills/tswap/SKILL.md" ] || die "the per-user install wrote no ~/.agents/skills/tswap/SKILL.md"
  [ -L "$t/home/.claude/skills/tswap" ] || die "the per-user install made no ~/.claude/skills/tswap symlink"
  [ -f "$t/home/.local/share/bash-completion/completions/tswap" ] || die "the per-user install wrote no bash completion"
  echo "per-user install wrote the skill, the Claude Code symlink and the bash completion (no sudo)"

  # The documented uninstall (docs/install.md, "Uninstall"), word for word; MacPkgScriptTests compares the two.
  sudo rm /usr/local/bin/tswap /usr/local/bin/libtswapse.dylib
  sudo pkgutil --forget dev.crawford.tswap.pkg
  for f in $files; do
    [ ! -e "$bin/$f" ] || die "/usr/local/bin/$f is still there after the uninstall"
  done
  if pkgutil --pkg-info "$pkg_id" > /dev/null 2>&1; then
    die "the receipt $pkg_id is still there after pkgutil --forget"
  fi
  echo "uninstalled: both files and the receipt are gone"
}

case "${1:-}" in
  build) [ $# -eq 4 ] || die "usage: package-pkg.sh build <publish-dir> <version> <dist-dir>"; cmd_build "$2" "$3" "$4" ;;
  notarise) [ $# -eq 2 ] || die "usage: package-pkg.sh notarise <pkg>"; cmd_notarise "$2" ;;
  check) [ $# -eq 3 ] || die "usage: package-pkg.sh check <pkg> <tarball>"; cmd_check "$2" "$3" ;;
  install-test) [ $# -eq 2 ] || die "usage: package-pkg.sh install-test <pkg>"; cmd_install_test "$2" ;;
  *)
    echo "usage: $0 build <publish-dir> <version> <dist-dir> | notarise <pkg> | check <pkg> <tarball> | install-test <pkg>" >&2
    exit 2
    ;;
esac
