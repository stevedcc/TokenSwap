# shellcheck shell=bash
# Mach-O helpers of the macOS release scripts (issues #240, #265). Sourced; bash 3.2.

# macho_minos <file>: the minimum macOS its LC_BUILD_VERSION declares (vtool -show-build, else otool -l), or nothing.
macho_minos() {
  local out
  if command -v vtool > /dev/null 2>&1; then
    out=$(vtool -show-build "$1" 2> /dev/null) || out=
  fi
  if [ -z "${out:-}" ]; then
    out=$(otool -l "$1" 2> /dev/null) || out=
  fi
  printf '%s\n' "$out" | awk '$1 == "minos" { print $2; exit }'
}
