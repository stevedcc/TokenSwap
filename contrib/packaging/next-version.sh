#!/usr/bin/env bash
# next-version.sh <released-version>: the version main's <Version> moves to after that release (brief T18 addendum,
# owner 2026-11-09), for release.yml's bump-version job.
#   0.3.0 -> 0.3.1, 0.9.9 -> 0.9.10: the next patch, printed on stdout.
#   A prerelease (0.3.0-rc.1): nothing on stdout, a notice on stderr, exit 0. Its final release is still to come, so
#   main keeps the version it has.
#   Anything else (a v prefix, build metadata, leading zeros, not three numbers): exit 2, nothing on stdout.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <released-version>" >&2
  exit 2
fi
released=$1
number='(0|[1-9][0-9]*)'

if [[ $released =~ ^$number\.$number\.$number$ ]]; then
  echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
elif [[ $released =~ ^$number\.$number\.$number-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*$ ]]; then
  echo "next-version.sh: $released is a prerelease: no bump (its final release is still to come)" >&2
else
  echo "next-version.sh: '$released' is not a version (expected <major>.<minor>.<patch>, optionally -<prerelease>)" >&2
  exit 2
fi
