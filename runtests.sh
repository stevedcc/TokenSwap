#!/usr/bin/env bash
# Run the tswap test suite.
#
#   ./runtests.sh                 all tests (unit + integration; ~40 s)
#   ./runtests.sh --unit          unit tests only (~1 s)
#   ./runtests.sh --integration   ProgramTests only (builds tswap once, then
#                                 spawns the built binary per test)
#
# Tests run sequentially (TswapTests/xunit.runner.json): ProgramTests spawns a
# tswap subprocess per test, and concurrent test hosts each doing that can
# exhaust memory on constrained machines.
set -eo pipefail

FILTER=""
case "${1:-}" in
  --unit)        FILTER="--filter FullyQualifiedName!~ProgramTests" ;;
  --integration) FILTER="--filter FullyQualifiedName~ProgramTests" ;;
  "")            ;;
  *) echo "Usage: $0 [--unit|--integration]" >&2; exit 64 ;;
esac

TSWAP_TEST_KEY="${TSWAP_TEST_KEY:-$(openssl rand -hex 32)}" \
  dotnet test ./TswapTests/TswapTests.csproj $FILTER
