#!/usr/bin/env bash
# Run the tswap test suite.
#
#   ./runtests.sh            all tests (in-process + E2E; ~40 s, builds tswap once)
#   ./runtests.sh --unit     in-process tests only (~5 s, no subprocess spawning)
#   ./runtests.sh --e2e      end-to-end tests only (spawn the built tswap binary;
#                            set TSWAP_E2E_BINARY to test a pre-built/AOT binary)
set -eo pipefail

FILTER=""
TARGET="./TokenSwap.slnx"
case "${1:-}" in
  --unit)        FILTER="--filter Category!=E2E" ;;
  # E2E tests live only in TswapTests; target that project directly so the
  # filter doesn't produce a "no tests matched" warning in ConsoleIntercept.Tests.
  --e2e|--integration)
                 FILTER="--filter Category=E2E"
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  "")            ;;
  *) echo "Usage: $0 [--unit|--e2e]" >&2; exit 64 ;;
esac

TSWAP_TEST_KEY="${TSWAP_TEST_KEY:-$(openssl rand -hex 32)}" \
  dotnet test "$TARGET" $FILTER
