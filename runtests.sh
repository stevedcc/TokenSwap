#!/usr/bin/env bash
# Run the tswap test suite.
#
#   ./runtests.sh                  all tests except hardware-gated (in-process + E2E; ~40 s)
#   ./runtests.sh --unit           in-process tests only (~5 s, no subprocess spawning)
#   ./runtests.sh --e2e            end-to-end tests only (spawn the built tswap binary;
#                                  set TSWAP_E2E_BINARY to test a pre-built/AOT binary)
#   ./runtests.sh --secure-enclave Secure Enclave backend tests (macOS + real hardware only;
#                                  prompts for biometry/presence)
set -eo pipefail

# Array so the xUnit '&' (AND) in a compound filter isn't treated as a shell operator.
FILTER=()
TARGET="./TokenSwap.slnx"
case "${1:-}" in
  --unit)        FILTER=(--filter 'Category!=E2E&Category!=SecureEnclave') ;;
  # E2E tests live only in TswapTests; target that project directly so the
  # filter doesn't produce a "no tests matched" warning in ConsoleIntercept.Tests.
  --e2e|--integration)
                 FILTER=(--filter 'Category=E2E')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # Secure Enclave tests are macOS-only and prompt for biometry; run them on purpose.
  --secure-enclave)
                 FILTER=(--filter 'Category=SecureEnclave')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # Default: everything except the hardware-gated Secure Enclave tests.
  "")            FILTER=(--filter 'Category!=SecureEnclave') ;;
  *) echo "Usage: $0 [--unit|--e2e|--secure-enclave]" >&2; exit 64 ;;
esac

TSWAP_TEST_KEY="${TSWAP_TEST_KEY:-$(openssl rand -hex 32)}" \
  dotnet test "$TARGET" "${FILTER[@]}"
