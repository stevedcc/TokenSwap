#!/usr/bin/env bash
# Run the tswap test suite.
#
#   ./runtests.sh                  all tests except hardware-gated and Perf (in-process + E2E; ~40 s)
#   ./runtests.sh --unit           in-process tests only (~5 s, no subprocess spawning; no Perf)
#   ./runtests.sh --e2e            end-to-end tests only (spawn the built tswap binary;
#                                  set TSWAP_E2E_BINARY to test a pre-built/AOT binary)
#   ./runtests.sh --secure-enclave Secure Enclave backend tests (macOS + real hardware only;
#                                  prompts for biometry/presence)
#   ./runtests.sh --tpm            Linux TPM backend tests (Linux + tpm2-tools required; needs
#                                  a reachable TPM 2.0 device or swtpm simulator — see
#                                  docs/design/hardware-backends.md's Linux TPM section)
#   ./runtests.sh --tpm-windows    Windows TPM backend tests (Windows + a TPM 2.0 device or
#                                  virtual TPM required — see docs/design/hardware-backends.md's Windows
#                                  TPM section)
#   ./runtests.sh --yubikey        YubiKey tests through Yubico's SDK (a real key plugged in;
#                                  TSWAP_TEST_YUBIKEY_SERIAL names it; TSWAP_TEST_FIDO2=1 runs
#                                  the read-only FIDO2 ones)
#   ./runtests.sh --perf           Category=Perf: wall-clock budgets, out of every default and CI
#                                  run (#300). Alone it runs the Argon2 budgets (vault password
#                                  under 1 s, export KDF under 3 s); the redaction throughput
#                                  measurement also needs TSWAP_PERF=1 (and a Release build, see
#                                  RunRedactionThroughputTests). Run it on the owner's machines
#                                  before a release and after any change to VaultPasswordParams
#                                  or the KDFs.
set -eo pipefail

# Array so the xUnit '&' (AND) in a compound filter isn't treated as a shell operator.
FILTER=()
TARGET="./TokenSwap.slnx"
case "${1:-}" in
  --unit)        FILTER=(--filter 'Category!=E2E&Category!=SecureEnclave&Category!=Tpm&Category!=TpmWindows&Category!=YubiKey&Category!=Perf') ;;
  --e2e|--integration)
                 FILTER=(--filter 'Category=E2E')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # Secure Enclave tests are macOS-only and prompt for biometry; run them on purpose.
  --secure-enclave)
                 FILTER=(--filter 'Category=SecureEnclave')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # TPM tests are Linux-only and need a reachable TPM/simulator; run them on purpose.
  --tpm)         FILTER=(--filter 'Category=Tpm')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # TPM tests are Windows-only and need a reachable TPM/virtual TPM; run them on purpose.
  --tpm-windows) FILTER=(--filter 'Category=TpmWindows')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # Wall-clock budgets only mean something on the owner's machines; run them on purpose.
  --perf)        FILTER=(--filter 'Category=Perf')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # YubiKey tests need a real key plugged in; run them on purpose.
  --yubikey)     FILTER=(--filter 'Category=YubiKey')
                 TARGET="./TswapTests/TswapTests.csproj" ;;
  # Default: everything except the hardware-gated Secure Enclave/TPM/YubiKey tests and the Perf budgets.
  "")            FILTER=(--filter 'Category!=SecureEnclave&Category!=Tpm&Category!=TpmWindows&Category!=YubiKey&Category!=Perf') ;;
  *) echo "Usage: $0 [--unit|--e2e|--secure-enclave|--tpm|--tpm-windows|--yubikey|--perf]" >&2; exit 64 ;;
esac

TSWAP_TEST_KEY="${TSWAP_TEST_KEY:-$(openssl rand -hex 32)}" \
  dotnet test "$TARGET" "${FILTER[@]}"
