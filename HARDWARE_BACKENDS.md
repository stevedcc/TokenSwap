# Hardware backends

This design record moved to [docs/design/hardware-backends.md](docs/design/hardware-backends.md).

For the review status and posture of each backend, see [docs/security-model.md](docs/security-model.md).

For setting tswap up, see [docs/setup.md](docs/setup.md).

## Moved sections

Old links to these sections land here.

<a id="the-seam"></a> [the-seam](docs/design/hardware-backends.md#the-seam)

<a id="the-enrollment-seam-issue-151"></a> [the-enrollment-seam-issue-151](docs/design/hardware-backends.md#the-enrollment-seam-issue-151)

<a id="the-simulated-backend-issue-153"></a> [the-simulated-backend-issue-153](docs/design/hardware-backends.md#the-simulated-backend-issue-153)

<a id="tpm-and-secure-enclave-vaults-are-keyring-vaults-brief-t2-decisions-2-and-4"></a> [tpm-and-secure-enclave-vaults-are-keyring-vaults-brief-t2-decisions-2-and-4](docs/design/hardware-backends.md#tpm-and-secure-enclave-vaults-are-keyring-vaults-brief-t2-decisions-2-and-4)

<a id="yubikey-keyring-slots-one-key-per-slot-brief-t4-issue-184"></a> [yubikey-keyring-slots-one-key-per-slot-brief-t4-issue-184](docs/design/hardware-backends.md#yubikey-keyring-slots-one-key-per-slot-brief-t4-issue-184)

<a id="several-keys-plugged-in-and-the-touch-posture-brief-t7-issues-198-and-185"></a> [several-keys-plugged-in-and-the-touch-posture-brief-t7-issues-198-and-185](docs/design/hardware-backends.md#several-keys-plugged-in-and-the-touch-posture-brief-t7-issues-198-and-185)

<a id="a-tpm-or-secure-enclave-machine-joins-a-fleet-brief-t5-issue-152"></a> [a-tpm-or-secure-enclave-machine-joins-a-fleet-brief-t5-issue-152](docs/design/hardware-backends.md#a-tpm-or-secure-enclave-machine-joins-a-fleet-brief-t5-issue-152)

<a id="config-discriminator"></a> [config-discriminator](docs/design/hardware-backends.md#config-discriminator)

<a id="secure-enclave-implemented-runs-unsigned-verified-on-real-hardware"></a> [secure-enclave-implemented-runs-unsigned-verified-on-real-hardware](docs/design/hardware-backends.md#secure-enclave-implemented-runs-unsigned-verified-on-real-hardware)

<a id="under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157"></a> [under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157](docs/design/hardware-backends.md#under-sudo-used-as-the-vault-folders-owner-not-root-brief-t12-issue-157)

<a id="status-poc-grade-not-yet-production-hardened"></a> [status-poc-grade-not-yet-production-hardened](docs/design/hardware-backends.md#status-poc-grade-not-yet-production-hardened)

<a id="touch-or-no-touch-an-explicit-choice-brief-t11"></a> [touch-or-no-touch-an-explicit-choice-brief-t11](docs/design/hardware-backends.md#touch-or-no-touch-an-explicit-choice-brief-t11)

<a id="checking-a-no-touch-secure-enclave-slot-on-a-mac"></a> [checking-a-no-touch-secure-enclave-slot-on-a-mac](docs/design/hardware-backends.md#checking-a-no-touch-secure-enclave-slot-on-a-mac)

<a id="why-a-swift-shim-not-raw-securityframework-pinvoke-the-path-not-taken"></a> [why-a-swift-shim-not-raw-securityframework-pinvoke-the-path-not-taken](docs/design/hardware-backends.md#why-a-swift-shim-not-raw-securityframework-pinvoke-the-path-not-taken)

<a id="the-trade-off-this-brings"></a> [the-trade-off-this-brings](docs/design/hardware-backends.md#the-trade-off-this-brings)

<a id="distribution-the-dylib-is-embedded-not-shipped-as-a-companion-file"></a> [distribution-the-dylib-is-embedded-not-shipped-as-a-companion-file](docs/design/hardware-backends.md#distribution-the-dylib-is-embedded-not-shipped-as-a-companion-file)

<a id="linux-tpm-implemented-verified-on-a-software-simulator-and-on-a-physical-intel-ptt"></a> [linux-tpm-implemented-verified-on-a-software-simulator-and-on-a-physical-intel-ptt](docs/design/hardware-backends.md#linux-tpm-implemented-verified-on-a-software-simulator-and-on-a-physical-intel-ptt)

<a id="status-verified-on-one-physical-tpm-intel-ptt-single-vendor"></a> [status-verified-on-one-physical-tpm-intel-ptt-single-vendor](docs/design/hardware-backends.md#status-verified-on-one-physical-tpm-intel-ptt-single-vendor)

<a id="simulator-phase-before-2026-10-29"></a> [simulator-phase-before-2026-10-29](docs/design/hardware-backends.md#simulator-phase-before-2026-10-29)

<a id="devtest-setup-swtpm-in-a-container"></a> [devtest-setup-swtpm-in-a-container](docs/design/hardware-backends.md#devtest-setup-swtpm-in-a-container)

<a id="why-a-shellout-to-tpm2-tools-not-pinvoke-libtss2-esyslibtss2-fapi-the-path-not-taken"></a> [why-a-shellout-to-tpm2-tools-not-pinvoke-libtss2-esyslibtss2-fapi-the-path-not-taken](docs/design/hardware-backends.md#why-a-shellout-to-tpm2-tools-not-pinvoke-libtss2-esyslibtss2-fapi-the-path-not-taken)

<a id="windows-tpm-implemented-verified-on-a-virtual-tpm-also-run-on-a-physical-one-during-development"></a> [windows-tpm-implemented-verified-on-a-virtual-tpm-also-run-on-a-physical-one-during-development](docs/design/hardware-backends.md#windows-tpm-implemented-verified-on-a-virtual-tpm-also-run-on-a-physical-one-during-development)

<a id="status-virtual-tpm-verified-physical-tpm-tested-during-development-v010-re-check-open"></a> [status-virtual-tpm-verified-physical-tpm-tested-during-development-v010-re-check-open](docs/design/hardware-backends.md#status-virtual-tpm-verified-physical-tpm-tested-during-development-v010-re-check-open)

<a id="virtual-tpm-parallels"></a> [virtual-tpm-parallels](docs/design/hardware-backends.md#virtual-tpm-parallels)

<a id="dev-environment-note-this-vms-internet-connection-is-a-marginal-cellular-link"></a> [dev-environment-note-this-vms-internet-connection-is-a-marginal-cellular-link](docs/design/hardware-backends.md#dev-environment-note-this-vms-internet-connection-is-a-marginal-cellular-link)

<a id="the-vault-password-per-backend-brief-t17"></a> [the-vault-password-per-backend-brief-t17](docs/design/hardware-backends.md#the-vault-password-per-backend-brief-t17)

<a id="linux-tpm-the-auth-value-through-tpm2-tools"></a> [linux-tpm-the-auth-value-through-tpm2-tools](docs/design/hardware-backends.md#linux-tpm-the-auth-value-through-tpm2-tools)

<a id="windows-tpm-pcp_usageauth-at-creation-and-at-use"></a> [windows-tpm-pcp_usageauth-at-creation-and-at-use](docs/design/hardware-backends.md#windows-tpm-pcp_usageauth-at-creation-and-at-use)

<a id="secure-enclave-the-enclave-checks-the-password"></a> [secure-enclave-the-enclave-checks-the-password](docs/design/hardware-backends.md#secure-enclave-the-enclave-checks-the-password)

<a id="yubikey-the-kdf-only"></a> [yubikey-the-kdf-only](docs/design/hardware-backends.md#yubikey-the-kdf-only)

<a id="devtest-swtpm-on-the-build-machine"></a> [devtest-swtpm-on-the-build-machine](docs/design/hardware-backends.md#devtest-swtpm-on-the-build-machine)

<a id="adding-a-backend"></a> [adding-a-backend](docs/design/hardware-backends.md#adding-a-backend)

<a id="redundancy-and-phase-6"></a> [redundancy-and-phase-6](docs/design/hardware-backends.md#redundancy-and-phase-6)
