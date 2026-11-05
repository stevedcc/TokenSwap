# Multi-machine keying: hardware backends and the vault key model

This design record moved to [docs/design/multi-machine-keying.md](docs/design/multi-machine-keying.md).

For setting tswap up, see [docs/setup.md](docs/setup.md).

<details>
<summary>Moved sections</summary>

<a id="scope-v0--v1--v2"></a> [scope-v0--v1--v2](docs/design/multi-machine-keying.md#scope-v0--v1--v2)

<a id="why-broaden-hardware-support-to-grow-adoption"></a> [why-broaden-hardware-support-to-grow-adoption](docs/design/multi-machine-keying.md#why-broaden-hardware-support-to-grow-adoption)

<a id="how-todays-crypto-actually-works-be-precise"></a> [how-todays-crypto-actually-works-be-precise](docs/design/multi-machine-keying.md#how-todays-crypto-actually-works-be-precise)

<a id="the-design-space-and-why-it-all-funnels-to-one-answer"></a> [the-design-space-and-why-it-all-funnels-to-one-answer](docs/design/multi-machine-keying.md#the-design-space-and-why-it-all-funnels-to-one-answer)

<a id="the-secure-enclave-is-the-tiebreaker"></a> [the-secure-enclave-is-the-tiebreaker](docs/design/multi-machine-keying.md#the-secure-enclave-is-the-tiebreaker)

<a id="where-enforcement-can-and-cannot-live-a-standing-rule"></a> [where-enforcement-can-and-cannot-live-a-standing-rule](docs/design/multi-machine-keying.md#where-enforcement-can-and-cannot-live-a-standing-rule)

<a id="the-model-a-keyring-of-wrapped-shares-k--1"></a> [the-model-a-keyring-of-wrapped-shares-k--1](docs/design/multi-machine-keying.md#the-model-a-keyring-of-wrapped-shares-k--1)

<a id="extension-implies-decryption--an-extension-only-recovery-slot-isnt-achievable"></a> [extension-implies-decryption--an-extension-only-recovery-slot-isnt-achievable](docs/design/multi-machine-keying.md#extension-implies-decryption--an-extension-only-recovery-slot-isnt-achievable)

<a id="why-not-k--2-yet"></a> [why-not-k--2-yet](docs/design/multi-machine-keying.md#why-not-k--2-yet)

<a id="two-layer-slot-wrap"></a> [two-layer-slot-wrap](docs/design/multi-machine-keying.md#two-layer-slot-wrap)

<a id="aad-binding"></a> [aad-binding](docs/design/multi-machine-keying.md#aad-binding)

<a id="per-slot-x25519-keypair"></a> [per-slot-x25519-keypair](docs/design/multi-machine-keying.md#per-slot-x25519-keypair)

<a id="yubikey-slots-one-key-per-slot-brief-t4-issue-184"></a> [yubikey-slots-one-key-per-slot-brief-t4-issue-184](docs/design/multi-machine-keying.md#yubikey-slots-one-key-per-slot-brief-t4-issue-184)

<a id="the-recovery-slot-a-bare-keypair-not-a-ca-issued-certificate-a-path-not-taken"></a> [the-recovery-slot-a-bare-keypair-not-a-ca-issued-certificate-a-path-not-taken](docs/design/multi-machine-keying.md#the-recovery-slot-a-bare-keypair-not-a-ca-issued-certificate-a-path-not-taken)

<a id="per-backend-wrap-primitive"></a> [per-backend-wrap-primitive](docs/design/multi-machine-keying.md#per-backend-wrap-primitive)

<a id="hand-carried-enrollment-v0"></a> [hand-carried-enrollment-v0](docs/design/multi-machine-keying.md#hand-carried-enrollment-v0)

<a id="fleet-enrollment-receipts-merge-and-the-recovery-key-brief-t5-issues-190-152-187"></a> [fleet-enrollment-receipts-merge-and-the-recovery-key-brief-t5-issues-190-152-187](docs/design/multi-machine-keying.md#fleet-enrollment-receipts-merge-and-the-recovery-key-brief-t5-issues-190-152-187)

<a id="shared-vault-folders-the-record-store-brief-t6"></a> [shared-vault-folders-the-record-store-brief-t6](docs/design/multi-machine-keying.md#shared-vault-folders-the-record-store-brief-t6)

<a id="record-format-3-metadata-and-value-sections-brief-t16-s1-v020"></a> [record-format-3-metadata-and-value-sections-brief-t16-s1-v020](docs/design/multi-machine-keying.md#record-format-3-metadata-and-value-sections-brief-t16-s1-v020)

<a id="the-vault-password-brief-t17-v020"></a> [the-vault-password-brief-t17-v020](docs/design/multi-machine-keying.md#the-vault-password-brief-t17-v020)

<a id="the-landmine-threshold-downgrade"></a> [the-landmine-threshold-downgrade](docs/design/multi-machine-keying.md#the-landmine-threshold-downgrade)

<a id="how-this-maps-onto-the-code-already-in-the-branch"></a> [how-this-maps-onto-the-code-already-in-the-branch](docs/design/multi-machine-keying.md#how-this-maps-onto-the-code-already-in-the-branch)

<a id="implementation-ordering"></a> [implementation-ordering](docs/design/multi-machine-keying.md#implementation-ordering)

<a id="open-questions"></a> [open-questions](docs/design/multi-machine-keying.md#open-questions)

<a id="deferred-to-v1"></a> [deferred-to-v1](docs/design/multi-machine-keying.md#deferred-to-v1)

</details>
