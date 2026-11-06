# yk-spike (throwaway)

The stage-0 spike for docs/superpowers/plans/2026-11-04-yubikey-sdk-spike.md. Not part of TokenSwap.slnx, not
product code. Every command prints `key=value` lines; secrets and hmac-secret outputs appear only as `h=`/`output_h=`
(the first 16 hex characters of their SHA-256), never raw.

## FIDO2 Windows gate check (2026-11-06)

Answers the Windows questions of the FIDO2 slot design (fido2 design, "Calls after the builder check"): can a
**NativeAOT** build make a credential through `webauthn.dll` (hmac-secret on, non-discoverable, PIN + touch), does
Windows keep the key's AAGUID under attestation "none", and does a PIN-verified assertion give the same output on
Windows and Linux, in both directions.

What it does with the key: it uses the key's own FIDO2 PIN and about three touches (one to create the credential,
two to assert it; Windows' dialog asks for the PIN each time). The credential is non-discoverable for
`tswap-spike.invalid`, so nothing is stored on the key and there is nothing to clean up. Neither tswap nor the spike
ever retries a wrong PIN: if a PIN is rejected, cancel, and rerun when ready (each wrong PIN costs one of the key's
tries). Plug in only the key under test.

### 1. Windows

Needs the .NET 10 SDK and the Visual Studio Build Tools with the "Desktop development with C++" workload (NativeAOT
links with it; there is no JIT fallback in this check). Run as a normal user, not elevated.

```powershell
git clone -b design/yubikey-sdk https://github.com/stevedcc/TokenSwap.git
cd TokenSwap\spikes\yubikey-sdk
# an existing clone instead: git fetch origin; git checkout design/yubikey-sdk; git pull; cd spikes\yubikey-sdk
powershell -ExecutionPolicy Bypass -File .\fido2-windows-check.ps1
```

The script publishes NativeAOT into `out\` (and stops on any IL2xxx/IL3xxx warning), runs `env` (must say
`aot=True`), `fido2-enroll --out out\cred-windows.json`, then `fido2-assert --cred out\cred-windows.json` (two
assertions, PIN + touch each). Everything goes to `out\fido2-windows-report.txt`. If the AAGUID comes back all zero
under attestation "none", it offers to enrol once more with `--attestation direct` (into `out\cred-windows-direct.json`).
If a `cred-linux.json` (made on Linux, step 3) sits next to the script, it offers to assert that one too.

What to look for in the report: `aot=True`, `webauthn_api=`, `hmac_secret_created=True`, `attestation_format=`,
`aaguid=` / `aaguid_zero=False`, `uv_flag=True,True`, `deterministic=True`, and `output_h=`.

### 2. Linux: assert the Windows credential

Copy `out\cred-windows.json` (and the report) to the Linux machine, put `cred-windows.json` into
`spikes/yubikey-sdk/` of the same branch, then:

```bash
cd spikes/yubikey-sdk
./publish.sh
./out/yk-spike fido2-assert --uv --cred cred-windows.json
```

`--uv` makes a PIN-verified assertion through the SDK (it asks for the FIDO2 PIN once, then two touches). Its
`output_h` must equal the Windows `output_h`, with `uv_flag=True,True`. Without `--uv` the assertion is touch only,
which the key answers from a different hmac-secret: a different `output_h` there is expected, not a failure.

### 3. The other direction: a Linux credential on Windows

```bash
./out/yk-spike fido2-enroll --out cred-linux.json          # PIN + touch
./out/yk-spike fido2-assert --uv --cred cred-linux.json    # note output_h
```

Copy `cred-linux.json` into `spikes\yubikey-sdk\` on Windows and run the check script again (or just
`.\out\yk-spike.exe fido2-assert --cred cred-linux.json`): its `output_h` must equal the Linux `--uv` one.

`cred*.json` files are ignored by git; they hold only the relying party id and the credential id, no secret.
