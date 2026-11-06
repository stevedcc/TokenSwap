# The FIDO2 "Windows gate" check (docs/superpowers/specs/2026-11-06-fido2-slot-design.md in the fido2 design, "Calls
# after the builder check"): a NativeAOT yk-spike makes a FIDO2 credential through webauthn.dll (hmac-secret on,
# non-discoverable, PIN + touch) and asserts it twice with PIN + touch. Everything lands in out\fido2-windows-report.txt;
# outputs only as 16-hex-character hashes, never raw.
#
#   powershell -ExecutionPolicy Bypass -File .\fido2-windows-check.ps1
#
# Windows PowerShell 5.1 compatible on purpose (no ?? or ternaries).
$ErrorActionPreference = 'Continue' # native commands; exit codes are checked explicitly
Set-Location $PSScriptRoot
$out = Join-Path $PSScriptRoot 'out'
$exe = Join-Path $out 'yk-spike.exe'
$report = Join-Path $out 'fido2-windows-report.txt'
$cred = Join-Path $out 'cred-windows.json'
$credDirect = Join-Path $out 'cred-windows-direct.json'

Write-Host @"

yk-spike: FIDO2 Windows gate check
----------------------------------
What this does with your YubiKey:
  * It uses your key's FIDO2 PIN (the one you already use; Windows' own security key dialog asks for it) and
    about three touches: one to create a test credential, two to read it back.
  * The test credential is non-discoverable (relying party tswap-spike.invalid): nothing is stored on the key,
    so it takes no space and needs no clean-up.
  * Neither tswap nor this spike ever retries a wrong PIN. If Windows says the PIN was wrong, cancel the dialog
    instead of typing it again, and rerun this script when ready: every wrong PIN uses up one of the key's tries.
  * Plug in only the one YubiKey you want to test.

First it publishes yk-spike as NativeAOT (needs the Visual Studio C++ build tools; there is no JIT fallback).
"@
Read-Host "Press Enter to start (Ctrl+C to stop)" | Out-Null

& (Join-Path $PSScriptRoot 'publish.ps1') -AotOnly
if ($LASTEXITCODE -ne 0) {
    Write-Host "Publish failed; nothing was run against the key." -ForegroundColor Red
    exit 1
}

$commit = (git rev-parse --short HEAD 2>$null)
"--- yk-spike fido2-windows-check $(Get-Date -Format o) commit=$commit" | Set-Content -Path $report -Encoding ascii

function Invoke-Spike([string]$title, [string[]]$arguments) {
    Write-Host ""
    Write-Host "=== $title" -ForegroundColor Cyan
    "--- $title" | Add-Content -Path $report -Encoding ascii
    # Out-Host keeps the spike's lines on screen and out of this function's return value.
    & $exe @arguments --report $report | Out-Host
    $code = $LASTEXITCODE
    "exit=$code" | Add-Content -Path $report -Encoding ascii
    return $code
}

function Get-ReportValue([string]$key) {
    $line = Select-String -Path $report -Pattern "^$key=" | Select-Object -Last 1
    if ($line) { return $line.Line.Substring($key.Length + 1) }
    return $null
}

function Stop-Check([string]$what) {
    Write-Host ""
    Write-Host "$what failed (see the error line above and $report)." -ForegroundColor Red
    Write-Host "A cancelled dialog, a wrong PIN or a timeout all end here; the spike never retries. Rerun the script when ready."
    exit 1
}

if ((Invoke-Spike 'env' @('env')) -ne 0) { Stop-Check 'env' }
if ((Get-ReportValue 'aot') -ne 'True') {
    Write-Host "out\yk-spike.exe is not a NativeAOT build (aot=$(Get-ReportValue 'aot')); stopping." -ForegroundColor Red
    exit 1
}

if ((Invoke-Spike 'fido2-enroll (attestation none)' @('fido2-enroll', '--out', $cred)) -ne 0) { Stop-Check 'Creating the credential' }

if ((Get-ReportValue 'aaguid_zero') -eq 'True') {
    Write-Host ""
    Write-Host "webauthn.dll returned an all-zero AAGUID under attestation 'none'." -ForegroundColor Yellow
    Write-Host "The design's fallback is to ask for attestation. Rerun the enrolment with attestation 'direct' now?"
    Write-Host "(one more PIN and touch, and Windows may show an extra consent screen; another non-discoverable credential)"
    $answer = Read-Host "[y/N]"
    if ($answer -match '^[yY]') {
        if ((Invoke-Spike 'fido2-enroll (attestation direct)' @('fido2-enroll', '--attestation', 'direct', '--out', $credDirect)) -ne 0) {
            Stop-Check 'Creating the credential with attestation direct'
        }
    }
}

if ((Invoke-Spike 'fido2-assert cred-windows.json (twice, PIN + touch each)' @('fido2-assert', '--cred', $cred)) -ne 0) { Stop-Check 'The assertion' }
$windowsOutput = Get-ReportValue 'output_h'

$credLinux = Join-Path $PSScriptRoot 'cred-linux.json'
if (Test-Path $credLinux) {
    Write-Host ""
    Write-Host "Found cred-linux.json (a credential made on Linux). Assert it here too? (two more PIN entries and touches)"
    $answer = Read-Host "[y/N]"
    if ($answer -match '^[yY]') {
        if ((Invoke-Spike 'fido2-assert cred-linux.json (twice, PIN + touch each)' @('fido2-assert', '--cred', $credLinux)) -ne 0) {
            Stop-Check 'The assertion of cred-linux.json'
        }
    }
}

Write-Host ""
Write-Host "=== Summary (all of it is in $report)" -ForegroundColor Cyan
Select-String -Path $report -Pattern '^(---|aot|webauthn_api|attestation_requested|attestation_format|hmac_secret_created|prf_enabled|aaguid|aaguid_zero|aaguid_note|credential_id_bytes|uv_flag|output_h|deterministic|error)=?' |
    ForEach-Object { Write-Host "  $($_.Line)" }

Write-Host @"

Next, on the Linux machine (same branch, design/yubikey-sdk):
  1. Copy these two files from this machine:
       $cred
       $report
     Put cred-windows.json into spikes/yubikey-sdk/ there.
  2. In spikes/yubikey-sdk/ run:
       ./publish.sh
       ./out/yk-spike fido2-assert --uv --cred cred-windows.json
  3. Its output_h must equal the Windows output_h: $windowsOutput
"@
