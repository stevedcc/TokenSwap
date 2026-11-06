# Publishes yk-spike into .\out: NativeAOT first (needs the Visual Studio C++ build tools), and a JIT build if that
# fails, so the hash comparison still runs. `yk-spike env` says which one ran (aot=True/False).
# -AotOnly (used by fido2-windows-check.ps1): no JIT fallback; a failed NativeAOT publish fails the script.
# Either way any trim/AOT warning (IL2xxx/IL3xxx) fails it.
param([switch]$AotOnly)
# Not 'Stop': Windows PowerShell 5.1 turns a native command's stderr line into a terminating error under 'Stop' when
# it is redirected with 2>&1. Exit codes are checked explicitly instead.
$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot
$log = New-TemporaryFile
dotnet publish -c Release -o out -nologo 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log
if ($LASTEXITCODE -ne 0) {
    if ($AotOnly) {
        Write-Host ""
        Write-Host "NativeAOT publish failed; this check needs a NativeAOT build and has no JIT fallback." -ForegroundColor Red
        if (Select-String -Path $log -Pattern 'Platform linker not found|vcvarsall|link\.exe|nativeaot-prerequisites' -Quiet) {
            Write-Host "The C++ linker was not found. Install the Visual Studio Build Tools with the 'Desktop development with C++'"
            Write-Host "workload (see https://aka.ms/nativeaot-prerequisites), open a new terminal and rerun."
        }
        Remove-Item $log
        exit 1
    }
    Write-Host "NativeAOT publish failed (C++ build tools missing?); publishing a JIT build instead."
    dotnet publish -c Release -o out -nologo -p:PublishAot=false 2>&1 | ForEach-Object { "$_" } | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { Remove-Item $log; exit 1 }
}
$warnings = Select-String -Path $log -Pattern 'warning IL(2|3)[0-9]{3}' | ForEach-Object { $_.Line }
Remove-Item $log
if ($warnings) {
    $warnings | Set-Content out\aot-warnings.txt
    Write-Host "AOT/trim warnings (also in out\aot-warnings.txt):" -ForegroundColor Red
    $warnings
    exit 1
}
Set-Content out\aot-warnings.txt -Value $null
Write-Host "published: $PSScriptRoot\out\yk-spike.exe"
exit 0
