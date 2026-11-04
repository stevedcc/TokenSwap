# Publishes yk-spike into .\out: NativeAOT first (needs the Visual Studio C++ build tools), and a JIT build if that
# fails, so the hash comparison still runs. `yk-spike env` says which one ran (aot=True/False).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
$log = New-TemporaryFile
dotnet publish -c Release -o out -nologo 2>&1 | Tee-Object -FilePath $log
if ($LASTEXITCODE -ne 0) {
    Write-Host "NativeAOT publish failed (C++ build tools missing?); publishing a JIT build instead."
    dotnet publish -c Release -o out -nologo -p:PublishAot=false 2>&1 | Tee-Object -FilePath $log
    if ($LASTEXITCODE -ne 0) { Remove-Item $log; exit 1 }
}
$warnings = Select-String -Path $log -Pattern 'warning IL(2|3)[0-9]{3}' | ForEach-Object { $_.Line }
Remove-Item $log
if ($warnings) {
    $warnings | Set-Content out\aot-warnings.txt
    Write-Host "AOT/trim warnings (also in out\aot-warnings.txt):"; $warnings
    exit 1
}
Set-Content out\aot-warnings.txt -Value $null
Write-Host "published: $PSScriptRoot\out\yk-spike.exe"
