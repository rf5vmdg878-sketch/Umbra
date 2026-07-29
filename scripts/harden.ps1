# harden.ps1 — lock down an installed Umbra directory on Windows.
#
# This is the OS-level half of Umbra's anti-tamper story. The app already
# verifies an Ed25519-signed integrity manifest at startup and refuses to run if
# a binary/asset was altered (see docs/hardening.md), but a signed manifest is
# only *evidence* — anything the app checks, an attacker with write access could
# patch out. This script removes that write access and enlists Windows itself:
#
#   1. owner-only ACLs (no other user, no inheritance) on the whole install dir
#   2. the read-only attribute on every executable, DLL, and the manifest
#   3. reminds you to Authenticode-sign the binaries so Windows rejects
#      unsigned/modified copies at load time (the only true immutability layer).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File harden.ps1 -InstallDir "C:\Path\To\Umbra"

param([Parameter(Mandatory = $true)][string]$InstallDir)

if (-not (Test-Path $InstallDir)) { Write-Error "not found: $InstallDir"; exit 1 }
$InstallDir = (Resolve-Path $InstallDir).Path
$me = "$env:USERDOMAIN\$env:USERNAME"

Write-Host "Locking $InstallDir to $me (owner-only, read/execute; inheritance off)..."
icacls $InstallDir /reset /T /C | Out-Null
icacls $InstallDir /inheritance:r /grant:r "${me}:(OI)(CI)RX" "SYSTEM:(OI)(CI)RX" /T /C | Out-Null

Write-Host "Setting read-only on executables, DLLs, and the integrity manifest..."
Get-ChildItem $InstallDir -Recurse -File -Include *.exe, *.dll, umbra.manifest |
    ForEach-Object { Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $true }

Write-Host ""
Write-Host "Done. For Windows-enforced trust (recommended), Authenticode-sign the binaries:"
Write-Host '  signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 umbra.exe'
Write-Host ""
Write-Host "After ANY legitimate update, re-run:  umbra-manifest sign <key> <InstallDir>  then this script."
