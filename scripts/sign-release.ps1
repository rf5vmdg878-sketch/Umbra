# sign-release.ps1 — (re)generate the signed integrity manifest for a build.
#
# Run this after EVERY release build: the app verifies its binaries against the
# manifest and refuses to run if they don't match, so a rebuilt-but-unsigned
# install will not launch. Deleting umbra.manifest instead lets a build run
# "unverified" (no tamper protection) — useful during development.
#
# Usage:
#   powershell -File scripts\sign-release.ps1 -Key "$env:USERPROFILE\.umbra-release-signing.key"

param(
    [Parameter(Mandatory = $true)][string]$Key,
    [string]$Dir = "$PSScriptRoot\..\unichat-notor\target\release"
)

$tool = "$PSScriptRoot\..\unichat-common\target\release\umbra-manifest.exe"
if (-not (Test-Path $tool)) { $tool = "$PSScriptRoot\..\unichat-common\target\debug\umbra-manifest.exe" }
if (-not (Test-Path $tool)) { Write-Error "build umbra-manifest first (cargo build -p umbra-manifest)"; exit 1 }
if (-not (Test-Path $Key)) { Write-Error "signing key not found: $Key"; exit 1 }

# Sign the binaries that actually ship together in $Dir.
$files = Get-ChildItem $Dir -File | Where-Object { $_.Extension -in ".exe", ".dll" } | ForEach-Object { $_.Name }
& $tool sign $Key $Dir @files
Write-Host "Manifest written to $Dir\umbra.manifest — re-run harden.ps1 to re-lock."
