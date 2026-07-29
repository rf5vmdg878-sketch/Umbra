# bootstrap.ps1 — one-shot Windows setup + build for Umbra.
#
# Installs the Rust toolchain if missing, builds the umbra-build tool, then hands
# every remaining argument to it. Examples:
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 app --package
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 app --torify --package
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 relay --torify
#   powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1 all --package --sign "$env:USERPROFILE\.umbra-release-signing.key"

param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Write-Host "== Umbra bootstrap (Windows) =="

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Rust (rustup)..."
    $ri = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $ri
    & $ri -y --default-toolchain stable-x86_64-pc-windows-gnu | Out-Null
    $env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
}

# This project links the vendored MinGW-format SymCrypt import lib, so use the
# GNU toolchain (its bundled rust-mingw provides the linker; no separate MinGW
# install needed for a basic build).
rustup toolchain install stable-x86_64-pc-windows-gnu 2>&1 | Out-Null
rustup default stable-x86_64-pc-windows-gnu 2>&1 | Out-Null

Write-Host "Building umbra-build..."
cargo build --release -p umbra-build --manifest-path "$repo\unichat-common\Cargo.toml"
$tool = "$repo\unichat-common\target\release\umbra-build.exe"

if (-not $Rest) { $Rest = @("app") }
Write-Host "Running: umbra-build $($Rest -join ' ')"
& $tool @Rest
