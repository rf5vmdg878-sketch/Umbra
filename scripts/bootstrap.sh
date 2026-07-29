#!/bin/sh
# bootstrap.sh — one-shot Linux setup + build for Umbra.
#
# Installs system build deps (ALSA + V4L2 for real mic/camera, a C toolchain,
# pkg-config, clang, curl) and the Rust toolchain if missing, builds the
# umbra-build tool, then hands every remaining argument to it. Examples:
#   ./scripts/bootstrap.sh app --package
#   ./scripts/bootstrap.sh app --torify --package
#   ./scripts/bootstrap.sh relay --torify
#   ./scripts/bootstrap.sh all --package --sign "$HOME/.umbra-release-signing.key"
set -e

repo="$(cd "$(dirname "$0")/.." && pwd)"
echo "== Umbra bootstrap (Linux) =="

SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO="sudo"

if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    $SUDO apt-get install -y curl build-essential pkg-config libasound2-dev libv4l-dev clang tar
elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y curl gcc gcc-c++ make pkgconf-pkg-config alsa-lib-devel libv4l-devel clang tar
elif command -v pacman >/dev/null 2>&1; then
    $SUDO pacman -Sy --noconfirm curl base-devel pkgconf alsa-lib v4l-utils clang tar
else
    echo "!! Unknown package manager. Install manually: curl, a C toolchain," >&2
    echo "   pkg-config, ALSA dev headers, V4L2 dev headers, clang, tar." >&2
fi

if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust (rustup)..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

echo "Building umbra-build..."
cargo build --release -p umbra-build --manifest-path "$repo/unichat-common/Cargo.toml"

[ "$#" -eq 0 ] && set -- app
echo "Running: umbra-build $*"
exec "$repo/unichat-common/target/release/umbra-build" "$@"
