#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Checks that the workspace still compiles, with no warnings, for a non-Linux target.
#
# v0 runs only on Linux, but the crates are meant to build elsewhere so the later macOS and Windows services start
# from code that compiles. Linux-only modules are gated with `cfg(target_os = "linux")`; this catches an ungated use.
#
# Only the libraries and binaries are checked, not the tests: the test suites use Unix-only APIs and the dev-dependency
# rustix with `pty`, which does not build for Windows. Each profile feature is checked too, since each gates code of
# its own. `ring`'s build script compiles C for the target, so a MinGW cross-compiler (x86_64-w64-mingw32-gcc, Debian
# package gcc-mingw-w64-x86-64) must be installed.
set -euo pipefail

target=x86_64-pc-windows-gnu

if ! rustup target list --installed | grep -qx "$target"; then
    echo "error: the $target target is not installed; run: rustup target add $target" >&2
    exit 2
fi

export RUSTFLAGS="${RUSTFLAGS:-} -D warnings"

cargo check --locked --target "$target" --workspace --lib --bins
cargo check --locked --target "$target" -p iron-vault --lib --bins --features dev-mode
cargo check --locked --target "$target" -p iron-vault --lib --bins --features container
