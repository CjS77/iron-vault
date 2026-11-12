#!/usr/bin/env bash
# Measures test coverage of the workspace with cargo-llvm-cov, the same way locally and in CI.
#
# Usage: scripts/coverage.sh [html|lcov]
#   html (default): writes <target>/llvm-cov/html/index.html, for reading locally.
#   lcov: writes <target>/llvm-cov/lcov.info, for .github/workflows/coverage.yml to upload to Coveralls.
# <target> is cargo's target directory (target/ unless cargo's configuration names another). Both print a per-file
# summary. The format changes only the report; the tests that run are the same.
#
# Tools (not workspace dependencies):
#   cargo install cargo-llvm-cov --locked
#   sudo apt install libtss2-dev pkg-config   # the TPM signing helper links tpm2-tss
# llvm-tools-preview comes with the pinned toolchain (rust-toolchain.toml).
#
# The runs mirror the test steps of .github/workflows/ci.yml, merged into one report: the workspace with default
# features, each deployment profile (dev-mode and container gate code of their own and cannot be built together), and
# the TPM signing helper with its `tpm` feature. Tests marked #[ignore] (those needing swtpm) are not run, so code
# reached only through a TPM is reported as uncovered.
set -euo pipefail

format=${1:-html}
case $format in
    html | lcov) ;;
    *)
        echo "usage: scripts/coverage.sh [html|lcov]" >&2
        exit 2
        ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo llvm-cov clean --workspace
cargo llvm-cov --no-report --locked --workspace
cargo llvm-cov --no-report --locked -p iron-vault --features dev-mode
cargo llvm-cov --no-report --locked -p iron-vault --features container
cargo llvm-cov --no-report --locked -p iron-vault-tpm-signer --features tpm

cargo llvm-cov report
case $format in
    html) cargo llvm-cov report --html ;;
    lcov)
        target=$(cargo metadata --no-deps --locked --format-version 1 \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
        lcov=$target/llvm-cov/lcov.info
        mkdir -p "$(dirname "$lcov")"
        cargo llvm-cov report --lcov --output-path "$lcov"
        echo "report: $lcov"
        ;;
esac
