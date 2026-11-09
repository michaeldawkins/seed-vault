#!/bin/sh
# Build the Secure Enclave helper on a Mac with Apple Silicon or a T2 chip.
# Needs the Xcode command-line tools (xcode-select --install).
set -e
cd "$(dirname "$0")"
swiftc -O seed-enclave.swift -o seed-enclave
echo "Built $(pwd)/seed-enclave"
