#!/usr/bin/env bash
# Runs the full unit test suite for manual verification.
# Usage: ./test.sh
set -euo pipefail
cd "$(dirname "$0")"

echo "==> go vet"
go vet ./...

echo "==> rules package tests (layered rule evaluation)"
go test -v ./rules/...

echo "==> http package tests (Check priority, checkerPrefix boundary, debug logs)"
go test -v -run 'TestCheck' ./http/...

echo "==> http package full tests"
go test ./http/...

echo "==> all remaining packages"
go test ./...

echo "==> all tests passed"
