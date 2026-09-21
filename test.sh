#!/bin/sh
# Runs all unit tests covering the rule evaluation refactor:
#   - rules package: layered rule evaluation (explicit priority)
#   - http package:  data.Check layering, checkerPrefix boundary handling,
#     debug rule-hit logging, and public share end-to-end behavior
set -eu

cd "$(dirname "$0")"

echo "==> go build ./..."
go build ./...

echo "==> go vet ./rules/... ./http/..."
go vet ./rules/... ./http/...

echo "==> go test ./rules/..."
go test -v -count=1 ./rules/...

echo "==> go test ./http/..."
go test -v -count=1 ./http/...

echo "==> go test ./... (full suite)"
go test -count=1 ./...

echo "All tests passed."
