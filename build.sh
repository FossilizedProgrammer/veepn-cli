#!/usr/bin/env bash
# Static cross-build of veepn for Linux (amd64 + arm64).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
for arch in amd64 arm64; do
    echo "==> linux/$arch"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
        -ldflags "-s -w" -o "dist/veepn-linux-$arch" .
done
ls -la dist/
