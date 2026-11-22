#!/usr/bin/env bash
# Static cross-build of veepn for Linux and Windows (amd64 + arm64).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
for t in "linux amd64" "linux arm64" "windows amd64" "windows arm64"; do
    set -- $t
    echo "==> $1/$2"
    CGO_ENABLED=0 GOOS="$1" GOARCH="$2" go build -trimpath -buildvcs=false \
        -ldflags "-s -w" -o "dist/veepn-$1-$2$([ "$1" = "windows" ] && echo .exe)" .
done
ls -la dist/
