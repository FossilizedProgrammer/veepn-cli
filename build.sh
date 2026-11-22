#!/usr/bin/env bash
# Static cross-build of veepn for Linux and Windows (amd64 + arm64).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist
for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
    os=${target%/*}
    arch=${target#*/}
    out="dist/veepn-$os-$arch"
    if [ "$os" = "windows" ]; then
        out="$out.exe"
    fi
    echo "==> $os/$arch"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
        -ldflags "-s -w" -o "$out" .
done
ls -la dist/
