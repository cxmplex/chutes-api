#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${CHUTES_API_RUNTIME_SMOKE_IMAGE:-chutes-api-runtime-cosign-smoke}"

docker build --target api --tag "$IMAGE" "$ROOT"
docker run --rm \
  --entrypoint bash \
  --env COSIGN_PASSWORD=runtime-smoke-password \
  "$IMAGE" -ceu '
    work="$(mktemp -d)"
    trap '\''rm -rf "$work"'\'' EXIT
    printf "api runtime provenance smoke\n" > "$work/payload"
    cosign generate-key-pair --output-key-prefix "$work/key" >/dev/null
    cosign sign-blob --yes --tlog-upload=false \
      --key "$work/key.key" \
      --output-signature "$work/payload.sig" \
      "$work/payload" >/dev/null
    cosign verify-blob --insecure-ignore-tlog \
      --key "$work/key.pub" \
      --signature "$work/payload.sig" \
      "$work/payload" >/dev/null
  '
