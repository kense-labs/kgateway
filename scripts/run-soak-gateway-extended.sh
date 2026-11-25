#!/usr/bin/env bash
# Lab-extended soak (default 120s). Not a dedicated-hardware published envelope.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${1:-./target/debug/kgateway}"
if [[ ! -x "$BIN" && ! -f "$BIN" ]]; then
  echo "building kgateway..."
  cargo build --bin kgateway
  BIN=./target/debug/kgateway
fi

DUR="${KGATEWAY_SOAK_DURATION:-120}"
C="${KGATEWAY_SOAK_CONCURRENCY:-8}"

for profile in http-json sse-finite openai-json openai-sse; do
  python3 scripts/soak-gateway.py \
    --bin "$BIN" \
    --profile "$profile" \
    --duration "$DUR" \
    --concurrency "$C" \
    --envelope-status lab-extended
done
echo "soak-gateway lab-extended: OK"
