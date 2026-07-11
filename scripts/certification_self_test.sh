#!/usr/bin/env bash
# Yakr v1.0 certification self-test bundle.
# Paste full output into a certification application issue.
#
# Usage: ./scripts/certification_self_test.sh [--rust]

set -euo pipefail
cd "$(dirname "$0")/.."

RUN_RUST=0
if [[ "${1:-}" == "--rust" ]]; then
  RUN_RUST=1
fi

echo "=== Yakr Protocol v1.0 certification self-test ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Repo: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo ""

echo "--- Python: sync ---"
uv sync --all-packages

echo ""
echo "--- Python: interop vectors (standalone verifier) ---"
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q

echo ""
echo "--- Python: relay abuse ---"
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q

echo ""
echo "--- Python: cross-language interop (Phase 11) ---"
if [[ -x rust/target/release/yakr-cli ]] || command -v cargo >/dev/null 2>&1; then
  export YAKR_RUST_BIN="${YAKR_RUST_BIN:-$(pwd)/rust/target/release/yakr}"
  if [[ ! -x "$YAKR_RUST_BIN" ]]; then
    echo "Building rust/yakr-cli (release)…"
    (cd rust && cargo build --release -p yakr-cli)
    export YAKR_RUST_BIN="$(pwd)/rust/target/release/yakr"
  fi
  uv run pytest packages/yakr-testkit/tests/test_phase11_cross_lang.py -q
else
  echo "SKIP: cargo not available (set YAKR_RUST_BIN or install Rust for cross-lang test)"
fi

if [[ "$RUN_RUST" == 1 ]]; then
  echo ""
  echo "--- Rust: yakr-crypto vectors ---"
  (cd rust && cargo test -p yakr-crypto -q)

  echo ""
  echo "--- Rust: workspace ---"
  (cd rust && cargo test -q)
fi

echo ""
echo "=== Self-test complete ==="
echo "Next: complete certification/client-checklist.md or relay-checklist.md"
echo "      open a GitHub issue: Yakr Certification Application"
