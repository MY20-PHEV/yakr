#!/usr/bin/env bash
# Create a tarball of spec + vectors + blind-review instructions only (no reference code).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/dist"
BUNDLE="${OUT_DIR}/yakr-blind-review-v1"
ARCHIVE="${OUT_DIR}/yakr-blind-review-v1.tar.gz"

rm -rf "${BUNDLE}"
mkdir -p "${BUNDLE}/docs/spec/test-vectors-v1"

copy() {
  local src="$1"
  local dest="$2"
  mkdir -p "$(dirname "${dest}")"
  cp "${src}" "${dest}"
}

# Normative specs
for spec in \
  yakr-protocol-v1.md \
  pairing-transcript-v1.md \
  double-ratchet.md \
  negative-vector-outcomes-v1.md \
  errata-v1.md; do
  copy "${ROOT}/docs/spec/${spec}" "${BUNDLE}/docs/spec/${spec}"
done

# Vectors (Slice 1 + 2)
for vec in hybrid_kex.json pairing_transcript.json double_ratchet.json; do
  copy "${ROOT}/docs/spec/test-vectors-v1/${vec}" "${BUNDLE}/docs/spec/test-vectors-v1/${vec}"
done
cp -R "${ROOT}/docs/spec/test-vectors-v1/negative" "${BUNDLE}/docs/spec/test-vectors-v1/negative"

# Blind review package
mkdir -p "${BUNDLE}/interop/blind-review"
for doc in README.md MANIFEST.md SLICE-1.md SLICE-2.md FEEDBACK-TEMPLATE.md; do
  copy "${ROOT}/interop/blind-review/${doc}" "${BUNDLE}/interop/blind-review/${doc}"
done

copy "${ROOT}/NOTICE.md" "${BUNDLE}/NOTICE.md"

cat > "${BUNDLE}/README.txt" <<'EOF'
Yakr v1.0 blind implementation review bundle.

Start at: interop/blind-review/README.md

Do not expect reference implementation source in this archive.
EOF

mkdir -p "${OUT_DIR}"
tar -czf "${ARCHIVE}" -C "${OUT_DIR}" "$(basename "${BUNDLE}")"
echo "Created ${ARCHIVE}"
echo "Contents:"
tar -tzf "${ARCHIVE}" | head -30
echo "... ($(tar -tzf "${ARCHIVE}" | wc -l | tr -d ' ') files)"
