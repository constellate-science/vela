#!/usr/bin/env bash
set -euo pipefail

REPO="constellate-science/vela"
BINARY="vela"
PREFIX="${VELA_INSTALL_PREFIX:-/usr/local}"
BINDIR="${VELA_INSTALL_BINDIR:-$PREFIX/bin}"

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}-${ARCH}" in
  darwin-arm64|darwin-aarch64) NAME="vela-macos-aarch64" ;;
  darwin-x86_64) NAME="vela-macos-x86_64" ;;
  linux-x86_64)  NAME="vela-linux-x86_64" ;;
  *) echo "Unsupported: ${OS}-${ARCH}"; exit 1 ;;
esac

# Resolve the release tag. VELA_VERSION pins an exact tag (e.g. v0.710.0) — used
# by CI (the vela-check action) so a frontier gate is reproducible; empty falls
# back to the latest release.
TAG="${VELA_VERSION:-}"
if [ -z "$TAG" ]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
fi
URL="https://github.com/${REPO}/releases/download/${TAG}/${NAME}"
SUM_URL="${URL}.sha256"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Installing vela ${TAG} for ${OS}/${ARCH}..."
curl -fsSL "$URL" -o "$TMP/$BINARY"

if curl -fsSL "$SUM_URL" -o "$TMP/$BINARY.sha256"; then
  (
    cd "$TMP"
    shasum -a 256 -c "$BINARY.sha256"
  )
else
  echo "Checksum file not found for ${NAME}; continuing without checksum verification."
fi

chmod +x "$TMP/$BINARY"
mkdir -p "$BINDIR" 2>/dev/null || true
if [[ -w "$BINDIR" ]]; then
  install "$TMP/$BINARY" "$BINDIR/$BINARY"
else
  sudo install "$TMP/$BINARY" "$BINDIR/$BINARY"
fi

echo "Installed vela to $BINDIR/$BINARY"
"$BINDIR/$BINARY" --version

if ! command -v "$BINDIR/$BINARY" >/dev/null 2>&1 && [[ ":$PATH:" != *":$BINDIR:"* ]]; then
  echo
  echo "Note: $BINDIR is not on PATH. Add it before running vela directly."
fi

echo
echo "Quick start (frontier workflow):"
echo "  1) new:     vela frontier new frontier.json --name \"Your bounded question\""
echo "  2) add:     vela finding add frontier.json --assertion \"A scoped finding\" --type therapeutic --evidence-type experimental --source \"Author et al., 2026\" --source-type published_paper --author reviewer:you --confidence 0.5 --apply"
echo "  3) check:   vela check frontier.json"
echo "  4) proof:   vela proof frontier.json --out proof-packet"
echo "  5) serve:   vela serve frontier.json"
echo
echo "To inspect a maintained frontier, clone the repo and run:"
echo "  git clone https://github.com/constellate-science/vela.git"
echo "  cd vela"
echo "  vela check examples/sidon-sets"
echo "  vela reproduce examples/sidon-sets"
