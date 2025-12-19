#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$ROOT_DIR/pip_package"
DIST_DIR="$PKG_DIR/dist"
CYTHON_SRC="$PKG_DIR/Pixseal/simpleImage_ext.pyx"
rm -rf "$DIST_DIR"

if command -v cython >/dev/null 2>&1; then
  echo "[build] regenerating C source from $CYTHON_SRC"
  (cd "$PKG_DIR" && cython "$CYTHON_SRC")
fi

export PIP_NO_INPUT=1
echo "[build] running python -m build"
(cd "$PKG_DIR" && python -m build)

echo "[build] artifacts stored in $DIST_DIR"

# Cleanup generated sources that should not be committed
rm -f "$PKG_DIR/Pixseal/simpleImage_ext.c"
rm -rf "$PKG_DIR/Pixseal.egg-info"
