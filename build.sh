#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$ROOT_DIR/pip_package"
DIST_DIR="$PKG_DIR/dist"
CYTHON_SRC="$PKG_DIR/Pixseal/simpleImage_ext.pyx"
CYTHON_C="$PKG_DIR/Pixseal/simpleImage_ext.c"
CYTHON_SO="$PKG_DIR/Pixseal/simpleImage_ext.cpython-$(python3 -c 'import sys;print(sys.version_info.major,sys.version_info.minor,sep="")')-$(uname -m)-linux-gnu.so"

rm -rf "$DIST_DIR"

if command -v cython >/dev/null 2>&1; then
  echo "[build] regenerating C source from $CYTHON_SRC"
  (cd "$PKG_DIR" && cython "$CYTHON_SRC")
fi

if [ -f "$CYTHON_C" ]; then
  echo "[build] compiling extension via gcc"
  PY_CFLAGS=$(python3-config --cflags)
  PY_LDFLAGS=$(python3-config --ldflags)
  (cd "$PKG_DIR/Pixseal" && gcc -shared -fPIC simpleImage_ext.c $PY_CFLAGS $PY_LDFLAGS -o "$CYTHON_SO")
else
  echo "[build] warning: $CYTHON_C not found; skipping manual gcc step"
fi

export PIP_NO_INPUT=1
(cd "$PKG_DIR" && python -m build)
