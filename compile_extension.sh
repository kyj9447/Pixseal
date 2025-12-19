#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="$ROOT_DIR/pip_package"
SRC_PYX="$PKG_DIR/Pixseal/simpleImage_ext.pyx"
SRC_C="$PKG_DIR/Pixseal/simpleImage_ext.c"
PYTHON_BIN="${PYTHON:-python3}"

log() { echo "[build] $*"; }
fail() { echo "[build] error: $*" >&2; exit 1; }

ensure_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "required command '$1' not found"
  fi
}

ensure_module() {
  if ! "$PYTHON_BIN" -c "import $1" >/dev/null 2>&1; then
    fail "python module '$1' is not installed. Run 'python -m pip install -r requirements.txt'."
  fi
}

get_ext_suffix() {
  "$PYTHON_BIN" - <<'PY'
import importlib.machinery as m
print(m.EXTENSION_SUFFIXES[0])
PY
}

get_flag() {
  local var="$1"
  "$PYTHON_BIN" - <<PY
import sysconfig
value = sysconfig.get_config_var("$var") or ""
print(value)
PY
}

prepare_sources() {
  ensure_module cython
  log "regenerating C source from $SRC_PYX"
  (cd "$PKG_DIR" && cython Pixseal/simpleImage_ext.pyx)
}

compile_extension() {
  local compiler="${CC:-}"
  if [[ -z "$compiler" ]]; then
    if command -v clang >/dev/null 2>&1; then
      compiler="clang"
    elif command -v gcc >/dev/null 2>&1; then
      compiler="gcc"
    else
      fail "no suitable C compiler found (install clang or gcc)"
    fi
  fi
  ensure_command "$compiler"
  local suffix
  suffix="$(get_ext_suffix)"
  local output="$PKG_DIR/Pixseal/simpleImage_ext${suffix}"

  local cflags ldflags
  if command -v python3-config >/dev/null 2>&1; then
    cflags="$(python3-config --cflags)"
    ldflags="$(python3-config --ldflags)"
  else
    cflags="$(get_flag CFLAGS)"
    ldflags="$(get_flag LDFLAGS)"
  fi

  log "compiling ${output##*/} for $(uname -s)-$(uname -m)"
  if [[ "$compiler" == "clang" || "$compiler" == *clang ]]; then
    "$compiler" -shared -fPIC "$SRC_C" $cflags $ldflags -o "$output"
  else
    "$compiler" -shared -fPIC "$SRC_C" $cflags $ldflags -o "$output"
  fi

  log "built $output"
}

cleanup() {
  rm -f "$SRC_C"
  rm -rf "$PKG_DIR/Pixseal.egg-info"
}

prepare_sources
compile_extension
cleanup
log "simpleImage_ext ready."
