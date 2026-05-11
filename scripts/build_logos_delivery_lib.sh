#!/usr/bin/env bash
# Prerequisites:
#   - Nim / nimble / choosenim installed (e.g. via https://nim-lang.org/choosenim)
#   - make, gcc / g++ (or clang on macOS)
#   - python3 available on PATH
#   - git submodules initialised:
#       git submodule update --init --recursive

set -euo pipefail

# ── Resolve repository root ───────────────────────────────────────────────────
# The script lives in <repo>/scripts/, so go one level up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Resolve Python interpreter ────────────────────────────────────────────────
# Prefer the project's own virtual environment (cffi + all requirements).
# Checks both the hidden (.venv) and non-hidden (venv) conventional names.
# Falls back to whatever python3 is on PATH (e.g. in CI after pip install).
if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
    echo "Using venv Python: $PYTHON"
elif [ -x "$REPO_ROOT/venv/bin/python" ]; then
    PYTHON="$REPO_ROOT/venv/bin/python"
    echo "Using venv Python: $PYTHON"
else
    PYTHON="$(command -v python3 || command -v python)"
    echo "No local venv found, falling back to: $PYTHON"
fi

# ── 1. Build liblogosdelivery shared library for Python bindings ──────────────
echo "──────────────────────────────────────────────────────────────────────────"
echo "Step 1 – Build liblogosdelivery shared library for Python bindings"
echo "──────────────────────────────────────────────────────────────────────────"

# Make sure nimble / choosenim binaries are on PATH (same as CI)
export PATH="$HOME/.nimble/bin:$PATH"

BINDINGS_DIR="$REPO_ROOT/vendor/logos-delivery-python-bindings"
DELIVERY_DIR="$BINDINGS_DIR/vendor/logos-delivery"

export "PYTHONPATH=$BINDINGS_DIR/waku${PYTHONPATH:+:$PYTHONPATH}"

echo "--> Creating lib output directory: $BINDINGS_DIR/lib"
mkdir -p "$BINDINGS_DIR/lib"

echo "--> Entering: $DELIVERY_DIR"
cd "$DELIVERY_DIR"

echo "--> Creating waku.nims symlink (waku.nimble -> waku.nims)"
ln -sf waku.nimble waku.nims

echo "--> Installing Nim dependencies (nimble install -y)"
nimble install -y

echo "--> Running: make setup"
make setup

echo "--> Running: make liblogosdelivery"
make liblogosdelivery

# On Linux the library is .so; on macOS it may be .dylib
SO_PATH="$(find . -type f \( -name 'liblogosdelivery.so' -o -name 'liblogosdelivery.dylib' \) | head -n 1)"

if [ -z "$SO_PATH" ]; then
    echo "ERROR: liblogosdelivery shared library was not built (neither .so nor .dylib found)"
    exit 1
fi

# Preserve the platform-native extension in the destination
case "$SO_PATH" in
    *.dylib) DEST_LIB="$BINDINGS_DIR/lib/liblogosdelivery.dylib" ;;
    *)       DEST_LIB="$BINDINGS_DIR/lib/liblogosdelivery.so"    ;;
esac

cp "$SO_PATH" "$DEST_LIB"
echo "Built library:"
ls -l "$DEST_LIB"

# ── 2. Verify wrapper library ─────────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────────────────────────"
echo "Step 2 – Verify wrapper library"
echo "──────────────────────────────────────────────────────────────────────────"

if test -f "$BINDINGS_DIR/lib/liblogosdelivery.so" \
    || test -f "$BINDINGS_DIR/lib/liblogosdelivery.dylib"; then
    echo "OK: wrapper library is present in $BINDINGS_DIR/lib/"
else
    echo "ERROR: wrapper library not found in $BINDINGS_DIR/lib/"
    exit 1
fi

# ── 3. Debug Python import paths ──────────────────────────────────────────────
echo ""
echo "──────────────────────────────────────────────────────────────────────────"
echo "Step 3 – Debug Python import paths"
echo "──────────────────────────────────────────────────────────────────────────"

cd "$REPO_ROOT"

# Prepend the waku bindings directory to PYTHONPATH (mirrors the CI env step)
export PYTHONPATH="$REPO_ROOT/vendor/logos-delivery-python-bindings/waku${PYTHONPATH:+:$PYTHONPATH}"

pwd
echo "PYTHONPATH=$PYTHONPATH"
find . -maxdepth 5 | grep wrapper || true

"$PYTHON" - <<'PY'
import sys
print("sys.path:")
for p in sys.path:
    print(p)
try:
    import wrapper
    print("wrapper import OK:", wrapper)
except Exception as e:
    print("wrapper import failed:", e)
    raise
PY
