#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
PORTABLE_PY_DIR="$PROJECT_DIR/.python"

# Ensure PATH includes Homebrew (Apple Silicon & Intel) and Python.org Frameworks when launched from Finder
export PATH="/Library/Frameworks/Python.framework/Versions/Current/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

# ─────────────────────────────────────────────────────────────────────────────
# Helper: On macOS, Apple's built-in /usr/bin/python3 links to Tcl/Tk 8.5.9
# which renders a completely BLACK window on modern macOS (Sonoma/Sequoia).
# Therefore, we strictly require Tcl/Tk >= 8.6 on macOS.
# ─────────────────────────────────────────────────────────────────────────────
has_modern_tk() {
    local py="$1"
    [ -n "$py" ] || return 1
    command -v "$py" >/dev/null 2>&1 || [ -x "$py" ] || return 1
    if [ "$py" = "/usr/bin/python3" ]; then
        return 1
    fi
    "$py" -c "import sys, tkinter; raise SystemExit(0 if sys.version_info >= (3, 9) and float(tkinter.TkVersion) >= 8.6 else 1)" >/dev/null 2>&1
}

# ─────────────────────────────────────────────────────────────────────────────
# Fast Path: If .venv already exists and has working Tcl/Tk >= 8.6 + customtkinter
# ─────────────────────────────────────────────────────────────────────────────
if [ -x "$VENV_DIR/bin/python3" ]; then
    if "$VENV_DIR/bin/python3" -c "import tkinter, customtkinter; raise SystemExit(0 if float(tkinter.TkVersion) >= 8.6 else 1)" >/dev/null 2>&1; then
        exec "$VENV_DIR/bin/python3" "$PROJECT_DIR/main.py" "$@"
    fi
fi

find_best_python() {
    local candidates=()
    local p

    # 1. Portable standalone Python inside project (.python/python/bin/python3)
    if [ -x "$PORTABLE_PY_DIR/python/bin/python3" ]; then
        candidates+=("$PORTABLE_PY_DIR/python/bin/python3")
    fi

    # 2. Python.org Framework builds (bundle modern Tcl/Tk 8.6+)
    for p in /Library/Frameworks/Python.framework/Versions/*/bin/python3; do
        [ -x "$p" ] && candidates+=("$p")
    done

    # 3. Homebrew & local builds (if python-tk is installed)
    for p in /opt/homebrew/bin/python3* /usr/local/bin/python3*; do
        case "$p" in
            *-config) continue ;;
        esac
        [ -x "$p" ] && candidates+=("$p")
    done

    # 4. Default python3 in PATH
    if command -v python3 >/dev/null 2>&1; then
        candidates+=("$(command -v python3)")
    fi

    for p in "${candidates[@]}"; do
        if has_modern_tk "$p"; then
            echo "$p"
            return 0
        fi
    done

    return 1
}

install_portable_python_macos() {
    echo "=================================================================="
    echo "[안내] macOS GUI(Tk 8.6+)가 포함된 독립형 Python 3.12 환경을 준비합니다."
    echo "       (macOS 기본 Tk 8.5의 검은 화면 버그 방지 및 무설치 원클릭 구동용)"
    echo "=================================================================="

    local arch
    arch="$(uname -m)"
    local url
    if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then
        url="https://github.com/astral-sh/python-build-standalone/releases/download/20241219/cpython-3.12.8%2B20241219-aarch64-apple-darwin-install_only_stripped.tar.gz"
    else
        url="https://github.com/astral-sh/python-build-standalone/releases/download/20241219/cpython-3.12.8%2B20241219-x86_64-apple-darwin-install_only_stripped.tar.gz"
    fi

    rm -rf "$PORTABLE_PY_DIR"
    mkdir -p "$PORTABLE_PY_DIR"
    local archive="$PORTABLE_PY_DIR/python-standalone.tar.gz"

    echo "1/2. 독립형 Python 3.12 + Tcl/Tk 8.6 다운로드 중..."
    curl -fL --progress-bar "$url" -o "$archive"

    echo "2/2. 압축 해제 중..."
    tar -xzf "$archive" -C "$PORTABLE_PY_DIR"
    rm -f "$archive"
}

ensure_pip_for() {
    local py="$1"
    if "$py" -m pip --version >/dev/null 2>&1; then
        return 0
    fi
    echo "pip 모듈이 없어 자동으로 활성화하고 있습니다 (ensurepip)..."
    if "$py" -m ensurepip --upgrade >/dev/null 2>&1 || "$py" -m ensurepip --user >/dev/null 2>&1; then
        return 0
    fi
    echo "get-pip.py를 통해 pip를 설치하고 있습니다..."
    local get_pip="/tmp/get-pip.py"
    curl -fsSL "https://bootstrap.pypa.io/get-pip.py" -o "$get_pip"
    "$py" "$get_pip" --user || "$py" "$get_pip" --break-system-packages || "$py" "$get_pip"
    rm -f "$get_pip"
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. Locate or Download Python 3 with Modern Tcl/Tk 8.6+
# ─────────────────────────────────────────────────────────────────────────────
PYTHON_BIN="$(find_best_python || true)"

if [ -z "$PYTHON_BIN" ]; then
    install_portable_python_macos
    PYTHON_BIN="$(find_best_python || true)"
fi

if [ -z "$PYTHON_BIN" ]; then
    echo "[오류] Python3 및 Tcl/Tk 8.6+ 환경을 준비하지 못했습니다."
    exit 1
fi

echo "사용할 Python 환경: $PYTHON_BIN ($("$PYTHON_BIN" --version 2>&1), Tk $("$PYTHON_BIN" -c 'import tkinter; print(tkinter.TkVersion)'))"

# ─────────────────────────────────────────────────────────────────────────────
# 2. Setup Isolated Virtual Environment (.venv)
# ─────────────────────────────────────────────────────────────────────────────
if [ -d "$VENV_DIR" ] && ! has_modern_tk "$VENV_DIR/bin/python3"; then
    echo "기존 가상환경(.venv)을 최신 Tcl/Tk 8.6+ 환경으로 재구성합니다..."
    rm -rf "$VENV_DIR"
fi

USE_PY="$PYTHON_BIN"
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "독립 실행용 가상환경(.venv)을 생성하고 있습니다..."
    if "$PYTHON_BIN" -m venv "$VENV_DIR" >/dev/null 2>&1; then
        USE_PY="$VENV_DIR/bin/python3"
    else
        USE_PY="$PYTHON_BIN"
    fi
else
    USE_PY="$VENV_DIR/bin/python3"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. Ensure pip & Install UI Requirements (customtkinter)
# ─────────────────────────────────────────────────────────────────────────────
if ! "$USE_PY" -c "import customtkinter" >/dev/null 2>&1; then
    ensure_pip_for "$USE_PY"
    echo "필요한 UI 패키지(customtkinter)를 설치하고 있습니다..."
    if [ "$USE_PY" = "$VENV_DIR/bin/python3" ]; then
        "$USE_PY" -m pip install --disable-pip-version-check -r "$PROJECT_DIR/requirements.txt"
    else
        "$USE_PY" -m pip install --disable-pip-version-check --user --break-system-packages -r "$PROJECT_DIR/requirements.txt" 2>/dev/null \
            || "$USE_PY" -m pip install --disable-pip-version-check --user -r "$PROJECT_DIR/requirements.txt" \
            || "$USE_PY" -m pip install --disable-pip-version-check --break-system-packages -r "$PROJECT_DIR/requirements.txt"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. Launch Installer GUI
# ─────────────────────────────────────────────────────────────────────────────
exec "$USE_PY" "$PROJECT_DIR/main.py" "$@"
