#!/bin/bash
# L0p4Map launcher: checks dependencies, keeps the checkout up to date and
# starts the GUI with the least privilege that still allows raw sockets.
#
#   ./L0p4Map.sh          install deps, update, launch with sudo (full capture)
#   ./L0p4Map.sh --no-sudo launch unprivileged (ARP + capture disabled)
#   ./L0p4Map.sh --check  verify the environment only, do not launch
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$REPO_DIR/$(basename "$0")"
BRANCH="main"
VENV="$REPO_DIR/.venv"
PY="$VENV/bin/python"

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
fail() { printf 'error: %s\n' "$*" >&2; exit 1; }

install_nmap() {
    if command -v nmap >/dev/null 2>&1; then
        return 0
    fi
    say "nmap not found, installing it..."
    if command -v brew >/dev/null 2>&1; then
        brew install nmap
    elif command -v apt >/dev/null 2>&1; then
        sudo apt update -qq && sudo apt install -y -qq nmap
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y -q nmap
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -Sy --noconfirm --noprogressbar nmap
    else
        fail "no supported package manager (brew/apt/dnf/pacman), install nmap manually"
    fi
}

setup_python() {
    if [ ! -x "$PY" ]; then
        say "Creating virtualenv in .venv ..."
        python3 -m venv "$VENV" || fail "python3 -m venv failed (Python 3.11+ required)"
    fi
    # Skip the (slow, network-bound) install when everything already imports:
    # it also keeps a sudo run from writing root-owned files into .venv.
    if "$PY" -c "import PyQt6.QtWebEngineWidgets, scapy, psutil, requests, dns, cryptography" >/dev/null 2>&1; then
        return 0
    fi
    "$PY" -m pip install --quiet --upgrade pip
    "$PY" -m pip install --quiet -r "$REPO_DIR/requirements.txt" \
        || fail "dependency installation failed"
}

update_repo() {
    cd "$REPO_DIR"
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || return 0

    local current
    current=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) || return 0
    if [ "$current" != "$BRANCH" ]; then
        say "On branch '$current', skipping auto-update of '$BRANCH'."
        return 0
    fi
    if [ -n "$(git status --porcelain)" ]; then
        say "Local changes present, skipping auto-update."
        return 0
    fi

    git fetch --quiet origin "$BRANCH" || { warn "git fetch failed, keeping local copy"; return 0; }
    local local_sha remote_sha
    local_sha=$(git rev-parse HEAD)
    remote_sha=$(git rev-parse "origin/$BRANCH" 2>/dev/null) || return 0
    if [ "$local_sha" != "$remote_sha" ]; then
        say "Update found, pulling latest changes..."
        git pull --quiet --ff-only origin "$BRANCH" || { warn "git pull failed, keeping local copy"; return 0; }
        if [ "${L0P4MAP_REEXEC:-0}" = "1" ]; then
            return 0
        fi
        say "Updated, restarting with the new version."
        L0P4MAP_REEXEC=1 exec bash "$SCRIPT_PATH" "$@"
    fi
}

# scapy needs CAP_NET_RAW for ARP sniffing. Granting it to the venv interpreter
# means the GUI and its Chromium engine no longer have to run as root.
grant_raw_sockets() {
    [ "$(uname -s)" = "Linux" ] || return 1
    command -v setcap >/dev/null 2>&1 || return 1
    local target
    target=$(readlink -f "$PY")
    if getcap "$target" 2>/dev/null | grep -q cap_net_raw; then
        return 0
    fi
    say "Granting raw-socket capability to $target (sudo password required once)..."
    sudo setcap cap_net_raw,cap_net_admin+eip "$target"
}

raw_sockets_available() {
    "$PY" - <<'PYCODE' >/dev/null 2>&1
import socket
import sys

if sys.platform.startswith("linux"):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    sock.close()
else:
    from scapy.all import conf
    link = conf.L2socket()
    link.close()
PYCODE
}

report_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        say "Running as root — full ARP discovery and packet capture enabled."
        return 0
    fi
    if raw_sockets_available; then
        return 0
    fi
    if grant_raw_sockets && raw_sockets_available; then
        say "Raw sockets enabled, running unprivileged."
        return 0
    fi
    warn "no raw-socket access: ARP scan and packet capture will fail."
    warn "fix once with: sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f "$PY" 2>/dev/null || echo "$PY")"
    warn "on macOS the same features require: ./L0p4Map.sh (launches with sudo)"
}

main() {
    local check_only=0 want_sudo=1
    case "${1:-}" in
        --check) check_only=1 ;;
        --no-sudo) want_sudo=0 ;;
        --sudo) want_sudo=1 ;;
        -h|--help)
            sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
    esac

    install_nmap
    update_repo
    setup_python

    if ! "$PY" -c "import PyQt6.QtWebEngineWidgets" >/dev/null 2>&1; then
        fail "PyQt6-WebEngine is not importable: check the pip output above"
    fi
    say "Dependencies OK ($(nmap --version 2>/dev/null | head -1))"

    if [ "$check_only" -eq 1 ]; then
        report_privileges
        say "Check complete, not launching."
        exit 0
    fi
    cd "$REPO_DIR"
    if [ "$want_sudo" -eq 1 ] && [ "$(id -u)" -ne 0 ] && ! raw_sockets_available; then
        say "Starting with sudo for full ARP discovery and packet capture..."
        exec sudo -E "$PY" ui/app.py
    fi
    # Unprivileged mode is fully supported: only ARP/capture are disabled.
    report_privileges
    exec "$PY" ui/app.py
}

main "$@"
