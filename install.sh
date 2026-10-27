#!/usr/bin/env bash
#
# install.sh - installation helper for the protonport project.
#
# What it does (default):
#   1) copies the script to ~/.local/bin/protonport.py           (mode 0700)
#   2) creates the config ~/.config/protonport/protonport.conf from the template
#      (mode 0600; if it ALREADY exists, it is NOT overwritten - only a notice)
#   3) copies the systemd --user unit to ~/.config/systemd/user/
#   4) runs py_compile on the installed script (syntax check)
#   5) daemon-reload + enable --now protonport.service
#
# The script is copied to ~/.local/bin because the workspace path contains spaces
# (see DESIGN.md §9.1/§10.5): the ExecStart in the unit then needs no escaping.
#
# Usage:
#   ./install.sh                 # full install + start the service
#   ./install.sh --install-only  # only copy files, no systemctl enable/start
#   ./install.sh --uninstall     # remove the unit (disable --now) and files
#
# After installing, fill in the credentials:
#   $EDITOR ~/.config/protonport/protonport.conf    # replace __CHANGE_ME__
#   # or: export PROTONPORT_QBIT_PASSWORD='...'     # the password need not be on disk

set -euo pipefail

# $EDITOR is only used in the hints; under `set -u` an unset variable would
# break the install - so give it a safe fallback (default vi).
: "${EDITOR:=vi}"

# Path to the source directory (even when it contains spaces - quoting above).
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN_DIR="$HOME/.local/bin"
BIN_PATH="$BIN_DIR/protonport.py"

CFG_DIR="$HOME/.config/protonport"
CFG_PATH="$CFG_DIR/protonport.conf"
CFG_SRC="$SRC_DIR/protonport.conf.example"

UNIT_DIR="$HOME/.config/systemd/user"
UNIT_PATH="$UNIT_DIR/protonport.service"
UNIT_SRC="$SRC_DIR/protonport.service"

UNIT_NAME="protonport.service"

DO_SYSTEMD=1
DO_UNINSTALL=0

for arg in "$@"; do
  case "$arg" in
    --install-only) DO_SYSTEMD=0 ;;
    --uninstall)    DO_UNINSTALL=1 ;;
    -h|--help)      sed -n '2,/^set -euo/p' "$0" | sed -n 's/^# \{0,1\}//p'; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; echo "Usage: $0 [--install-only|--uninstall]" >&2; exit 2 ;;
  esac
done

echo "=== protonport: installation ==="

if [[ "$DO_UNINSTALL" -eq 1 ]]; then
  echo "[1/3] Stopping and removing the systemd unit ($UNIT_NAME) ..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user disable --now "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_PATH"
    systemctl --user daemon-reload 2>/dev/null || true
  else
    rm -f "$UNIT_PATH"
  fi
  echo "[2/3] Removing the script $BIN_PATH ..."
  rm -f "$BIN_PATH"
  echo "[3/3] Removing the state (the config ~/.config/protonport is KEPT - it holds secrets)."
  rm -rf "$HOME/.local/state/protonport"
  echo "=== done. Remove the config manually if you want: rm -i $CFG_PATH ==="
  exit 0
fi

# --- prerequisites ---------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 was not found in PATH." >&2
  exit 1
fi
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)'; then
  echo "ERROR: Python 3.8 or newer is required." >&2
  exit 1
fi

# --- 1) script ------------------------------------------------------------
echo "[1/5] Copying the script -> $BIN_PATH (0700)"
mkdir -p "$BIN_DIR"
install -m 700 "$SRC_DIR/protonport.py" "$BIN_PATH"

# --- 2) configuration ------------------------------------------------------
echo "[2/5] Configuration -> $CFG_PATH (0600)"
mkdir -p "$CFG_DIR"
if [[ -e "$CFG_PATH" ]]; then
  echo "      The configuration already exists - NOT overwriting it."
  echo "      Check the credentials:  $EDITOR $CFG_PATH"
else
  install -m 600 "$CFG_SRC" "$CFG_PATH"
  echo "      Created from the template. DO NOT FORGET to fill in the credentials "
  echo "      (replace __CHANGE_ME__):"
  echo "        $EDITOR $CFG_PATH"
fi

# --- 3) systemd unit ---------------------------------------------------------
echo "[3/5] systemd unit -> $UNIT_PATH (0644)"
mkdir -p "$UNIT_DIR"
install -m 644 "$UNIT_SRC" "$UNIT_PATH"

# Returns 0 when the config has usable qBittorrent credentials (API key, or
# username+password; env variables count as well). Keeps the installer from
# starting a service that would only exit with a configuration error.
credentials_configured() {
  python3 - "$CFG_PATH" <<'PY'
import json, os, sys

try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        cfg = json.load(fh)
except (OSError, ValueError):
    sys.exit(1)
if not isinstance(cfg, dict):
    sys.exit(1)
qb = cfg.get("qbittorrent") or {}
if not isinstance(qb, dict):
    sys.exit(1)

def clean(value):
    value = str(value or "").strip()
    return "" if value == "__CHANGE_ME__" else value

api_key = clean(os.environ.get("PROTONPORT_QBIT_API_KEY")) or clean(qb.get("api_key"))
username = clean(qb.get("username"))
password = clean(os.environ.get("PROTONPORT_QBIT_PASSWORD")) or clean(qb.get("password"))
sys.exit(0 if api_key or (username and password) else 1)
PY
}

# --- 4) syntax check of the installed script -------------------------------
echo "[4/5] py_compile: $BIN_PATH"
python3 -m py_compile "$BIN_PATH"

echo "[5/5] Done - files are in place."
echo
echo "Test log parsing and the current state (read-only, works while the service runs):"
echo "  $BIN_PATH --config $CFG_PATH --check"
echo "To test a single sync cycle, stop the service first (the lock is single-instance):"
echo "  systemctl --user stop $UNIT_NAME"
echo "  $BIN_PATH --config $CFG_PATH --once --dry-run"

if [[ "$DO_SYSTEMD" -eq 1 ]]; then
  echo
  if ! credentials_configured; then
    echo "qBittorrent credentials are NOT configured (or the config is invalid) - the service was NOT started."
    echo "Fill them in first (api_key, or username + password):"
    echo "  $EDITOR $CFG_PATH"
    echo "Then (if needed) expose the password/key to systemd, and start the service:"
    echo "  systemctl --user daemon-reload && systemctl --user enable --now $UNIT_NAME"
  elif ! command -v systemctl >/dev/null 2>&1; then
    echo "systemctl not found - the service was not started. Start it manually:" >&2
    echo "  systemctl --user daemon-reload && systemctl --user enable --now $UNIT_NAME" >&2
  else
    echo "Starting the systemd --user service ..."
    systemctl --user daemon-reload
    systemctl --user enable --now "$UNIT_NAME"
    # Hardening: verify that the unit physically exists and is enabled - so that
    # a "silent partial install" cannot happen again (set -e would not help here
    # if systemctl ended "successfully" without the unit being created/enabled).
    if [[ ! -f "$UNIT_PATH" ]]; then
      echo "  ERROR: the unit $UNIT_PATH was not created - installation INCOMPLETE." >&2
      exit 1
    fi
    if ! systemctl --user is-enabled --quiet "$UNIT_NAME"; then
      echo "  ERROR: the unit $UNIT_NAME is not enabled - installation INCOMPLETE." >&2
      exit 1
    fi
    echo "  Service started. Status / log:"
    echo "  systemctl --user status $UNIT_NAME"
    echo "  journalctl --user -u $UNIT_NAME -f"
  fi
else
  echo
  echo "--install-only mode: the service is not started. Once the credentials "
  echo "are filled in:"
  echo "  systemctl --user daemon-reload"
  echo "  systemctl --user enable --now $UNIT_NAME"
fi
