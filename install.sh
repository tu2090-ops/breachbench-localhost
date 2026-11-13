#!/usr/bin/env bash
# ==============================================================================
# BreachBench Local & Multi-Machine Permission-Gated Installer
# Copyright 2026 Tanushree Umathe (Apache License 2.0)
# ==============================================================================
set -euo pipefail

MODE="local"
MACHINES_FILE="config/machines.example.json"
MACHINES_CSV=""
CONFIRM_PERMISSION="false"
DRY_RUN="false"

usage() {
  cat <<USAGE
Usage: ./install.sh [OPTIONS]

Options:
  --local                     Install BreachBench on this local machine (default)
  --multi-machine             Deploy & run BreachBench across authorized SSH machines
  --machines <h1,h2>          Comma-separated hostnames/IPs (must be in allowlist)
  --machines-file <path>      Path to JSON allowlist file (default: config/machines.example.json)
  --confirm-permission        Explicit non-interactive confirmation of owner authorization
  --dry-run                   Validate permissions and print planned commands without executing
  -h, --help                  Show this help message
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --local)
      MODE="local"
      shift
      ;;
    --multi-machine)
      MODE="multi-machine"
      shift
      ;;
    --machines)
      MACHINES_CSV="$2"
      shift 2
      ;;
    --machines-file)
      MACHINES_FILE="$2"
      shift 2
      ;;
    --confirm-permission)
      CONFIRM_PERMISSION="true"
      shift
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

echo "=================================================================="
echo "  BreachBench Security Suite — Permission Gate & Installer"
echo "  Mode: ${MODE}"
echo "=================================================================="

if [[ "${CONFIRM_PERMISSION}" != "true" ]]; then
  echo ""
  echo "[PERMISSION REQUIRED]"
  echo "You are about to install BreachBench (${MODE} mode)."
  echo "Confirm that you own or have explicit authorization to install and run"
  echo "security benchmarks on the target machine(s)."
  read -r -p "Type 'YES_I_HAVE_AUTHORIZATION' to proceed: " USER_CONSENT
  if [[ "${USER_CONSENT}" != "YES_I_HAVE_AUTHORIZATION" ]]; then
    echo "[ABORTED] Explicit authorization was not granted. Exiting without changes."
    exit 1
  fi
fi

if [[ "${MODE}" == "local" ]]; then
  if [[ "${DRY_RUN}" == "true" ]]; then
    echo "[DRY-RUN] Would run: python3 -m pip install -e ."
    exit 0
  fi
  echo "[INFO] Installing BreachBench locally in editable mode..."
  python3 -m pip install -e .
  echo "[SUCCESS] BreachBench installed. Run 'breachbench --help' to get started."
else
  CMD=(python3 -m breachbench deploy-machines --machines-file "${MACHINES_FILE}" --confirm-permission)
  if [[ -n "${MACHINES_CSV}" ]]; then
    CMD+=(--machines "${MACHINES_CSV}")
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    CMD+=(--dry-run)
  else
    CMD+=(--execute)
  fi
  "${CMD[@]}"
fi
