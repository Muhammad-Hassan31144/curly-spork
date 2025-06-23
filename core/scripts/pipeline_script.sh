#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#  Shikra File‑Pipeline Script
# -----------------------------------------------------------------------------
#  Automates end‑to‑end transfer of tools / samples **to** an isolated Windows
#  analysis VM over SSH, triggers the execution under Procmon, then retrieves
#  the resulting logs back to the host.
#
#  Requirements on the **host** (Ubuntu):
#     ▸ openssh‑client (scp, ssh)  ▸ jq (for simple JSON parsing, optional)
#  Requirements on the **guest** (Windows):
#     ▸ OpenSSH server enabled & running (built‑in since Win10 1809)
#     ▸ A local user with an SSH key or password that can run commands
#     ▸ procmon.exe already uploaded once or referenced by URL
#
#  Typical usage:
#     sudo ./shikra_file_pipeline.sh \   # root needed only if you keep PCAP
#         --ip 192.168.100.5            \
#         --user analyst                \
#         --sample ./samples/bad.exe    \
#         --procmon ./tools/Procmon.exe \
#         --remote-dir C:\\sandbox    \
#         --runtime 120                \
#         --pull ./loot
# -----------------------------------------------------------------------------
set -euo pipefail

# -------------------------- Defaults & helpers --------------------------------
WIN_IP=""
WIN_USER="analyst"
SSH_KEY="~/.ssh/id_rsa"
SAMPLE_PATH=""
PROCMON_PATH=""
REMOTE_DIR="C:\\sandbox"
RUN_TIME=90            # seconds Procmon will capture after sample start
PULL_DIR="./loot"
LOG_PREFIX="run"

color() { local c=$1 msg=$2; case $c in red) echo -e "\033[0;31m$msg\033[0m";; green) echo -e "\033[0;32m$msg\033[0m";; yellow) echo -e "\033[1;33m$msg\033[0m";; *) echo "$msg";; esac; }
usage() {
  cat << EOF
Usage: $0 --ip <win_ip> --sample <file> --procmon <file> [options]
Options:
  --user <user>         Windows SSH username (default: analyst)
  --key <path>          Private key for SSH auth (default: ~/.ssh/id_rsa)
  --remote-dir <dir>    Destination folder in guest (default: C:\\sandbox)
  --runtime <sec>       Seconds to capture before stopping Procmon (default: 90)
  --pull <dir>          Local dir to dump logs + artifacts (default: ./loot)
  --log-prefix <name>   Base name for PML & pulled files (default: run)
  -h, --help            Show this message
EOF
  exit 1
}

[[ $# -eq 0 ]] && usage
while [[ $# -gt 0 ]]; do case $1 in
  --ip)          WIN_IP=$2; shift 2;;
  --user)        WIN_USER=$2; shift 2;;
  --key)         SSH_KEY=$2; shift 2;;
  --sample)      SAMPLE_PATH=$2; shift 2;;
  --procmon)     PROCMON_PATH=$2; shift 2;;
  --remote-dir)  REMOTE_DIR=$(echo "$2" | sed 's/\\/\\\\/g'); shift 2;;
  --runtime)     RUN_TIME=$2; shift 2;;
  --pull)        PULL_DIR=$2; shift 2;;
  --log-prefix)  LOG_PREFIX=$2; shift 2;;
  -h|--help)     usage;;
  *) color red "Unknown option $1"; usage;;
esac; done

for var in WIN_IP SAMPLE_PATH PROCMON_PATH; do
  [[ -z "${!var}" ]] && color red "Error: --${var,,} is required" && usage
done

[[ ! -f "$SAMPLE_PATH" ]]  && color red "Sample file not found: $SAMPLE_PATH" && exit 1
[[ ! -f "$PROCMON_PATH" ]] && color red "Procmon file not found: $PROCMON_PATH" && exit 1

mkdir -p "$PULL_DIR"

# ---------------------------- Helper macros ----------------------------------
REMOTE_PML="${REMOTE_DIR}\\${LOG_PREFIX}.pml"
REMOTE_SAMPLE="${REMOTE_DIR}\\$(basename "$SAMPLE_PATH" | sed 's/ /_/g')"
REMOTE_PROCMON="${REMOTE_DIR}\\$(basename "$PROCMON_PATH" | sed 's/ /_/g')"
WINCMD() { # convenience wrapper to run a Windows cmd via ssh
  # handle crazy quoting, double‑up backslashes for PowerShell
  local raw=$*; ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "${WIN_USER}@${WIN_IP}" "$raw"; }

# ---------------------------- Transfer phase ---------------------------------
color yellow "[*] Uploading files to $WIN_IP …"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "$PROCMON_PATH" "$SAMPLE_PATH" "${WIN_USER}@${WIN_IP}:$(echo "$REMOTE_DIR" | sed 's/\\\\/\//g')/" >/dev/null
color green "[+] Upload complete"

# ---------------------------- Execution phase --------------------------------
color yellow "[*] Launching Procmon + sample (capture ${RUN_TIME}s) …"
# Build Windows command: start Procmon, wait, run sample, wait, then terminate Procmon
WINCMD "cmd /c \"%SystemRoot%\\System32\\timeout.exe /t 1 >nul && \\
  \"${REMOTE_PROCMON}\" /AcceptEula /Quiet /Minimized /BackingFile \"${REMOTE_PML}\" && \\
  %SystemRoot%\\System32\\timeout.exe /t 3 >nul && \\
  \"${REMOTE_SAMPLE}\" && \\
  %SystemRoot%\\System32\\timeout.exe /t ${RUN_TIME} >nul && \\
  taskkill /IM procmon.exe /F >nul\""
color green "[+] Execution finished; log should be at ${REMOTE_PML}"

# ---------------------------- Retrieval phase --------------------------------
color yellow "[*] Pulling PML back …"
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "${WIN_USER}@${WIN_IP}:$(echo "$REMOTE_PML" | sed 's/\\\\/\//g')" "${PULL_DIR}/${LOG_PREFIX}.pml" >/dev/null
color green "[+] Retrieved log → ${PULL_DIR}/${LOG_PREFIX}.pml"

# ---------------------------- Done -------------------------------------------
color green "All done! Analyse away."
