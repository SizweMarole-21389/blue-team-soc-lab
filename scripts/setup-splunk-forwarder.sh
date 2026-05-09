#!/usr/bin/env bash
# ==============================================================================
# setup-splunk-forwarder.sh
# Installs and configures Splunk Universal Forwarder on Ubuntu 24.04.
# Run this script on the VICTIM machine, not on the Splunk server.
# Usage: sudo ./setup-splunk-forwarder.sh
# ==============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
# Replace these values with your actual Splunk server IP and deployment credentials.
SPLUNK_SERVER_IP="15.240.43.62"
SPLUNK_RECEIVE_PORT="9997"
SPLUNK_ADMIN_USER="admin"
SPLUNK_ADMIN_PASS="changeme123"   # Change this before running
FORWARDER_VERSION="9.1.4"
FORWARDER_BUILD="a22b31d2e1f8"   # Update to the current build hash from splunk.com
FORWARDER_DEB="splunkforwarder-${FORWARDER_VERSION}-${FORWARDER_BUILD}-linux-2.6-amd64.deb"
DOWNLOAD_URL="https://download.splunk.com/products/universalforwarder/releases/${FORWARDER_VERSION}/linux/${FORWARDER_DEB}"
INSTALL_DIR="/opt/splunkforwarder"

# Log sources to monitor
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
AUDIT_LOG="/var/log/audit/audit.log"

# --- Helper functions --------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "Error: This script must be run as root. Use: sudo $0"
        exit 1
    fi
}

# --- Main --------------------------------------------------------------------
check_root

log "Starting Splunk Universal Forwarder setup..."
log "Target Splunk server: ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}"

# Step 1: Download the Universal Forwarder package
log "Downloading Splunk Universal Forwarder ${FORWARDER_VERSION}..."
if [[ ! -f "/tmp/${FORWARDER_DEB}" ]]; then
    wget -O "/tmp/${FORWARDER_DEB}" "${DOWNLOAD_URL}"
    log "Download complete."
else
    log "Package already exists at /tmp/${FORWARDER_DEB}, skipping download."
fi

# Step 2: Install the package
log "Installing Splunk Universal Forwarder..."
dpkg -i "/tmp/${FORWARDER_DEB}"
log "Installation complete."

# Step 3: Accept the licence and start the forwarder
log "Accepting licence and starting forwarder..."
"${INSTALL_DIR}/bin/splunk" start --accept-license \
    --answer-yes \
    --no-prompt \
    --seed-passwd "${SPLUNK_ADMIN_PASS}" 2>/dev/null || true

# Step 4: Enable boot-start so the forwarder survives a reboot
log "Enabling boot-start..."
"${INSTALL_DIR}/bin/splunk" enable boot-start -user splunk 2>/dev/null || true

# Step 5: Configure the forwarding server (Splunk indexer)
log "Configuring forwarding to ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}..."
"${INSTALL_DIR}/bin/splunk" add forward-server \
    "${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}" \
    -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"

# Step 6: Add log sources to monitor
log "Adding monitor for ${AUTH_LOG}..."
"${INSTALL_DIR}/bin/splunk" add monitor "${AUTH_LOG}" \
    -index main \
    -sourcetype linux_secure \
    -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"

log "Adding monitor for ${SYSLOG}..."
"${INSTALL_DIR}/bin/splunk" add monitor "${SYSLOG}" \
    -index main \
    -sourcetype syslog \
    -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"

# Audit log requires auditd to be installed (see threat-hunting-rules.sh)
if [[ -f "${AUDIT_LOG}" ]]; then
    log "Adding monitor for ${AUDIT_LOG}..."
    "${INSTALL_DIR}/bin/splunk" add monitor "${AUDIT_LOG}" \
        -index main \
        -sourcetype linux_audit \
        -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"
else
    log "Warning: ${AUDIT_LOG} not found. Run threat-hunting-rules.sh first to install auditd."
fi

# Step 7: Fix SPLUNK_HOME ownership so the forwarder can run as the splunk user
log "Setting correct file ownership..."
if id "splunk" &>/dev/null; then
    chown -R splunk:splunk "${INSTALL_DIR}"
fi

# Step 8: Restart the forwarder to apply all changes
log "Restarting Splunk Universal Forwarder..."
"${INSTALL_DIR}/bin/splunk" restart --accept-license --answer-yes

# Step 9: Verify the forwarder is running and connected
log "Verifying forwarder status..."
sleep 5
"${INSTALL_DIR}/bin/splunk" list forward-server \
    -auth "${SPLUNK_ADMIN_USER}:${SPLUNK_ADMIN_PASS}"

# Step 10: Clean up the downloaded package
log "Cleaning up downloaded package..."
rm -f "/tmp/${FORWARDER_DEB}"

log "===================================================================="
log "Splunk Universal Forwarder setup complete."
log ""
log "  Forwarding to:  ${SPLUNK_SERVER_IP}:${SPLUNK_RECEIVE_PORT}"
log "  Monitoring:     ${AUTH_LOG}"
log "  Monitoring:     ${SYSLOG}"
if [[ -f "${AUDIT_LOG}" ]]; then
    log "  Monitoring:     ${AUDIT_LOG}"
fi
log ""
log "  Wait 30-60 seconds, then check Splunk at:"
log "  http://${SPLUNK_SERVER_IP}:8000"
log ""
log "  In Splunk Search, run:"
log "    index=* host=$(hostname)"
log "  to verify events are arriving."
log "===================================================================="
