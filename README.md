# Blue Team SOC Lab

![Splunk](https://img.shields.io/badge/Splunk-10.2-black?style=for-the-badge&logo=splunk&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-EC2-orange?style=for-the-badge&logo=amazonaws&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-Attacker-blue?style=for-the-badge&logo=kalilinux&logoColor=white)
![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-PCAP-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Lab Architecture](#lab-architecture)
- [Tools Used](#tools-used)
- [Projects](#projects)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Detection Rules](#detection-rules)
- [How to Replicate the Lab](#how-to-replicate-the-lab)
- [Contact](#contact)

---

## Project Overview

This repository documents a hands-on Blue Team Security Operations Center (SOC) lab I built entirely on AWS EC2. The goal was to simulate real-world attack scenarios, detect them using Splunk Enterprise, and practice the full analyst workflow from log ingestion to alert creation and incident response.

I designed this lab to build and demonstrate practical skills that are directly applicable to a junior SOC analyst role. Every detection in this repository has been confirmed with live Splunk results, and all supporting scripts and detection rules are included.

The lab covers the following attack categories:

- SSH brute force attacks (simulated with Hydra from Kali Linux)
- Network reconnaissance (Nmap port and service scans)
- Phishing email analysis and IOC extraction
- Packet capture and network forensics (tcpdump and Wireshark)
- Persistence and privilege escalation (auditd monitoring)
- Threat hunting with custom Splunk queries
- SOC dashboard building
- Full incident response report writing

---

## Lab Architecture

```
+--------------------------------------------------+
|                  AWS af-south-1                  |
|              (Africa / Cape Town)                |
|                                                  |
|  +--------------------+   +-------------------+ |
|  |  Splunk Enterprise |   |   Victim Machine  | |
|  |      10.2.0        |   |   Ubuntu 24.04    | |
|  |                    |   |                   | |
|  |  15.240.43.62:8000 |<--| 13.246.220.248    | |
|  |  t3.medium         |   | ip-172-31-3-95    | |
|  |  Ubuntu Server     |   | Splunk UF running | |
|  +--------------------+   | auditd enabled    | |
|                           +-------------------+ |
|                                    ^            |
+--------------------------------------------------+
                                     |
                            SSH brute force
                            Nmap recon
                            Persistence sim
                                     |
                    +--------------------------------+
                    |       Attacker Machine         |
                    |         Kali Linux             |
                    |   Hydra, Nmap, tcpdump,        |
                    |   custom phishing scripts      |
                    +--------------------------------+
```

**Data Flow:**
```
Victim Logs (/var/log/auth.log, /var/log/audit/audit.log)
     |
     v
Splunk Universal Forwarder
     |
     v
Splunk Enterprise (Indexer + Search Head)
     |
     v
Detection Rules --> Alerts --> Incident Response
```

---

## Tools Used

| Tool | Purpose | Version |
|------|---------|---------|
| Splunk Enterprise | SIEM, log analysis, alerting | 10.2.0 |
| Splunk Universal Forwarder | Log shipping from victim to Splunk | 9.1.x |
| AWS EC2 | Cloud infrastructure | af-south-1 region |
| Kali Linux | Attacker simulation | Rolling |
| Hydra | SSH brute force simulation | 9.x |
| Nmap | Network reconnaissance simulation | 7.x |
| auditd | Linux system call auditing | 3.x |
| tcpdump | Packet capture | 4.x |
| Wireshark | PCAP analysis | 4.x |
| Python 3 | Scripting and IOC extraction | 3.x |

---

## Projects

| # | Project | Techniques | MITRE ID |
|---|---------|-----------|----------|
| 01 | [SSH Brute Force Detection](projects/01-brute-force-detection/README.md) | Credential brute forcing over SSH | T1110.001 |
| 02 | [Nmap Recon Detection](projects/02-nmap-recon-detection/README.md) | Active network scanning | T1046 |
| 03 | [Phishing Email Analysis](projects/03-phishing-analysis/README.md) | Spearphishing, IOC extraction | T1566.001 |
| 04 | [PCAP Network Forensics](projects/04-pcap-network-forensics/README.md) | Network traffic analysis | T1040 |
| 05 | [Threat Hunting](projects/05-threat-hunting/README.md) | Persistence and privilege escalation | T1053.003, T1136 |
| 06 | [SOC Dashboard](projects/06-soc-dashboard/README.md) | Dashboard building in Splunk | N/A |
| 07 | [Incident Response Report](projects/07-incident-response-report/README.md) | Full IR documentation | N/A |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID | Detection Method |
|--------|-----------|-----|-----------------|
| Reconnaissance | Network Service Scanning | T1046 | Splunk query on syslog/auth.log |
| Credential Access | Brute Force: Password Guessing | T1110.001 | Failed password spike in auth.log |
| Initial Access | Spearphishing Attachment | T1566.001 | Manual IOC analysis |
| Persistence | Scheduled Task/Job: Cron | T1053.003 | auditd + Splunk alert |
| Persistence | Create Account | T1136 | auditd user_modification rule |
| Privilege Escalation | Abuse Elevation Control | T1548 | auditd privilege_escalation rule |
| Discovery | Network Sniffing | T1040 | tcpdump PCAP analysis |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | PCAP and connection log analysis |

---

## Detection Rules

All Splunk detection rules are stored in the [detection-rules/](detection-rules/) directory:

- [brute-force-alert.spl](detection-rules/brute-force-alert.spl) - Detects SSH brute force by counting failed logins per source IP
- [recon-detection.spl](detection-rules/recon-detection.spl) - Detects Nmap scanning patterns in syslog
- [persistence-detection.spl](detection-rules/persistence-detection.spl) - Detects persistence and privilege escalation via auditd

---

## How to Replicate the Lab

### Prerequisites

- AWS account (free tier works for the victim; Splunk needs at least t3.medium)
- Kali Linux (local VM or separate EC2)
- Basic Linux command-line experience

### Step 1 - Launch EC2 Instances

1. Log into AWS Console and navigate to EC2 in the **af-south-1** (Africa Cape Town) region.
2. Launch a **t3.medium** Ubuntu 22.04 instance for Splunk Enterprise.
3. Launch a **t2.micro** Ubuntu 24.04 instance as the victim.
4. Open inbound security group rules:
   - Splunk: port 8000 (web UI), port 9997 (forwarder receive)
   - Victim: port 22 (SSH)

### Step 2 - Install Splunk Enterprise

```bash
# Download Splunk Enterprise (get the link from splunk.com)
wget -O splunk.deb 'https://download.splunk.com/products/splunk/releases/10.2.0/linux/splunk-10.2.0-amd64.deb'
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

### Step 3 - Set Up the Splunk Universal Forwarder

Run the setup script on the victim machine:

```bash
chmod +x scripts/setup-splunk-forwarder.sh
sudo ./scripts/setup-splunk-forwarder.sh
```

See [scripts/setup-splunk-forwarder.sh](scripts/setup-splunk-forwarder.sh) for full details.

### Step 4 - Enable auditd on the Victim

```bash
chmod +x scripts/threat-hunting-rules.sh
sudo ./scripts/threat-hunting-rules.sh
```

### Step 5 - Run Attack Simulations

```bash
# SSH brute force from Kali
chmod +x scripts/brute-force-simulation.sh
./scripts/brute-force-simulation.sh

# Nmap recon from Kali
nmap -sV -sS <victim_public_ip>
```

### Step 6 - Import Detection Rules into Splunk

Copy the SPL queries from the [detection-rules/](detection-rules/) directory into Splunk Search and save each as an alert.

---

## Contact

**Sizwe Marole**
Junior SOC Analyst | Blue Team Security Enthusiast

- GitHub: [SizweMarole-21389](https://github.com/SizweMarole-21389)
- Email: marolesizwe1@gmail.com
- LinkedIn: [Add your LinkedIn URL here]
- Location: South Africa

---

*This lab was built entirely for learning and portfolio purposes. All attack simulations were conducted in an isolated AWS environment that I own and control.*
