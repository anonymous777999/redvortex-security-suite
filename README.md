<p align="center">
  <img src="https://avatars.githubusercontent.com/u/193800714?v=4" width="200" alt="RedVortex Logo">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge" alt="Build">
</p>
<h1 align="center">
  <br/>
  🔒 SECURITY SUITE 🛡️<br/>
  <em>by RedVortex</em> 🐺
</h1>

<div align="center">
  
  **🌐 [GitHub Repository](https://github.com/anonymous777999/redvortex-security-suite) • 🐺 [Contact Links](https://github.com/anonymous777999/RedVortex/)**
  
</div>

---

## 🚀 About RedVortex

**ME RedVortex** represents the relentless pursuit of cybersecurity excellence. As an aspiring elite hacker and dedicated cybersecurity student, my mission is to develop powerful, practical security tools that bridge the gap between academic knowledge and real-world penetration testing. This suite embodies my commitment to creating robust security solutions while continuously evolving my skills in the ever-changing landscape of digital security.

> **"In the world of cybersecurity, only the prepared survive."** - RedVortex

---

## 📋 Overview

The **RedVortex Security Suite** is a comprehensive collection of security tools designed for system administrators, penetration testers, and security enthusiasts. This initial release focuses on **SSH security** with two powerful modules that work in tandem to protect and harden your SSH infrastructure against common attack vectors.

### 🛡️ Core Modules

| Module | Purpose | Status |
|--------|---------|---------|
| **SSH-Guard** 🚨 | Real-time SSH attack detection and prevention | ✅ Active |
| **SSH-Hardening** ⚡ | Automated SSH server configuration hardening | ✅ Active |

---

## ✨ Features

### 🔐 SSH-Guard Module
- **Real-time monitoring** of SSH authentication attempts
- **Intelligent IP blocking** based on failed login thresholds
- **Attack pattern detection** with customizable sensitivity
- **Automatic whitelist management** for trusted networks
- **Live attack dashboard** with detailed logging

### ⚡ SSH-Hardening Module
- **Automated security configuration** for SSH servers
- **Protocol version enforcement** (SSHv2 only)
- **Strong cipher and MAC algorithm selection**
- **User access control** and privilege escalation limits
- **Banner and information leakage prevention**
- **Compliance templates** for various security standards

---

## 📥 Installation

### Prerequisites
- **Linux** operating system (Ubuntu/Debian/CentOS)
- **Root/sudo access** for system modifications

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/anonymous777999/redvortex-security-suite.git
cd redvortex-security-suite
mv 20-systemd-ssh-proxy.conf /etc/ssh/sshd_config.d
# Everytime run this command [ sudo systemctl restart ssh ] when You change anything in 20-system-ssh-proxy.conf 

# 2. Run Commands 
chmod +x redvortex_ssh_guard.sh
# For Running this Tool use this command 👇
./redvortex_ssh_guard.sh
```

---

<h2>🎯 Usage : HELP MENU </h2>

```bash

./redvortex_ssh_guard.sh -h    

RedVortex SSH Guard v4.1

Usage: ./redvortex_ssh_guard.sh [command] [options]

Commands:
  (none)              Start monitoring
  --menu              Interactive menu
  --status            Show full status

Whitelist:
  --whitelist-add IP      Add IP to whitelist (also unbans)
  --whitelist-remove IP   Remove IP from whitelist
  --whitelist-show        Show all whitelisted IPs

Ban Management:
  --unban IP          Remove ban for specific IP
  --unban-all         Remove ALL bans
  --ban IP [reason]   Manually ban an IP
  --list-banned       Show all banned IPs

Other:
  --test              Test firewall blocking
  --reset             Remove all rules and data
  --help              Show this help

Examples:
  ./redvortex_ssh_guard.sh --whitelist-add 192.168.1.100
  ./redvortex_ssh_guard.sh --unban 10.0.0.50
./redvortex_ssh_guard.sh --ban 203.0.113.5 "manual block"

=================================================================================================================

./redvortex_ssh_guard.sh --menu

╔════════════════════════════════════════╗
║       RedVortex Guard - Menu           ║
╠════════════════════════════════════════╣
║  1. Show status                        ║
║  2. List banned IPs                    ║
║  3. List whitelisted IPs               ║
║  4. Add IP to whitelist                ║
║  5. Remove IP from whitelist           ║
║  6. Unban an IP                        ║
║  7. Unban ALL IPs                      ║
║  8. Start monitoring                   ║
║  0. Exit                               ║
╚════════════════════════════════════════╝
Choose option: 


```

---

### Screenshots

#### Menu
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/MENU-1.png)
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/OPTION-1.png)
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/OPTION-2.png)
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/OPTION-3.png)
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/OPTION-4.png)
![Menu Screenshot](https://github.com/anonymous777999/redvortex-security-suite/blob/main/Screenshots/OPTION-5.png)

---

<h1>⚠️ Security Disclaimer</h1>

Deploy only on systems you own or have explicit permission to test.
Unauthorized usage may be illegal. Educational & authorized testing only.

---

<h2>📄 License</h2>
This project is licensed under the MIT License

---

<div align="center">
🐺 Stay Secure. Stay Vigilant. Stay in the Vortex. 🛡️
"In the hands of the knowledgeable, security becomes an art form."

RedVortex Security Suite - For educational and authorized security testing purposes only.

</div> ```
