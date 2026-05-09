# 🍯 HoneyGrid — SSH/HTTP Honeypot

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![SSH](https://img.shields.io/badge/SSH-Honeypot-6a0dad?style=for-the-badge)
![HTTP](https://img.shields.io/badge/HTTP-Honeypot-0077b6?style=for-the-badge)
![Gemini](https://img.shields.io/badge/Gemini_AI-Free_Tier-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Portfolio](https://img.shields.io/badge/Portfolio-D--03_Defensive-0077b6?style=for-the-badge)

**Concurrent SSH and HTTP honeypot with fake filesystem, attacker session recording, and AI threat profiling**

*D-03 of 9 · Cybersecurity Portfolio by [@jmsDev](https://www.linkedin.com/in/jmsilva83)*

</div>

---

## What it does

HoneyGrid runs concurrent SSH and HTTP honeypots that lure attackers, accept any credentials, record every command and HTTP request, simulate a convincing Debian environment to maximize dwell time, and feed captured TTP chains to **Google Gemini** for threat actor profiling.

```bash
honeygrid run --ssh-port 2222 --http-port 8080
honeygrid sessions
honeygrid stats
```

---

## Features

### SSH Honeypot
- **Accepts all credentials** — every username/password combination succeeds
- **Fake Debian 12 filesystem** — `ls`, `cat`, `ps`, `ifconfig`, `netstat`, `wget`, `curl` all respond realistically
- **Full keystroke capture** — every command logged with timestamp and session context
- **Threat classification** — automated TTP tagging (crypto mining, data exfil, persistence, etc.)
- **Session timeline** — complete command history per attacker session

### HTTP Honeypot
- **Fake sensitive endpoints** — `/.env`, `/wp-login.php`, `/phpmyadmin/`, `/admin/`
- **Realistic responses** — serves plausible content to keep attackers engaged
- **Attack detection** — SQLi, XSS, path traversal, webshell upload attempts flagged
- **Credential harvest logging** — captures submitted login attempts

### AI Threat Profiling
- **Actor classification** — script kiddie, APT, ransomware operator, botnet, security researcher
- **TTP chain reconstruction** — what did they try, in what order, what was the goal
- **MITRE ATT&CK mapping** — automatic technique tagging from observed behavior
- **Threat level scoring** — per-session risk assessment

---

## What Gets Captured

| Data Point | SSH | HTTP |
|---|---|---|
| Source IP + port | ✅ | ✅ |
| Credentials attempted | ✅ | ✅ |
| Commands executed | ✅ | — |
| HTTP paths requested | — | ✅ |
| User-Agent | — | ✅ |
| POST body / form data | — | ✅ |
| Timestamps | ✅ | ✅ |
| Session duration | ✅ | — |

---

## Fake Filesystem Responses

The SSH honeypot responds realistically to 30+ common commands:

```bash
$ ls /etc
passwd shadow group hosts hostname resolv.conf ssh/ crontab ...

$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...

$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  168940  9124 ?        Ss   08:12   0:01 /sbin/init
...

$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
      inet 10.0.0.42  netmask 255.255.255.0  broadcast 10.0.0.255
```

---

## Installation

```bash
git clone https://github.com/jmsdev83/honeygrid
cd honeygrid
pip install -e .

cp .env.example .env
# Add GEMINI_API_KEY for AI profiling (optional)
```

### Requirements

- Python 3.11+
- `asyncssh` for SSH server
- Ports 22/2222 for SSH (run as root or set `CAP_NET_BIND_SERVICE` for port 22)

---

## Usage

```bash
# Start both honeypots
honeygrid run --ssh-port 2222 --http-port 8080

# Start with AI profiling enabled
honeygrid run --ssh-port 2222 --http-port 8080 --ai

# View captured sessions
honeygrid sessions

# View specific session detail
honeygrid sessions --id <session_id>

# Live statistics
honeygrid stats

# Generate HTML report
honeygrid report --output honeygrid-report.html

# Demo mode (synthetic attack simulation)
honeygrid demo
```

---

## Architecture

```
honeygrid run
      │
      ├─► SSHHoneypot (asyncssh)
      │      ├── Accept all credentials
      │      ├── Spawn fake shell session
      │      ├── fake_fs.py → realistic command responses
      │      ├── Record every keystroke + command
      │      └── Classify threat level on disconnect
      │
      ├─► HTTPHoneypot (aiohttp)
      │      ├── Serve fake /.env, /admin/, /wp-login.php
      │      ├── Detect SQLi / XSS / path traversal
      │      ├── Log all requests + POST bodies
      │      └── Classify attack type
      │
      └─► SessionStore
             ├── asyncio.Lock — thread-safe
             ├── JSON persistence every update
             └─► GeminiProfiler → actor type + MITRE + profile
```

---

## Threat Levels

| Level | Indicators |
|---|---|
| 🔴 **CRITICAL** | Data exfiltration commands, backdoor installation, cron/service persistence |
| 🟠 **HIGH** | Crypto mining setup, SSH key injection, reverse shell attempts |
| 🟡 **MEDIUM** | Reconnaissance commands (whoami, uname, ps, ifconfig) |
| 🔵 **LOW** | Basic login + single command |
| ⚪ **INFO** | Login only, no commands |

---

## Project Structure

```
honeygrid/
├── honeygrid/
│   ├── protocols/
│   │   ├── ssh_honey.py        # asyncssh SSH honeypot server
│   │   ├── http_honey.py       # aiohttp HTTP honeypot
│   │   └── fake_fs.py          # Fake Debian filesystem responses
│   ├── capture/
│   │   └── session_store.py    # Thread-safe session storage + JSON persistence
│   ├── core/
│   │   ├── orchestrator.py     # HoneyGridConfig + run() entrypoint
│   │   └── ai_profiler.py      # Gemini threat actor profiling
│   ├── types/
│   │   └── events.py           # AttackerSession, AuthAttempt, CommandEntry
│   ├── report/
│   │   ├── generator.py
│   │   └── template.html       # Top attackers, creds, commands, IP map
│   └── cli/
│       └── main.py
└── pyproject.toml
```

---

## Environment Variables

```env
GEMINI_API_KEY=                   # AI threat actor profiling (optional)
HONEYGRID_SSH_PORT=2222
HONEYGRID_HTTP_PORT=8080
HONEYGRID_DATA_DIR=./honeygrid-data
```

---

## Portfolio

| # | Category | Project | Status |
|---|---|---|---|
| P-01 | Offensive | ReconAI — Recon Orchestrator | ✅ |
| P-02 | Offensive | WebHunter — OWASP Top 10 Scanner | ✅ |
| P-03 | Offensive | PhishSim — Red Team Phishing | ✅ |
| D-01 | Defensive | SOC-Lite — AI SIEM | ✅ |
| D-02 | Defensive | ThreatFeed — CTI Aggregator | ✅ |
| D-03 | Defensive | **HoneyGrid** ← you are here | ✅ |
| F-01 | Forensics | DFIR-Auto — Forensic Triage | ✅ |
| F-02 | Forensics | MalwareScope — Malware Analyzer | ✅ |
| F-03 | Forensics | PCAPForge — Network Forensics | ✅ |

---

<div align="center">

Copyright © 2025 Desarrollado desde Las Breñas con 💜 por [@jmsDev](https://www.linkedin.com/in/jmsilva83) · All rights reserved

</div>
