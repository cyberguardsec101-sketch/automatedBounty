# 🔴 DRKSHDW — Automated Bug Bounty Framework

> Offensive recon automation for serious hunters  
> Fast. Silent. Effective.

AutomatedBounty (DRKSHDW) is an offensive security framework designed to **automate reconnaissance, surface attack paths, and accelerate vulnerability discovery** in bug bounty programs and authorized targets.

Built for hackers who prefer:
- less clicking
- more signal
- real findings

---

## ⚡ What is this?

DRKSHDW combines:

✔ OSINT  
✔ Passive recon  
✔ Active scanning  
✔ Smart fuzzing  
✔ Vulnerability triage  

into **one single workflow**.

Instead of running 10 tools manually…  
you run **one pipeline**.

---

# 🧠 Features

## 🔎 Recon Engine
- Subdomain discovery (crt.sh)
- Historical URLs (Wayback)
- Asset surface mapping
- Endpoint harvesting

## 🕵️ Dork Generator
- .env exposures
- .git leaks
- logs / backups
- admin panels
- debug endpoints

## 🧨 Fuzzing
- dirsearch / ffuf integration
- historical wordlist generation
- context-aware paths

## 🛡 Vulnerability Analysis
- Nmap vuln scripts
- service fingerprinting
- misconfig detection
- risk hints

## 🌐 Passive Intel
- Shodan integration (optional)
- exposed services
- banners
- cloud leaks

## 🧠 Smart Suggestions
- PoC hints
- validation ideas
- triage guidance

---

# 🧰 Stack

```
Python3
Nmap
FFUF
Dirsearch
Shodan API
Requests / BS4
```

---

# 🚀 Installation

## Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y nmap ffuf dirsearch python3-pip
pip3 install python-nmap requests beautifulsoup4 shodan
```

---

# 📦 Project Structure

```
automatedBounty/
│
├── recon_master.py       # surface discovery
├── vuln_analyzer.py      # vuln triage & analysis
├── wordlists/            # custom fuzz lists
├── outputs/              # json reports
├── targets.txt           # scope list
└── README.md
```

---

# ⚔️ Usage

## 1️⃣ Recon (single target)

```bash
python3 recon_master.py example.com
```

## 2️⃣ Recon (multiple targets)

```bash
python3 recon_master.py -l targets.txt
```

## 3️⃣ Analyze vulnerabilities

```bash
python3 vuln_analyzer.py recon_example.com.json
```

---

# 🌐 Shodan (optional)

```bash
export SHODAN_API_KEY="YOUR_KEY"
```

Adds:
- exposed ports
- banners
- leaked services
- passive intel

---

# 🧠 Recommended Workflow (Elite Mode)

```
Recon → Filter → Fuzz → Analyze → Validate → Report
```

### Strategy
1. Run recon
2. Prioritize high-value assets
3. Fuzz intelligently
4. Validate manually
5. Write clean report

Signal > Noise

---

# 📄 Output

Reports are generated as:

```
outputs/recon_example.com.json
```

Includes:
- subdomains
- endpoints
- open ports
- potential vulns
- PoC hints

---

# 🔥 Philosophy

> Automate the boring  
> Focus on impact  
> Think like an attacker  

---

# ⚠️ Disclaimer

For **authorized security testing only**.  
Do not scan targets without permission.

You are responsible for your actions.
