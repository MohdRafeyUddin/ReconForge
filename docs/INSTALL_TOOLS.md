# Security Tool Installation Guide

This guide details the commands to install all required security tools and command-line utilities on **Kali Linux** or **Ubuntu (WSL)**.

---

## 1. System Dependencies

First, update your package repository and install core system utilities, Python 3, Go, and Node.js:

```bash
sudo apt update
sudo apt install -y git curl wget python3 python3-pip python3-venv golang nodejs npm
```

---

## 2. ProjectDiscovery Tools

ProjectDiscovery provides the backbone for the resolution, live host probing, and vulnerability checking phases. Install them via Go:

```bash
# Subfinder (Passive Subdomain Discovery)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTPX (Live Host Probing)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Naabu (Port Discovery)
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nuclei (Vulnerability Scanning)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# DNSx (DNS Resolution)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Katana (Web Crawling & Spidering)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Chaos Client (Chaos Dataset Queries)
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

---

## 3. Other Reconnaissance Tools

Install additional domain gathering, crawler, and classification utilities:

```bash
# Assetfinder (Passive Subdomain Discovery)
go install github.com/tomnomnom/assetfinder@latest

# GF (Grep Wrapper for Vulnerability Patterns)
go install github.com/tomnomnom/gf@latest

# SubJS (JavaScript Discovery)
go install github.com/lc/subjs@latest

# GAU (Get All URLs - Historical URLs extraction)
go install github.com/lc/gau/v2/cmd/gau@latest

# Hakrawler (Web Crawler)
go install github.com/hakluke/hakrawler@latest

# Unfurl (URL Parsing & Analysis)
go install github.com/tomnomnom/unfurl@latest

# FFUF (Fuzzing)
go install github.com/ffuf/ffuf/v2@latest

# GoWitness (Visual Recon & Screenshots)
go install github.com/sensepost/gowitness@latest

# Dalfox (Confirmed XSS Scanner)
go install github.com/hahwul/dalfox/v2@latest
```

---

## 4. Subzy (Subdomain Takeover Scanner)

Install the takeover checker utility:

```bash
go install github.com/PentestPad/subzy@latest
```

---

## 5. Python-based Tools

Install `uro` for cleaning, deduplicating, and normalizing parameterised URLs before scanning:

```bash
pipx install uro
```

*Note: If `pipx` is not installed, install it using `sudo apt install pipx`.*

---

## 6. Gitleaks (Secret Scanning)

Install the standalone secret detection scanner:

```bash
sudo apt install gitleaks
```

---

## 7. PATH Environment Configuration

Ensure your shell environment can discover the compiled Go binaries and Python script entry points. Add the following lines to your profile configuration file (e.g., `~/.bashrc` or `~/.zshrc`):

```bash
# Append local binary directories to system PATH
export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin
```

Reload your shell config to apply changes immediately:
```bash
source ~/.bashrc
```

---

## 8. Verification

Verify that all critical tools are installed and accessible on your PATH:

```bash
subfinder -version
httpx -version
nuclei -version
katana -version
dnsx -version
naabu -version
subzy -version
dalfox version
gowitness version
uro --version
```
