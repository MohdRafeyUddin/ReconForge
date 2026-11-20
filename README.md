# ReconForge — Attack Surface Management Platform

ReconForge is a modern, comprehensive Attack Surface Management (ASM) platform designed to automate asset discovery, reconnaissance, web crawling, vulnerability validation, and attack surface risk prioritization.

---

## 1. Overview

ReconForge automates the end-to-end intelligence collection pipeline for security teams. By integrating industry-standard open-source security tools with a centralized post-processing risk engine and a real-time reactive React dashboard, it maps out external exposure boundaries and highlights high-remediation priorities.

---

## 2. Features

*   **Discovery Layer**: Passive subdomain gathering via **Subfinder**, **Assetfinder**, **Amass**, and **Chaos**.
*   **Resolution & Validation**: DNS mapping via **DNSx** and CNAME takeover scanning via **Subzy**.
*   **Port & Service Discovery**: Multi-protocol port checking via **Naabu** and web response probing via **HTTPX**.
*   **Spidering & Crawling**: Parameter and endpoints crawling using **Katana** and historical URL querying via **GAU**.
*   **JavaScript Analysis**: Extract JS dependencies using **SubJS** and search for API endpoints or credentials using **LinkFinder**.
*   **URL Processing**: Parameter normalization via **Uro** and vulnerability classification via **GF** patterns (SQLi, XSS, SSRF, LFI, RCE, IDOR, SSTI, AWS, etc.).
*   **Active Security Validation**: Vulnerability scanning via **Nuclei**, automated XSS confirmation via **Dalfox**, and open redirect checking via **OpenRedirex**.
*   **Visual Verification**: Headless screenshot rendering via **GoWitness**.
*   **Risk Scoring Engine**: Normalizes metadata, exposed ports, tech stacks, and active vulnerabilities into a `0-100` risk score with priority rankings.

---

## 3. Architecture Flowchart

Below is the execution flow of the ReconForge automated pipeline:

```
                  TARGET DOMAIN
                        |
                        v
          +---------------------------+
          |    Discovery Providers    | (Subfinder, Assetfinder, Amass, Chaos)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |      DNS Resolution       | (DNSx + Subzy Check)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |       HTTP Probing        | (Naabu + HTTPX Gating)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |       Crawler Layer       | (Katana + GAU + SubJS + LinkFinder)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |     URL Intelligence      | (Uro + GF Classification)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |    Security Validation    | (Nuclei + Dalfox + OpenRedirex + GoWitness)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |        Risk Engine        | (Normalized Scoring Configs)
          +---------------------------+
                        |
                        v
          +---------------------------+
          |      React Dashboard      | (Interactive UI Telemetry)
          +---------------------------+
```

---

## 4. Screenshots

Screenshots of the dark-mode dashboard, vulnerability console, and risk priority tables are hosted under [docs/images/](file:///c:/Users/rafey/Desktop/ReconForge/docs/images/).

---

## 5. Installation

### A. System & Tool Installation

#### System Requirements
Recommended:
- Linux / Kali Linux / Ubuntu WSL2
- Python 3.10+
- Node.js 18+
- Golang latest
- MongoDB

#### WSL Installation (Windows)
Install WSL:
```powershell
wsl --install
```

Install Ubuntu:
```powershell
wsl --install -d Ubuntu
```

Update:
```bash
sudo apt update && sudo apt upgrade -y
```

#### Install Base Packages
```bash
sudo apt install -y \
  git \
  curl \
  wget \
  python3 \
  python3-pip \
  python3-venv \
  pipx \
  nodejs \
  npm \
  golang \
  unzip
```

Configure Go:
Add to `~/.bashrc`:
```bash
export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin
```

Reload:
```bash
source ~/.bashrc
```

#### ProjectDiscovery Tools

Subfinder:
```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

HTTPX:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Naabu:
```bash
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

Nuclei:
```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Update templates:
```bash
nuclei -update-templates
```

DNSx:
```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

Katana:
```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

Chaos:
```bash
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

#### Discovery Tools

Assetfinder:
```bash
go install github.com/tomnomnom/assetfinder@latest
```

Amass:
```bash
sudo apt install amass -y
```

Subzy:
```bash
go install github.com/PentestPad/subzy@latest
```

#### URL / Endpoint Tools

GAU:
```bash
go install github.com/lc/gau/v2/cmd/gau@latest
```

GF:
```bash
go install github.com/tomnomnom/gf@latest
```

Install GF patterns:
```bash
git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir ~/.gf
cp Gf-Patterns/*.json ~/.gf/
```

URO:
```bash
pipx install uro
```

SubJS:
```bash
go install github.com/lc/subjs@latest
```

LinkFinder:
```bash
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip install -r requirements.txt
```

#### Validation Tools

Dalfox:
```bash
go install github.com/hahwul/dalfox/v2@latest
```

GoWitness:
```bash
go install github.com/sensepost/gowitness@latest
```

OpenRedirex:
```bash
git clone https://github.com/devanshbatham/OpenRedireX.git
```

Gitleaks:
```bash
sudo apt install gitleaks -y
```

#### Verify Installation
Run:
```bash
subfinder -version
httpx -version
naabu -version
nuclei -version
dnsx -version
katana -version
assetfinder -h
amass -version
gf -h
subzy -h
gau --version
subjs -h
dalfox version
gowitness version
uro --help
```

For detailed installation instructions see [docs/INSTALL_TOOLS.md](docs/INSTALL_TOOLS.md)

### B. Backend setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the Uvicorn ASGI server (bound to 127.0.0.1 only for single-user local security):
   ```bash
   # Live Scan Mode (Recommended during scans to prevent reloader from terminating active scan processes):
   uvicorn app.main:app --host 127.0.0.1 --port 8000

   # Development Mode (Strictly restrict reload watch to app directory, excluding storage/tmp/screenshots):
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir app
   ```
   > **Important Developer Note:**
   > When performing live scans, run Uvicorn **without** `--reload` (e.g. `uvicorn app.main:app`).
   > If running with `--reload`, use `--reload-dir app` to prevent file writes in `backend/storage/`, `tmp`, or `screenshots/` from triggering server reloads. If Uvicorn reloads while a scan is in progress, background child processes are killed and the active scan is marked `interrupted`.

### B. Frontend setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Launch the local development server:
   ```bash
   npm run dev
   ```

---

## 6. Configuration

Configure backend credentials and tool options by copying the template environment configuration:

```bash
cp .env.example .env
```

Customize environment variables in `.env`:
*   `DATABASE_URL`: MongoDB connection string.
*   `SECRET_KEY`/`JWT_SECRET`: JWT encryption keys.
*   `CHAOS_API_KEY`/`PROJECTDISCOVERY_API_KEY`: API credentials for discovery feeds.
*   `WSL_USER`: If running on Windows, configure this to your WSL username (default: `kali`) to allow auto-detection of tool paths.

---

## 7. Scan Model — One Full Scan + Per-Phase Switches

The Fast/Deep selector has been removed. Every scan runs the same full
pipeline; expensive phases are enabled per project from **Project Settings →
Scan Phases**. Each switch is **OFF by default**, shows an estimated cost, and
has a hard time cap (seconds). At the cap the phase's process tree is killed,
partial output is kept, and a `stage_timeout` event is recorded.

**Always-on phases**

Passive discovery, DNS resolution, HTTPX probing, subdomain takeover checks,
Katana, SubJS, JS analysis, URL merge/Uro, GF classification, and a baseline
top-1000 port scan.

**Optional phases** (`phase_switches` on the project document)

| Switch | Default | Time cap default | Estimated cost |
|---|---|---|---|
| `dns_bruteforce` — brute force + permutations | OFF | 600s | High |
| `waymore` — historical archive supplement | OFF | 240s | Medium |
| `ffuf` — content discovery | OFF | 600s | High |
| `param_discovery` — Arjun/x8 | OFF | 300s | Medium |
| `wide_port_scan` — upgrade baseline to `port_range` | OFF | 600s | High |
| `active_scanners` — Nuclei/Dalfox/OpenRedirex | OFF | 900s | Very high |
| `screenshots` — GoWitness | OFF | 300s | Medium |

Active scanners remain governed by `scan_profile`; the default `recon` profile
still skips Nuclei, Dalfox, and OpenRedirex. Time caps are clamped to 1–7200s.

Legacy `scan_mode` values on old jobs and schedules are still accepted and
displayed, but new runs are stored as `scan_mode: "full"`. The scheduler ignores
a legacy schedule mode and launches a full scan.

**Targeted runs**

Run ffuf, Arjun/x8, or a wide port scan on selected hosts only:

```http
POST /api/v1/jobs/project/{project_id}/targeted
Content-Type: application/json

{
  "tool": "ffuf",                // ffuf | arjun | naabu
  "hosts": ["https://app.example.com"],
  "port_range": "1-2000",        // naabu only, optional
  "time_cap_seconds": 600        // optional, clamped 1-7200
}
```

The request is scope-filtered before execution. The run gets its own `job_id`,
applies the project rate limit, has a hard timeout, records `executed_phases`,
`phase_durations` and `run_assets`, saves assets normally, and appears in
**Run History** as a targeted run (`run_kind: "targeted"`).

**Per-phase durations**

Executed phases emit `phase_timing` events; Run History shows each phase's
duration in the run inspection modal. Diffing and run comparison only compare
asset types whose producing phase ran in **both** runs, so a switch left OFF
never produces stale/closed/removed noise.

### Phase 8 optional tools (WSL install commands)

```bash
# JS analysis
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
pipx install xnLinkFinder
go install github.com/denandz/sourcemapper@latest

# Secret scanning (offline, no verification)
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/gitleaks/gitleaks/v8@latest

# Cloud buckets (read-only checks; no content downloads)
git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum
pip install -r ~/tools/cloud_enum/requirements.txt
pipx install s3scanner

# OAST + WordPress validation
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
sudo apt install -y wpscan   # or: sudo gem install wpscan
```

All tools are in the WSL Tool Registry with absolute-path resolution and
`backend/storage/tool_paths_override.json` override support. Full details and
manual tests are in `docs/PHASE8.md`.

---

## 8. Disclaimer

ReconForge is intended solely for authorized security assessment, penetration testing, and educational research. The authors assume no liability for misuse, unauthorized scanning, or damage caused by the application.
