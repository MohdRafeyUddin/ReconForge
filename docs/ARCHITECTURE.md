# ReconForge ASM Platform — Architecture & Pipeline Design

This document details the software architecture, pipeline sequence, and component responsibilities of the ReconForge Attack Surface Management (ASM) platform.

---

## System Workflow & Data Flow Pipeline

ReconForge uses a structured, sequential pipeline with gating boundaries. The flow of data moves as follows:

```
    +------------------------------------------+
    |               Input Handler              |
    |  Accepts domain / IP / URL / HOST:PORT   |
    +------------------------------------------+
                         |
                         v
    +------------------------------------------+
    |             Target Detection             |
    |      Resolves scope parameters & inputs   |
    +------------------------------------------+
                         |
                         v
    +------------------------------------------+
    |            Provider Execution            |
    |  Orchestrates Phase-based tool execution  |
    +------------------------------------------+
                         |
                         v
    +------------------------------------------+
    |           MongoDB Persistence            |
    |   Stores subdomains, URLs, screenshots,  |
    |    and findings flat-collection assets   |
    +------------------------------------------+
                         |
                         v
    +------------------------------------------+
    |            WebSocket Updates             |
    |  Broadcasts live scanner state/logs/stats|
    +------------------------------------------+
                         |
                         v
    +------------------------------------------+
    |             React Dashboard              |
    |   Renders active scan, telemetry, risk   |
    |    scoring breakdowns, and asset tables  |
    +------------------------------------------+
```

---

## Gated Pipeline Stages & Execution Order

ReconForge executes automated workflows in distinct sequential passes. Stage gating ensures that dead or unresolvable targets are filtered out early:

```
[Phase 1: Discovery] -> [Phase 2: DNSx Gating] -> [Phase 3: Naabu Port Gating] -> [Phase 4: HTTPX Web Probing]
                                                                                        |
  +-------------------------------------------------------------------------------------+
  v
[Phase 5: GAU / Crawlers] -> [Phase 6: Uro normalization] -> [Phase 7: GF Classifier] -> [Phase 8: Vulnerability (Nuclei/Dalfox)]
                                                                                        |
  +-------------------------------------------------------------------------------------+
  v
[Phase 9: Post-Processing Risk Engine]
```

### Explicit Dead-Host Gating Logic
*   **DNSx resolver pass**: Compares input count (`hosts_in`) to successfully resolved count (`hosts_resolved`). Subdomains with no DNS resolution (`hosts_dead`) are gated and excluded from downstream execution.
*   **Naabu port-scanner pass**: Excludes subdomains with closed ports (`hosts_no_ports`).
*   **HTTPX live-probing pass**: Excludes dead HTTP services. If no live targets remain (`hosts_live == 0`), a `PipelineHalted` event is generated, skipping all downstream steps (Katana, GAU, SubJS, GoWitness, GF, Nuclei, Dalfox, etc.) and updating dashboard cards to show `"Skipped — no live hosts"`.

---

## Provider Responsibilities

### 1. Discovery Layer
*   **Subfinder**: Passive subdomain scraping querying multiple external feeds.
*   **Assetfinder**: Searches host directories and domain indexes.
*   **Chaos**: Queries ProjectDiscovery's Chaos dataset for historical subdomains.
*   **Amass**: Advanced passive asset mapping.

### 2. Resolution & Filtering
*   **DNSx**: Resolves CNAME, A, and AAAA records, deduplicating wildcards.
*   **Subzy**: Scans active subdomains for vulnerable DNS configurations (e.g. CNAME takeovers).
*   **Naabu**: Scans for common open ports (e.g., HTTP, database, admin panel ports).
*   **HTTPX**: Performs web probing, extracting status codes, page titles, and web servers.

### 3. Crawling & Spidering
*   **Katana**: Fast web crawling and automatic form extraction.
*   **GAU (Get All URLs)**: Fetches historical URL indexes from Wayback Machine, Common Crawl, and AlienVault OTX.
*   **SubJS**: Discovers and extracts JavaScript file locations.

### 4. URL Processing & Classification
*   **Uro**: Normalizes URLs, strips redundant parameters, and filters static resource types.
*   **GF**: Classifies normalized URLs into vulnerability categories (e.g., SQLi, XSS, SSRF, LFI, Redirect) using grep-pattern matching.

### 5. Vulnerability & Exposure Checks
*   **Nuclei**: Multi-pass template scanner checking for exposures (`HostExposure` pass) and bug classes (`EndpointBugClass`/`EndpointCritical` passes).
*   **Dalfox**: Active parameter verification for Cross-Site Scripting (XSS).
*   **OpenRedirex**: Validates open redirects against parameterized parameters.
*   **GoWitness**: Captures screenshots of live HTTP endpoints for visual verification.

---

## Risk Scoring Post-Processing Engine

Upon pipeline completion, the **Risk Scoring Engine** reads the project inventory and calculates a normalized `0-100` risk score for each asset based on weights defined in `config/risk_weights.json`. It computes:
1.  **Vulnerability Severity Weight**: Sums CVSS severity counts (Critical: 40, High: 25, Medium: 10, Low: 5).
2.  **Asset Importance / Sensitivity**: Increments for databases, administrative panels, or sensitive files.
3.  **Internet Exposure Factors**: Outdated tech, missing SSL/HTTPS, or open databases.
4.  **Priority Ranking**: Provides security teams with a prioritized remediation list.
