# Phase 8 — JS analysis, secrets, cloud buckets, OAST, tech-aware routing

Phase 8 is additive: existing phases, event types and API shapes are unchanged.
Every new tool is optional. When a tool is missing, the pipeline emits a
`stage_skipped` event with `reason: "tool_missing: <name>"` and continues.

## New pipeline sub-phases

| Sub-phase | Where | Runs | Tools (all optional) |
|---|---|---|---|
| JS analysis + hashing + source maps | Phase 6B (replaces LinkFinder) | Every full scan | jsluice → xnLinkFinder → LinkFinder fallback, sourcemapper |
| Secret scanning | After historical URL probing (7C) | Every full scan (config-gated) | trufflehog (preferred, no verification), gitleaks |
| Cloud bucket enumeration | After root expansion (2B) | Opt-in only (project config) | cloud_enum, S3Scanner |
| OAST | Phase 9A | `recon_validation` + opt-in | interactsh-client |
| Tech-aware routing | Phase 9B | `recon_validation` + active-scanner switch (WPScan: `recon_validation`) | Nuclei tech tags, `-as`, WPScan |
| Burp/ZAP export | API/UI | n/a | none |

## New asset types (additive)

- `secret_finding` — secret type, URL + line location, masked preview (first 4
  characters only), value hash and a stable identity key
  (`type + location + value hash`). Raw values are never stored or verified.
- `bucket` — bucket URL/name, provider, public flag, in-scope keyword and
  `read_only: true`. No bucket contents are downloaded.
- `recon_info` — info-level Nuclei matches; never scored as vulnerabilities.

`js_file` metadata includes `hash`/`sha256`, `previous_hash`, `body_path`,
`size`, `kind` (`js` or `sourcemap`) and `parent_js`. JS bodies are stored under
`backend/storage/js/{project_id}/{sha256}.js`; source mapper stores only the
recovered file list at
`backend/storage/js/{project_id}/sourcemap_recovered_files.json`. `scan_diffs`
now includes `modified_js_files` (same URL, changed SHA-256),
`new_secret_findings`, `new_buckets`, `new_recon_info` and their summary counts.

## Per-project configuration

Defaults live in `backend/app/config/phase8_defaults.json`; per-project values
are stored on the project document and remain backward compatible.

```json
{
  "js_analysis": {"enabled": true, "max_files_fast": 25, "max_files_deep": 100,
                   "max_file_kb": 500, "timeout_seconds": 15,
                   "sourcemaps_deep_only": true, "sourcemap_max_files": 10},
  "secrets_scan": {"enabled": true, "max_files": 500, "timeout_seconds": 180},
  "cloud_enum": {"enabled": false, "max_keywords": 10, "timeout_seconds": 180},
  "oast": {"enabled": false, "server": "", "token": "", "startup_timeout_seconds": 20},
  "nuclei_options": {"auto_scan": false, "update_templates": false,
                      "custom_templates_dir": ""},
  "tech_routing": {"enabled": true, "max_hosts_per_tech": 25},
  "exports": {"max_urls": 50000}
}
```

UI: **Project Configuration → Phase 8** exposes OAST, Nuclei and cloud settings.
The inventory adds **Secrets**, **Buckets** and **Recon Info** tabs plus
**Export URLs** / **Burp XML** buttons. What's New shows new/changed JS,
secrets, buckets and recon info. Run History filters include the Phase 8 asset
types.

Cloud bucket enumeration is enabled only by the project config (`enabled: true`)
and is no longer tied to the removed Deep mode. Nuclei always runs with `-as`
and retains info-level results as `recon_info`. WPScan only runs in the
`recon_validation` profile. Teardown/exploitation tools are not invoked.

## WSL tool installation (Ubuntu/Kali)

```bash
# JS analysis
go install github.com/BishopFox/jsluice/cmd/jsluice@latest
pipx install xnLinkFinder
go install github.com/denandz/sourcemapper@latest

# Secrets
go install github.com/trufflesecurity/trufflehog/v3@latest
go install github.com/gitleaks/gitleaks/v8@latest

# Cloud buckets
git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum
pip install -r ~/tools/cloud_enum/requirements.txt
pipx install s3scanner

# OAST + tech routing
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
sudo apt install -y wpscan   # or: sudo gem install wpscan

# Refresh the registry shown in Project Settings → WSL Tool Registry
# (button: Refresh, or GET /api/v1/system/tools?refresh=true)
```

## Manual testing

1. Start backend and frontend as usual; open **Project Configuration → Phase 8**,
   enable OAST (optionally set a self-hosted server/token) and set scan profile
   `recon_validation`.
2. Launch a full scan. In the console look for:
   - `JS Analysis` hashing lines, the count/first 500 chars of skipped JS
     reasons (scope, file/size cap, download error), and, when jsluice/
     xnLinkFinder is installed, extracted endpoints. JS bodies should be under
     `backend/storage/js/{project_id}/` keyed by SHA-256.
   - `Secret Scanning` summary; **Asset Inventory → Secrets** shows only masked
     previews (`AKIA****`), never raw values, plus URL + line locations.
   - With OAST enabled and `recon_validation`: `OAST active: callback domain …`,
     Nuclei `-iserver`, and Dalfox `-b`. Callbacks show correlated host and
     request path.
   - Tech-aware routing summaries for Jenkins/Grafana/Kibana/Tomcat/phpMyAdmin/
     WordPress/GraphQL/Swagger; WPScan only in `recon_validation` (if installed).
   - Nuclei always uses `-as`; info-level matches appear as **Recon Info** and
     are not counted as findings.
3. Enable cloud enumeration in project config and re-run; detected candidates
   appear under **Buckets**, are limited to in-scope seed keywords, and show
   `read_only: true`. Confirm no bucket contents are downloaded.
4. Open **Asset Inventory** and click **Export URLs** / **Burp XML**; confirm
   scope filtering, hunt-priority ordering and query-token redaction.
5. Run the **What's New** tab after two scans and check Modified JS, New Secrets,
   New Buckets and Recon Info sections. Run History filters should include
   `secret_finding`, `bucket` and `recon_info`.

## Automated tests

```bash
cd /mnt/c/Users/rafey/Desktop/RC_copy/ReconForge
./backend/.venv/Scripts/python.exe -m pytest backend/tests/test_phase8_features.py -q
./backend/.venv/Scripts/python.exe -m pytest -q   # full suite
cd frontend && npx tsc -b
```
