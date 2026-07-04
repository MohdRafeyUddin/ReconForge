# Customizing Nuclei Scanner Templates

ReconForge supports executing custom Nuclei template checks alongside or in place of default templates. This guide details how to configure custom template directories and manage scanning flags.

---

## 1. Directory Setup

Create a local directory to host your custom `.yaml` Nuclei templates:

```bash
mkdir -p nuclei-custom-templates
```

Copy your custom vulnerability, configuration, or custom signature templates into this folder.

---

## 2. Configuration via Environment Variables

To register your custom template directory, modify the environment variables in your `.env` file (or duplicate `.env.example` as `.env`):

```bash
# Path to your custom template folder inside WSL or local filesystem
NUCLEI_CUSTOM_TEMPLATES_DIR=/absolute/path/to/reconforge/nuclei-custom-templates

# Set to false to ONLY run your custom templates (skipping default ProjectDiscovery signatures)
NUCLEI_INCLUDE_DEFAULT_TEMPLATES=true
```

---

## 3. How the Backend Processes Templates

The Nuclei provider (`nuclei_provider.py`) reads these environment values during execution:
*   If `NUCLEI_CUSTOM_TEMPLATES_DIR` is set, the path is passed to the `-t` or `-templates` flag.
*   If `NUCLEI_INCLUDE_DEFAULT_TEMPLATES` is `true`, it appends default tags (e.g. `cve,rce,tech,exposure`) to execute standard signatures along with your folder templates.
*   If `NUCLEI_INCLUDE_DEFAULT_TEMPLATES` is `false`, it restricts the scan context entirely to templates stored in your custom directory.

---

## 4. Example Template (XSS Check)

Create a sample file under `nuclei-custom-templates/xss-check.yaml`:

```yaml
id: custom-parameter-xss

info:
  name: Custom Parameter Reflection XSS
  author: security-researcher
  severity: medium
  description: Checks if the input parameter reflections are unescaped.

http:
  - method: GET
    path:
      - "{{BaseURL}}/?q=<script>alert(1)</script>"

    matchers-condition: and
    matchers:
      - type: word
        words:
          - "<script>alert(1)</script>"

      - type: status
        status:
          - 200
```
