# ReconForge Release Preparation Checklist

Before publishing the ReconForge repository to a public GitHub repository, complete the following audit checklist to ensure no sensitive files or environment residue is committed:

- [ ] **No API Keys Committed**: Audit git diffs to ensure no ProjectDiscovery, Chaos, or OpenAI keys are hardcoded.
- [ ] **.env Removed**: Ensure `.env` is omitted and only `.env.example` is committed.
- [ ] **node_modules Excluded**: Verify `node_modules` folders in `frontend/` are matched by `.gitignore` and removed from git cache.
- [ ] **venv Excluded**: Verify virtual environment folders (`venv/`, `.venv/`) are not tracked.
- [ ] **Screenshots Cleaned**: Delete any temporary scan images under `backend/screenshots/` and report exports under `backend/reports/`.
- [ ] **Test Scan Completed**: Manually trigger a Fast Scan and Deep Scan on `testphp.vulnweb.com` or local lab to verify that telemetry, WebSocket status events, and database storage run correctly.
- [ ] **README Updated**: Ensure installation dependencies and WSL setup commands match current version details.
