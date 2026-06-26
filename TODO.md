# TODO - AmassProvider streaming refactor (ReconForge)

- [x] Update `backend/app/providers/amass_provider.py` to replace `subprocess.run()` with `subprocess.Popen()`.
- [x] Stream `stdout` line-by-line while Amass is running; yield `type: "asset"` events immediately.
- [x] Preserve deduplication via `seen_subdomains`.
- [x] Preserve existing `type: "log"` yields and logging messages as closely as possible.
- [x] Ensure Windows+WSL command structure remains unchanged.
- [x] Wait for process completion via `process.wait()` and check exit code; raise on non-zero.
- [ ] Quick local test commands to validate streaming + runtime.
- [ ] Verify MongoDB compatibility path by ensuring asset event schema remains unchanged.

