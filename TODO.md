# TODO

## Unified Discovery Refactor - Phase 1

- [ ] Inspect current UnifiedDiscoveryProvider implementation and verify it meets Phase 1 requirements (concurrent execution, streaming, error isolation, preserved events).
- [ ] If any requirement is not met, update **only** `backend/app/providers/unified_discovery_provider.py`.
- [ ] Test Phase 1 by launching Unified Discovery job and verifying websocket stream receives `asset` events immediately as providers produce them, while failures don’t cancel other providers.

