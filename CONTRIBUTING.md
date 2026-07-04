# Contributing to ReconForge

We welcome contributions from the security research and development community. To maintain codebase stability, readability, and compatibility, please follow these guidelines when adding features or fixing bugs.

---

## Coding Style & Standards

### Backend (Python/FastAPI)
*   **PEP 8 Compliance**: Follow standard Python conventions.
*   **Type Hinting**: Use explicit type annotations for function signatures and properties.
*   **Async Generators**: Implement discovery providers using async generators (`AsyncGenerator[Dict[str, Any], None]`) to support real-time logging and WS stream relays.

### Frontend (React/TypeScript)
*   **Modern React**: Use hooks, functional components, and TypeScript interfaces.
*   **Aesthetics**: Follow the dark mode/glassmorphism theme. Avoid inline styles; use clean Tailwind classes or central vanilla CSS classes.
*   **State Updates**: Ensure telemetry states match existing interfaces in `ScanState`.

---

## Adding New Discovery or Validation Providers

To extend the pipeline with a new tool:

### 1. Implement the Provider Interface
Create a new file under `backend/app/providers/` subclassing `BaseProvider` from `app.providers.base`:

```python
from typing import AsyncGenerator, Dict, Any, List
from app.providers.base import BaseProvider

class CustomToolProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "custom_tool"

    @property
    def description(self) -> str:
        return "A description of what the custom tool does."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        # 1. Detect executable path using base helper
        tool_path = self.detect_tool("custom_tool")
        
        # 2. Check for empty inputs and exit early with skipped status
        if not seed_domains:
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "completed",
                "count": 0,
                "skipped_reason": "no_live_hosts_upstream"
            }
            return
            
        # 3. Yield logs or parsed output assets
        yield {"type": "log", "message": "Launching Custom Tool..."}
        # Execute tool via subprocess and parse results...
        
        # 4. Yield final completion status
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "status": "completed",
            "count": result_count
        }
```

### 2. Connect to Unified Discovery
Register your provider class inside `backend/app/providers/__init__.py` and include it in `unified_discovery_provider.py` inside the appropriate execution pass phase.

### 3. Update Frontend telemetry
Add the provider status card under `providerBreakdown` in `OverviewDashboard.tsx` and configure default state mappings in `initialScanState` inside `App.tsx`.
