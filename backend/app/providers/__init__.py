# ---------------------------------------------------------------------------
# ReconForge Provider Registry
# ---------------------------------------------------------------------------
# Only providers listed in PROVIDERS are exposed to the frontend scan launcher.
# Internal pipeline providers (DNSx, Subzy, Naabu, HTTPX, Katana, Uro, GF,
# Nuclei) are called exclusively by UnifiedDiscoveryProvider and must NOT be
# added to this dict.
# ---------------------------------------------------------------------------

from app.providers.cert_provider import CertTransparencyProvider
from app.providers.dns_provider import DNSProvider
from app.providers.inventory_provider import InventoryProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.amass_provider import AmassProvider
from app.providers.chaos_provider import ChaosProvider
from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider

# Internal providers – imported here for discoverability; not registered.
from app.providers.dnsx_provider import DnsxProvider       # noqa: F401
from app.providers.subzy_provider import SubzyProvider     # noqa: F401
from app.providers.uro_provider import UroProvider         # noqa: F401
from app.providers.gf_provider import GfProvider           # noqa: F401

PROVIDERS = {
    "Subfinder":        SubfinderProvider(),
    "Assetfinder":      AssetfinderProvider(),
    "Amass":            AmassProvider(),
    "Chaos":            ChaosProvider(),
    "Unified Discovery": UnifiedDiscoveryProvider(),
}


# ---------------------------------------------------------------------------
# WebSocket event-type registry  (Step 7)
# ---------------------------------------------------------------------------
# All event types that may be broadcast over the WebSocket channel.
# Add new types here when introducing new providers — the frontend can
# subscribe to them without changes to the WebSocket manager.

WS_EVENT_TYPES = {
    # Existing events (backward-compatible)
    "log":          "Generic log message from any provider stage.",
    "asset":        "Discovered or enriched asset (subdomain, live host, etc.).",
    "scan_summary": "End-of-phase summary emitted by each provider.",
    "status":       "Job lifecycle transition (running / completed / failed / stopped).",
    "provider_stat":"Per-provider subdomain count emitted after Phase 1.",

    # New structured event types (Step 7)
    "asset_event":    "Richer asset event carrying resolved_ip and dns metadata.",
    "dns_event":      "Raw DNS record event (A / AAAA / CNAME) from DnsxProvider.",
    "takeover_event": "Subdomain takeover finding from SubzyProvider.",
    "port_event":     "Open port discovered by NaabuProvider.",
    "host_event":     "Live HTTP/HTTPS host confirmed by HttpxProvider.",
    "url_event":      "Normalised URL emitted by UroProvider.",
    "gf_event":       "URL classification result emitted by GfProvider.",
    "finding_event":  "Vulnerability finding emitted by NucleiProvider.",
}


# ---------------------------------------------------------------------------
# MongoDB collection declarations  (Step 6)
# ---------------------------------------------------------------------------
# Logical collection names used across the platform.
# These are reference constants — the actual Motor/PyMongo collections are
# obtained via get_database().<collection>.  No migration is performed here.

MONGO_COLLECTIONS = {
    "assets":     "Discovered subdomains, live hosts, and enriched asset records.",
    "ports":      "Open port records associated with a live host (future dedicated collection).",
    "urls":       "Crawled and Uro-normalised URLs associated with a job.",
    "findings":   "Nuclei vulnerability and exposure findings.",
    "takeovers":  "Subzy subdomain takeover results.",
    "technology": "Technologies detected by HTTPX and Nuclei (future dedicated collection).",
}


# ---------------------------------------------------------------------------
# Future provider stubs  (Step 9)
# ---------------------------------------------------------------------------
# The providers below are NOT yet implemented.  Their class names are reserved
# so they can be imported and wired into UnifiedDiscoveryProvider._run_phase()
# without touching any other file.
#
# To add a future provider:
#   1. Create backend/app/providers/<name>_provider.py
#   2. Implement the BaseProvider interface (name, description, discover)
#   3. Import the class here (optional registration in PROVIDERS if standalone)
#   4. Add a phase call in unified_discovery_provider.py
#
# Reserved names:
#   WaybackUrlsProvider    – historical URL harvesting via Wayback Machine
#   GauProvider            – GetAllUrls aggregator
#   GoWitnessProvider      – HTTP screenshot capture
#   LinkFinderProvider     – JS endpoint extraction
#   SecretFinderProvider   – secret/key detection in JS files
#   AsnDiscoveryProvider   – ASN and IP range enumeration
#   CloudEnumProvider      – cloud asset discovery (S3, GCS, Azure)
