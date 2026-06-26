from app.providers.cert_provider import CertTransparencyProvider
from app.providers.dns_provider import DNSProvider
from app.providers.inventory_provider import InventoryProvider
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.assetfinder_provider import AssetfinderProvider
from app.providers.amass_provider import AmassProvider
from app.providers.chaos_provider import ChaosProvider
from app.providers.unified_discovery_provider import UnifiedDiscoveryProvider
# HTTPX is intentionally NOT registered as a frontend-facing discovery provider.
# It is executed internally as part of the Unified Discovery pipeline.

PROVIDERS = {
    "Subfinder": SubfinderProvider(),
    "Assetfinder": AssetfinderProvider(),
    "Amass": AmassProvider(),
    "Chaos": ChaosProvider(),
    "Unified Discovery": UnifiedDiscoveryProvider(),
}



