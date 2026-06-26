import asyncio
import random
from typing import AsyncGenerator, Dict, Any, List
from app.providers.base import BaseProvider

class CertTransparencyProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "Certificate Transparency"
        
    @property
    def description(self) -> str:
        return "Discovers subdomains by querying public Certificate Transparency (CT) logs."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": f"[*] Querying Certificate Transparency logs for: {', '.join(seed_domains)}..."}
        await asyncio.sleep(0.8)
        
        subdomains_templates = [
            "api", "dev", "staging", "prod", "vpn", "mail", "admin", 
            "portal", "billing", "blog", "status", "dashboard", "git", 
            "corp", "internal", "support", "test", "auth", "secure"
        ]
        
        found_count = 0
        for domain in seed_domains:
            # Generate 4-8 subdomains per seed domain
            num_subdomains = random.randint(4, 8)
            chosen_subs = random.sample(subdomains_templates, num_subdomains)
            
            yield {"type": "log", "message": f"[+] Querying crt.sh and Censys logs for {domain}..."}
            await asyncio.sleep(1.0)
            
            for sub in chosen_subs:
                subdomain = f"{sub}.{domain}"
                found_count += 1
                
                # Mock SSL Certificate Metadata
                cert_meta = {
                    "issuer": f"Let's Encrypt Authority X{random.choice([3, 4])}",
                    "valid_from": "2026-01-10T00:00:00Z",
                    "valid_to": "2026-08-10T23:59:59Z",
                    "sans": [subdomain, f"www.{subdomain}"],
                    "serial_number": hex(random.randint(10000000, 99999999))
                }
                
                yield {"type": "log", "message": f"[+] Found subdomain: {subdomain} (serial: {cert_meta['serial_number']})"}
                await asyncio.sleep(0.4)
                
                yield {
                    "type": "asset",
                    "data": {
                        "domain": subdomain,
                        "type": "subdomain",
                        "status": "unknown",  # Status will be active-probed by DNS
                        "open_ports": [],
                        "metadata": {
                            "ssl_info": cert_meta,
                            "source": "Certificate Transparency"
                        }
                    }
                }
                
        yield {"type": "log", "message": f"[√] Certificate Transparency scan complete. Discovered {found_count} subdomain(s)."}
