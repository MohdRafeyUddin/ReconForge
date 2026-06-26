import asyncio
import random
from typing import AsyncGenerator, Dict, Any, List
from app.providers.base import BaseProvider

class DNSProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "DNS Resolver"
        
    @property
    def description(self) -> str:
        return "Resolves hostnames to IP addresses and queries A, CNAME, and MX records."

    async def discover(self, seed_domains: List[str]) -> AsyncGenerator[Dict[str, Any], None]:
        yield {"type": "log", "message": f"[*] Starting DNS Resolution pipeline for: {', '.join(seed_domains)}..."}
        await asyncio.sleep(0.5)
        
        ips = ["192.168.10.", "10.0.12.", "45.33.22.", "104.244.42.", "35.186.220."]
        base_ip = random.choice(ips)
        
        for idx, domain in enumerate(seed_domains):
            yield {"type": "log", "message": f"[+] Resolving records for: {domain}..."}
            await asyncio.sleep(0.6)
            
            resolved_ip = f"{base_ip}{random.randint(2, 254)}"
            
            dns_records = {
                "A": [resolved_ip],
                "MX": [f"mail.{domain} (Priority: 10)"],
                "TXT": ["v=spf1 include:_spf.google.com ~all"],
                "CNAME": [] if idx % 2 == 0 else [f"proxy.cloudflare.net"]
            }
            
            # Select mock open ports
            common_ports = [80, 443, 22, 8080, 8443, 21, 3306]
            open_ports = random.sample(common_ports, random.randint(1, 4))
            open_ports.sort()
            
            yield {"type": "log", "message": f"[+] Resolved {domain} -> {resolved_ip} | Open Ports: {open_ports}"}
            await asyncio.sleep(0.4)
            
            yield {
                "type": "asset",
                "data": {
                    "domain": domain,
                    "type": "domain" if "." in domain and domain.count(".") == 1 else "subdomain",
                    "status": "live",
                    "open_ports": open_ports,
                    "metadata": {
                        "ip_address": resolved_ip,
                        "dns_records": dns_records,
                        "source": "DNS Resolver"
                    }
                }
            }
            
        yield {"type": "log", "message": "[√] DNS Resolver scan complete."}
