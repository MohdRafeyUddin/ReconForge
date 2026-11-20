"""API Surface & GraphQL Detection Provider
==========================================
Probes common API specification routes and GraphQL endpoints on priority hosts:
  - Common spec paths: /swagger.json, /openapi.json, /v2/api-docs, /api-docs, /api/swagger.json, /api/openapi.json
  - Discovered OpenAPI/Swagger specifications are parsed to extract individual routes/endpoints
    and merged into the URL pipeline.
  - GraphQL endpoints (/graphql, /graphiql) are flagged with tags and probed with a single
    READ-ONLY introspection query: {"query": "{__schema{types{name}}}"} (no mutations).
  - Common discovery paths: /.well-known/openid-configuration, /.well-known/security.txt
  - Every discovered URL passes is_in_scope before emission.
"""

import asyncio
import json
import logging
import time
from typing import Any, AsyncGenerator, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from app.core.scope import is_in_scope
from app.providers.base import BaseProvider

logger = logging.getLogger("reconforge.providers.api_surface")

COMMON_API_SPEC_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
    "/api/v1/swagger.json",
]

COMMON_GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/v1/graphql",
]

COMMON_WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/security.txt",
    "/.well-known/assetlinks.json",
]

# Strictly read-only GraphQL query to safely verify schema introspection
GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{types{name}}}"}


class ApiSurfaceProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "api_surface"

    @property
    def description(self) -> str:
        return "Probes API documentation specifications (OpenAPI/Swagger) and tests read-only GraphQL introspection."

    @classmethod
    def extract_spec_endpoints(
        cls,
        spec_data: Dict[str, Any],
        base_url: str,
        scope: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Builds endpoint URLs ONLY against the host where the spec was found (base_url).
        Ignores 'servers' entries pointing at other hosts.
        Runs every extracted URL through is_in_scope before returning.
        """
        parsed_base = urlparse(base_url)
        spec_host = parsed_base.netloc.lower()

        # Check servers (OpenAPI 3.x)
        server_prefixes = [""]
        raw_servers = spec_data.get("servers")
        if isinstance(raw_servers, list):
            valid_prefixes = []
            for s in raw_servers:
                if not isinstance(s, dict):
                    continue
                srv_url = str(s.get("url") or "").strip()
                if not srv_url:
                    continue
                parsed_srv = urlparse(srv_url)
                # If server entry specifies a different host, ignore it!
                if parsed_srv.netloc and parsed_srv.netloc.lower() != spec_host:
                    logger.debug("[api_surface] Ignoring out-of-scope/other-host servers entry: %s", srv_url)
                    continue
                # If relative or on the same host, take path prefix
                pfx = parsed_srv.path.rstrip("/")
                if pfx and pfx not in valid_prefixes:
                    valid_prefixes.append(pfx)
            if valid_prefixes:
                server_prefixes = valid_prefixes

        # Check basePath (Swagger 2.0)
        base_path = str(spec_data.get("basePath") or "").strip().rstrip("/")
        if base_path and base_path != "/":
            new_prefixes = []
            for pfx in server_prefixes:
                combined = f"{pfx}{base_path}".rstrip("/")
                if combined not in new_prefixes:
                    new_prefixes.append(combined)
            server_prefixes = new_prefixes or [""]

        paths_dict = spec_data.get("paths") or {}
        if not isinstance(paths_dict, dict):
            return []

        endpoints: List[str] = []
        for path in paths_dict.keys():
            if not isinstance(path, str):
                continue
            clean_path = path.lstrip("/")
            for pfx in server_prefixes:
                pfx_clean = pfx.lstrip("/")
                if pfx_clean:
                    full_path = f"/{pfx_clean}/{clean_path}"
                else:
                    full_path = f"/{clean_path}"
                endpoint_url = urljoin(base_url.rstrip("/") + "/", full_path.lstrip("/"))
                if endpoint_url not in endpoints:
                    if is_in_scope(endpoint_url, scope):
                        endpoints.append(endpoint_url)

        return endpoints

    @classmethod
    def build_graphql_probe_request(
        cls,
        gql_url: str,
        custom_headers: Optional[Dict[str, str]] = None,
        rate_limit: int = 10,
    ) -> Dict[str, Any]:
        """
        Builds the GraphQL introspection probe request with headers,
        read-only query payload, and calculated delay.
        """
        headers = {
            "User-Agent": "ReconForge-APISurface/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if custom_headers:
            headers.update(custom_headers)

        delay_seconds = 1.0 / max(rate_limit, 1) if rate_limit > 0 else 0.0
        return {
            "url": gql_url,
            "method": "POST",
            "headers": headers,
            "json": GRAPHQL_INTROSPECTION_QUERY,
            "rate_limit": rate_limit,
            "delay_seconds": delay_seconds,
        }

    async def discover(self, seed_domains: List[str], **kwargs: Any) -> AsyncGenerator[Dict[str, Any], None]:
        async for event in self.probe_api_surface(seed_domains, **kwargs):
            yield event

    async def probe_api_surface(
        self,
        targets: List[str],
        rate_limit: int = 10,
        custom_headers: Optional[Dict[str, str]] = None,
        scope: Optional[Dict[str, List[str]]] = None,
        timeout: float = 8.0,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Probes target hosts for API specs and GraphQL endpoints.
        Yields logs, assets (api_spec, graphql_endpoint, content_path), and url_events.
        """
        if not targets:
            yield {
                "type": "scan_summary",
                "provider": self.name,
                "status": "SKIPPED",
                "count": 0,
            }
            return

        headers = {
            "User-Agent": "ReconForge-APISurface/1.0",
            "Accept": "application/json, text/plain, */*",
        }
        if custom_headers:
            headers.update(custom_headers)

        yield {
            "type": "log",
            "message": f"\n========== API Surface & GraphQL Probing ==========\n"
                       f"[*] Probing API specs and GraphQL on {len(targets)} priority hosts (Rate limit: {rate_limit}/s)...",
        }

        start_ts = time.time()
        specs_found = 0
        graphql_found = 0
        endpoints_extracted = 0
        req_delay = 1.0 / max(rate_limit, 1) if rate_limit > 0 else 0.0

        limits = httpx.Limits(max_keepalive_connections=10, max_connections=20)
        async with httpx.AsyncClient(headers=headers, timeout=timeout, limits=limits, verify=False) as client:
            for base_url in targets:
                base_url = base_url.strip().rstrip("/")
                if not base_url:
                    continue

                parsed = urlparse(base_url)
                host = parsed.netloc.lower() or parsed.path.split("/")[0].lower()
                if ":" in host:
                    host = host.split(":")[0]

                if not is_in_scope(base_url, scope):
                    continue

                # 1. Probe OpenAPI / Swagger Specification Paths
                for path in COMMON_API_SPEC_PATHS:
                    spec_url = urljoin(base_url + "/", path.lstrip("/"))
                    if not is_in_scope(spec_url, scope):
                        continue

                    try:
                        if req_delay > 0:
                            await asyncio.sleep(req_delay)
                        resp = await client.get(spec_url)
                        if resp.status_code == 200:
                            content_type = resp.headers.get("content-type", "").lower()
                            raw_text = resp.text.strip()

                            # Verify if it looks like an API documentation specification
                            is_spec = False
                            spec_data = {}
                            if "application/json" in content_type or raw_text.startswith("{"):
                                try:
                                    spec_data = json.loads(raw_text)
                                    if any(k in spec_data for k in ("swagger", "openapi", "paths")):
                                        is_spec = True
                                except Exception:
                                    pass

                            if is_spec:
                                specs_found += 1
                                # Extract endpoint URLs mounted strictly on base_url, ignoring other-host servers
                                extracted_endpoints = self.extract_spec_endpoints(spec_data, base_url, scope)
                                spec_title = (spec_data.get("info") or {}).get("title", "API Specification")
                                spec_version = spec_data.get("openapi") or spec_data.get("swagger") or "unknown"

                                yield {
                                    "type": "log",
                                    "message": f"[+] Discovered API Spec ({spec_version}): {spec_url} "
                                               f"({len(extracted_endpoints)} routes documented: '{spec_title}')",
                                }

                                yield {
                                    "type": "asset",
                                    "data": {
                                        "domain": host,
                                        "type": "api_spec",
                                        "value": spec_url,
                                        "status": "live",
                                        "status_code": 200,
                                        "metadata": {
                                            "url": spec_url,
                                            "host": host,
                                            "spec_type": f"OpenAPI/{spec_version}",
                                            "title": spec_title,
                                            "endpoints_count": len(extracted_endpoints),
                                            "routes": extracted_endpoints[:100],
                                            "source": "api_surface",
                                        },
                                        "discovered_by": self.name,
                                        "sources": ["api_surface"],
                                    },
                                }

                                yield {
                                    "type": "api_spec_event",
                                    "data": {
                                        "host": host,
                                        "spec_url": spec_url,
                                        "spec_type": f"OpenAPI/{spec_version}",
                                        "endpoints_count": len(extracted_endpoints),
                                        "routes": extracted_endpoints[:100],
                                    },
                                }

                                # Emit extracted routes into the URL pipeline
                                for route_url in extracted_endpoints:
                                    if is_in_scope(route_url, scope):
                                        endpoints_extracted += 1
                                        yield {
                                            "type": "url_event",
                                            "data": {
                                                "url": route_url,
                                                "original_url": route_url,
                                                "source": "api_spec",
                                                "sources": ["api_spec"],
                                            },
                                        }

                                # Found a valid spec on this host, move on from redundant spec probes
                                break
                    except Exception as e:
                        logger.debug("[api_surface] Error checking %s: %s", spec_url, e)

                # 2. Probe GraphQL Endpoints & Test Introspection
                for gql_path in COMMON_GRAPHQL_PATHS:
                    gql_url = urljoin(base_url + "/", gql_path.lstrip("/"))
                    if not is_in_scope(gql_url, scope):
                        continue

                    try:
                        if req_delay > 0:
                            await asyncio.sleep(req_delay)
                        # Probe with read-only GET or OPTIONS
                        resp = await client.get(gql_url)
                        is_graphql = False
                        if resp.status_code in (200, 400, 405):
                            body_lower = resp.text.lower()
                            if any(k in body_lower for k in ("graphql", "query", "must provide query string", "syntax error")):
                                is_graphql = True
                            elif "application/json" in resp.headers.get("content-type", "").lower() and "errors" in body_lower:
                                is_graphql = True

                        if is_graphql or resp.status_code == 200:
                            # Build structured probe request with rate limit and custom headers
                            probe_req = self.build_graphql_probe_request(
                                gql_url,
                                custom_headers=custom_headers,
                                rate_limit=rate_limit,
                            )
                            # Log with redacted sensitive headers
                            hdr_summary = ", ".join(
                                f"{k}: [REDACTED]" if k.lower() in ("authorization", "cookie", "x-api-key") else f"{k}: {v}"
                                for k, v in probe_req["headers"].items()
                                if k not in ("User-Agent", "Content-Type", "Accept")
                            )
                            yield {
                                "type": "log",
                                "message": f"[*] Probing GraphQL introspection on {gql_url} (headers: {hdr_summary or 'default'})...",
                            }

                            if req_delay > 0:
                                await asyncio.sleep(req_delay)

                            # Verify with strictly read-only GraphQL Introspection check
                            intro_resp = await client.post(
                                gql_url,
                                json=probe_req["json"],
                                headers=probe_req["headers"],
                            )

                            introspection_enabled = False
                            types_count = 0
                            if intro_resp.status_code == 200:
                                try:
                                    data = intro_resp.json()
                                    schema_data = (data.get("data") or {}).get("__schema")
                                    if schema_data and "types" in schema_data:
                                        introspection_enabled = True
                                        types_count = len(schema_data["types"])
                                except Exception:
                                    pass

                            graphql_found += 1
                            log_msg = (
                                f"[+] GraphQL Endpoint Found: {gql_url} "
                                f"[Introspection: {'ENABLED (' + str(types_count) + ' types)' if introspection_enabled else 'DISABLED'}]"
                            )
                            yield {"type": "log", "message": log_msg}

                            yield {
                                "type": "asset",
                                "data": {
                                    "domain": host,
                                    "type": "graphql_endpoint",
                                    "value": gql_url,
                                    "status": "live",
                                    "status_code": intro_resp.status_code,
                                    "metadata": {
                                        "url": gql_url,
                                        "host": host,
                                        "status_code": intro_resp.status_code,
                                        "introspection_enabled": introspection_enabled,
                                        "types_count": types_count,
                                        "tag": "graphql_endpoint",
                                        "source": "api_surface",
                                    },
                                    "discovered_by": self.name,
                                    "sources": ["api_surface"],
                                },
                            }

                            yield {
                                "type": "graphql_event",
                                "data": {
                                    "host": host,
                                    "url": gql_url,
                                    "introspection_enabled": introspection_enabled,
                                    "types_count": types_count,
                                },
                            }
                            # Once identified, proceed to next category
                            break
                    except Exception as e:
                        logger.debug("[api_surface] GraphQL check error on %s: %s", gql_url, e)

                # 3. Probe .well-known Paths
                for wk_path in COMMON_WELL_KNOWN_PATHS:
                    wk_url = urljoin(base_url + "/", wk_path.lstrip("/"))
                    if not is_in_scope(wk_url, scope):
                        continue

                    try:
                        resp = await client.get(wk_url)
                        if resp.status_code == 200 and len(resp.text) > 10:
                            yield {
                                "type": "log",
                                "message": f"[+] Discovered Well-Known Resource: {wk_url}",
                            }
                            yield {
                                "type": "asset",
                                "data": {
                                    "domain": host,
                                    "type": "content_path",
                                    "value": wk_url,
                                    "status": "live",
                                    "status_code": 200,
                                    "metadata": {
                                        "url": wk_url,
                                        "host": host,
                                        "status_code": 200,
                                        "content_length": len(resp.content),
                                        "source": "well_known",
                                    },
                                    "discovered_by": self.name,
                                    "sources": ["api_surface"],
                                },
                            }
                            yield {
                                "type": "url_event",
                                "data": {
                                    "url": wk_url,
                                    "original_url": wk_url,
                                    "source": "api_surface",
                                    "sources": ["api_surface"],
                                },
                            }
                    except Exception:
                        pass

        duration = round(time.time() - start_ts, 2)
        yield {
            "type": "scan_summary",
            "provider": self.name,
            "status": "completed",
            "count": specs_found + graphql_found,
            "specs_found": specs_found,
            "graphql_found": graphql_found,
            "endpoints_extracted": endpoints_extracted,
            "duration_seconds": duration,
        }
        yield {
            "type": "log",
            "message": f"[√] API Surface probing complete. Specs: {specs_found} | GraphQL: {graphql_found} | "
                       f"Extracted routes: {endpoints_extracted} | Duration: {duration}s",
        }

