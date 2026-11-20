"""Cloud URL classification.

Scans discovered URLs for known cloud-provider host patterns (S3/R2/GCS/Azure
storage, CloudFront, EC2, App Engine, Cloud Run, Azure App Service, etc.) and
stores them as `cloud_service` assets with the originating host when known.

These assets power the Cloud inventory tab and are also used to extend
screenshot scope with the related cloud endpoints.
"""

import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("reconforge.services.cloud_classify")

# (hostname regex, provider, service, category)
CLOUD_PATTERNS: List[Tuple[re.Pattern, str, str, str]] = [
    # AWS
    (re.compile(r"(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$"), "aws", "s3", "storage"),
    (re.compile(r"\.s3-website[.-][a-z0-9.-]+\.amazonaws\.com$"), "aws", "s3-website", "storage"),
    (re.compile(r"\.s3\.dualstack\.[a-z0-9.-]+\.amazonaws\.com$"), "aws", "s3", "storage"),
    (re.compile(r"(^|\.)cloudfront\.net$"), "aws", "cloudfront", "cdn"),
    (re.compile(r"\.compute(?:-1)?\.amazonaws\.com$"), "aws", "ec2", "compute"),
    (re.compile(r"\.elasticbeanstalk\.com$"), "aws", "elastic-beanstalk", "platform"),
    (re.compile(r"\.amplifyapp\.com$"), "aws", "amplify", "platform"),
    (re.compile(r"\.execute-api\.[a-z0-9-]+\.amazonaws\.com$"), "aws", "api-gateway", "api"),
    (re.compile(r"\.elb\.[a-z0-9-]+\.amazonaws\.com$"), "aws", "elb", "load-balancer"),
    (re.compile(r"\.rds\.amazonaws\.com$"), "aws", "rds", "database"),
    (re.compile(r"\.redshift\.amazonaws\.com$"), "aws", "redshift", "database"),
    (re.compile(r"\.elasticache\.amazonaws\.com$"), "aws", "elasticache", "database"),
    (re.compile(r"\.awsapps\.com$"), "aws", "aws-apps", "platform"),
    (re.compile(r"\.amazonaws\.com$"), "aws", "aws-service", "cloud"),
    # GCP
    (re.compile(r"(^|\.)storage\.googleapis\.com$"), "gcp", "cloud-storage", "storage"),
    (re.compile(r"\.storage\.googleapis\.com$"), "gcp", "cloud-storage", "storage"),
    (re.compile(r"\.appspot\.com$"), "gcp", "app-engine", "platform"),
    (re.compile(r"\.run\.app$"), "gcp", "cloud-run", "compute"),
    (re.compile(r"\.cloudfunctions\.net$"), "gcp", "cloud-functions", "compute"),
    (re.compile(r"\.firebaseapp\.com$"), "gcp", "firebase-hosting", "platform"),
    (re.compile(r"\.web\.app$"), "gcp", "firebase-hosting", "platform"),
    (re.compile(r"\.googleapis\.com$"), "gcp", "google-api", "api"),
    (re.compile(r"\.googleusercontent\.com$"), "gcp", "google-user-content", "cdn"),
    # Azure
    (re.compile(r"\.blob\.core\.windows\.net$"), "azure", "blob-storage", "storage"),
    (re.compile(r"\.file\.core\.windows\.net$"), "azure", "file-storage", "storage"),
    (re.compile(r"\.queue\.core\.windows\.net$"), "azure", "queue-storage", "storage"),
    (re.compile(r"\.table\.core\.windows\.net$"), "azure", "table-storage", "storage"),
    (re.compile(r"\.azurewebsites\.net$"), "azure", "app-service", "platform"),
    (re.compile(r"\.cloudapp\.azure\.com$"), "azure", "cloud-app", "compute"),
    (re.compile(r"\.trafficmanager\.net$"), "azure", "traffic-manager", "load-balancer"),
    (re.compile(r"\.azurecontainer\.io$"), "azure", "container-instances", "compute"),
    (re.compile(r"\.azurecr\.io$"), "azure", "container-registry", "registry"),
    (re.compile(r"\.vault\.azure\.net$"), "azure", "key-vault", "security"),
    (re.compile(r"\.database\.windows\.net$"), "azure", "sql-database", "database"),
    # Cloudflare and common CDNs
    (re.compile(r"\.r2\.dev$"), "cloudflare", "r2", "storage"),
    (re.compile(r"\.workers\.dev$"), "cloudflare", "workers", "compute"),
    (re.compile(r"\.pages\.dev$"), "cloudflare", "pages", "platform"),
    (re.compile(r"\.cloudflare\.com$"), "cloudflare", "cloudflare", "cdn"),
    (re.compile(r"\.jsdelivr\.net$"), "cloudflare", "jsdelivr", "cdn"),
    (re.compile(r"\.unpkg\.com$"), "cloudflare", "unpkg", "cdn"),
    # Other providers
    (re.compile(r"\.digitaloceanspaces\.com$"), "digitalocean", "spaces", "storage"),
    (re.compile(r"\.ondigitalocean\.app$"), "digitalocean", "app-platform", "platform"),
    (re.compile(r"\.backblazeb2\.com$"), "backblaze", "b2", "storage"),
    (re.compile(r"\.wasabisys\.com$"), "wasabi", "object-storage", "storage"),
    (re.compile(r"\.linodeobjects\.com$"), "linode", "object-storage", "storage"),
    (re.compile(r"\.vultrobjects\.com$"), "vultr", "object-storage", "storage"),
    (re.compile(r"\.scw\.cloud$"), "scaleway", "cloud", "cloud"),
    (re.compile(r"\.oraclecloud\.com$"), "oracle", "oci", "cloud"),
    (re.compile(r"\.aliyuncs\.com$"), "alibaba", "aliyun", "cloud"),
    (re.compile(r"\.alicdn\.com$"), "alibaba", "cdn", "cdn"),
    (re.compile(r"\.cloud-object-storage\.appdomain\.cloud$"), "ibm", "cos", "storage"),
    (re.compile(r"\.sos\.exo\.io$"), "exoscale", "object-storage", "storage"),
    (re.compile(r"\.r2\.cloudflarestorage\.com$"), "cloudflare", "r2", "storage"),
]

PATH_STYLE_HOSTS = {
    "s3.amazonaws.com": ("aws", "s3", "storage"),
    "storage.googleapis.com": ("gcp", "cloud-storage", "storage"),
}


def classify_cloud_url(url: str) -> Optional[Dict[str, Any]]:
    """Returns provider/service/category/bucket metadata for a cloud URL."""
    try:
        parsed = urlparse(str(url or "").strip())
        host = (parsed.hostname or "").lower().strip(".")
    except Exception:
        return None
    if not host:
        return None

    provider = service = category = ""
    if host in PATH_STYLE_HOSTS:
        provider, service, category = PATH_STYLE_HOSTS[host]
    else:
        for pattern, prov, svc, cat in CLOUD_PATTERNS:
            if pattern.search(host):
                provider, service, category = prov, svc, cat
                break
    if not provider:
        return None

    bucket_name = ""
    if category == "storage":
        if provider == "aws" and service == "s3":
            if host.startswith("s3.amazonaws.com") or re.match(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$", host):
                parts = [part for part in (parsed.path or "").split("/") if part]
                bucket_name = parts[0] if parts else ""
            else:
                bucket_name = host.split(".")[0]
        elif provider == "gcp" and service == "cloud-storage":
            if host == "storage.googleapis.com":
                parts = [part for part in (parsed.path or "").split("/") if part]
                bucket_name = parts[0] if parts else ""
            else:
                bucket_name = host.split(".")[0]
        elif provider == "azure" and "core.windows.net" in host:
            bucket_name = host.split(".")[0]
        else:
            bucket_name = host.split(".")[0]

    return {
        "url": str(url).strip(),
        "host": host,
        "provider": provider,
        "service": service,
        "category": category,
        "bucket_name": bucket_name,
    }


async def classify_and_store(
    project_id: str,
    url_parents: Dict[str, Set[str]],
    scan_id: Optional[str] = None,
    limit: int = 1000,
) -> Dict[str, Any]:
    """Classifies URL→parent-host mappings and upserts cloud_service assets."""
    if not project_id:
        return {"total": 0, "urls": [], "by_provider": {}, "dropped": 0}

    classified: List[Dict[str, Any]] = []
    for url, parents in (url_parents or {}).items():
        info = classify_cloud_url(url)
        if not info:
            continue
        parent_hosts = sorted({
            str(parent or "").strip().lower()
            for parent in (parents or set())
            if str(parent or "").strip()
        })
        info["parent_hosts"] = parent_hosts
        info["parent_host"] = parent_hosts[0] if parent_hosts else ""
        classified.append(info)
        if len(classified) >= max(1, int(limit or 1000)):
            break

    if not classified:
        return {"total": 0, "urls": [], "by_provider": {}, "dropped": 0}

    stored = 0
    by_provider: Dict[str, int] = {}
    try:
        from app.database import get_database

        db = get_database()
        if db is None:
            return {"total": len(classified), "urls": [c["url"] for c in classified], "by_provider": {}, "dropped": 0}
        now = datetime.utcnow()
        for item in classified:
            by_provider[item["provider"]] = by_provider.get(item["provider"], 0) + 1
            existing = await db.assets.find_one({
                "project_id": project_id,
                "type": "cloud_service",
                "$or": [{"value": item["url"]}, {"metadata.url": item["url"]}],
            })
            metadata_fields = {
                "metadata.url": item["url"],
                "metadata.host": item["host"],
                "metadata.provider": item["provider"],
                "metadata.service": item["service"],
                "metadata.category": item["category"],
                "metadata.bucket_name": item["bucket_name"],
                "metadata.parent_host": item["parent_host"],
                "metadata.parent_hosts": item["parent_hosts"],
                "metadata.source": "url_classifier",
                "last_seen": now,
                "updated_at": now,
            }
            if scan_id:
                metadata_fields["scan_id"] = scan_id
            if existing:
                previous_parents = set(
                    (existing.get("metadata") or {}).get("parent_hosts") or []
                )
                merged_parents = sorted(previous_parents | set(item["parent_hosts"]))
                metadata_fields["metadata.parent_hosts"] = merged_parents
                metadata_fields["metadata.parent_host"] = merged_parents[0] if merged_parents else ""
                await db.assets.update_one({"_id": existing["_id"]}, {"$set": metadata_fields})
            else:
                await db.assets.insert_one({
                    "project_id": project_id,
                    "type": "cloud_service",
                    "domain": item["host"],
                    "value": item["url"],
                    "status": "live" if item["parent_hosts"] else "unknown",
                    "metadata": {
                        "url": item["url"],
                        "host": item["host"],
                        "provider": item["provider"],
                        "service": item["service"],
                        "category": item["category"],
                        "bucket_name": item["bucket_name"],
                        "parent_host": item["parent_host"],
                        "parent_hosts": item["parent_hosts"],
                        "source": "url_classifier",
                    },
                    "discovered_by": "url_classifier",
                    "sources": ["url_classifier"],
                    "first_seen": now,
                    "last_seen": now,
                    "created_at": now,
                    "updated_at": now,
                    **({"scan_id": scan_id} if scan_id else {}),
                })
            stored += 1
    except Exception as exc:
        logger.warning("Cloud classification persistence failed: %s", exc)

    return {
        "total": len(classified),
        "stored": stored,
        "urls": [item["url"] for item in classified],
        "by_provider": by_provider,
        "dropped": 0,
    }
