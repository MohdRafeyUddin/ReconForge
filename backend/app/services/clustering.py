"""Host Response Clustering Service
=================================
Groups live hosts by similarity to prevent redundant expensive scans
(Katana crawling, Nuclei endpoint probing, Dalfox XSS fuzzing, etc.):
  - Clustering key priority: body_hash > favicon_hash > title+content_length
  - One representative per cluster is scanned; remaining members are marked with a skip reason.
  - Skipped members REMAIN VISIBLE in the assets collection and UI (never hidden).
  - Can be overridden via project-level toggle (`scan_all_cluster_members: True`).
"""

import hashlib
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("reconforge.clustering")


def is_host_interesting(h: Dict[str, Any]) -> bool:
    """Checks whether a host asset is flagged as is_interesting or has 401/403 status."""
    if h.get("is_interesting") is True:
        return True
    meta = h.get("metadata", {}) if isinstance(h.get("metadata"), dict) else h
    if meta.get("is_interesting") is True:
        return True
    sc = h.get("status_code") if "status_code" in h else meta.get("status_code")
    try:
        if sc is not None and int(sc) in (401, 403):
            return True
    except (ValueError, TypeError):
        pass
    return False


def compute_cluster_key(asset_or_meta: Dict[str, Any], host: str = "") -> Tuple[str, str]:
    """
    Computes a canonical clustering key based on:
      1. status_code AND body_hash
      2. status_code AND favicon_hash AND title
    Title + content_length fallback is removed.
    Hosts without identical status_code or lacking hashes fall back to unique host identity.
    Returns (cluster_key_str, cluster_type).
    """
    meta = asset_or_meta.get("metadata", {}) if "metadata" in asset_or_meta else asset_or_meta
    domain = asset_or_meta.get("domain") or asset_or_meta.get("value") or host or "unknown"

    # Require status_code to cluster
    status_code = meta.get("status_code") if "status_code" in meta else asset_or_meta.get("status_code")
    if status_code is None or str(status_code).strip() == "":
        return f"host:{domain}", "unique_host"

    status_str = str(status_code).strip()

    # 1. Body hash (SHA256 / SimHash / MD5) with identical status_code
    body_hash = (
        meta.get("body_hash")
        or meta.get("body_sha256")
        or (asset_or_meta.get("fingerprint") or {}).get("body_hash")
    )
    if body_hash and str(body_hash).strip():
        clean_hash = str(body_hash).strip()
        return f"status:{status_str}|body:{clean_hash}", "body_hash"

    # 2. Favicon hash with identical status_code AND identical title
    favicon_hash = meta.get("favicon_hash") or meta.get("favicon_mmh3") or meta.get("favicon")
    if favicon_hash and str(favicon_hash).strip():
        clean_fav = str(favicon_hash).strip()
        title = meta.get("title") if "title" in meta else asset_or_meta.get("title")
        title_str = str(title if title is not None else "").strip()
        return f"status:{status_str}|title:{title_str}|favicon:{clean_fav}", "favicon_hash"

    # Fallback to host identity (unique)
    return f"host:{domain}", "unique_host"


def cluster_live_hosts(
    assets: List[Dict[str, Any]],
    scan_all_members: bool = False,
) -> Dict[str, Any]:
    """
    Clusters a list of live host assets.
    Enriches all assets in-place with cluster metadata:
      - cluster_id
      - cluster_key
      - cluster_type
      - is_cluster_representative
      - cluster_role ("representative" | "member")
      - cluster_size
      - cluster_representative_host
      - cluster_skip_reason (if member and not scanning all)
    
    Returns structured results:
      {
          "representatives": List[Dict],
          "skipped_members": List[Dict],
          "all_assets": List[Dict],
          "clusters": Dict[str, Dict],
          "summary": Dict[str, Any]
      }
    """
    if not assets:
        return {
            "representatives": [],
            "skipped_members": [],
            "all_assets": [],
            "clusters": {},
            "summary": {
                "total_hosts": 0,
                "cluster_count": 0,
                "representative_count": 0,
                "skipped_member_count": 0,
                "scan_all_members_enabled": scan_all_members,
            },
        }

    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    key_types: Dict[str, str] = {}

    for asset in assets:
        domain = asset.get("domain") or asset.get("value") or ""
        ckey, ktype = compute_cluster_key(asset, domain)
        grouped[ckey].append(asset)
        key_types[ckey] = ktype

    representatives: List[Dict[str, Any]] = []
    skipped_members: List[Dict[str, Any]] = []
    clusters_info: Dict[str, Dict[str, Any]] = {}

    for ckey, group in grouped.items():
        ktype = key_types[ckey]
        cluster_id = hashlib.sha256(ckey.encode("utf-8")).hexdigest()[:12]

        # Select deterministic representative (shortest domain, then alphabetical)
        group.sort(key=lambda a: (len(a.get("domain", "")), a.get("domain", "")))
        rep = group[0]
        rep_domain = rep.get("domain") or rep.get("value") or "representative"

        clusters_info[cluster_id] = {
            "cluster_id": cluster_id,
            "cluster_key": ckey,
            "clustering_attribute": ktype,
            "representative_host": rep_domain,
            "size": len(group),
            "members": [m.get("domain") or m.get("value") or "" for m in group],
        }

        # Mark representative
        rep["cluster_id"] = cluster_id
        rep["cluster_role"] = "representative"
        rep["is_cluster_representative"] = True
        rep["is_cluster_member"] = False
        rep["cluster_size"] = len(group)
        rep["cluster_representative_host"] = rep_domain
        rep["cluster_skip_reason"] = None
        rep["cluster_skipped"] = False
        representatives.append(rep)

        # Mark non-representatives
        for member in group[1:]:
            member["cluster_id"] = cluster_id
            member["cluster_role"] = "member"
            member["is_cluster_representative"] = False
            member["is_cluster_member"] = True
            member["cluster_size"] = len(group)
            member["cluster_representative_host"] = rep_domain

            # Never mark is_interesting (401/403) hosts as skipped members; they are always scanned.
            if scan_all_members or is_host_interesting(member):
                member["cluster_skip_reason"] = None
                member["cluster_skipped"] = False
                representatives.append(member)
            else:
                member["cluster_skip_reason"] = (
                    f"Duplicate HTTP response matching cluster representative '{rep_domain}' "
                    f"(duplicate of representative via {ktype}: {ckey}). Expensive scans skipped."
                )
                member["cluster_skipped"] = True
                skipped_members.append(member)

    summary = {
        "total_hosts": len(assets),
        "cluster_count": len(grouped),
        "representative_count": len(representatives),
        "skipped_member_count": len(skipped_members),
        "scan_all_members_enabled": scan_all_members,
    }

    logger.info(
        "[clustering] Clustered %d live hosts into %d clusters: %d representatives, %d skipped members (override=%s)",
        len(assets),
        len(grouped),
        len(representatives),
        len(skipped_members),
        scan_all_members,
    )

    return {
        "representatives": representatives,
        "skipped_members": skipped_members,
        "all_assets": assets,
        "clusters": clusters_info,
        "summary": summary,
    }


def filter_hosts_for_downstream(clustered_data: Any) -> List[Dict[str, Any]]:
    """Returns the list of hosts that should be scanned downstream."""
    if isinstance(clustered_data, dict) and "representatives" in clustered_data:
        return clustered_data["representatives"]
    elif isinstance(clustered_data, list):
        return [h for h in clustered_data if h.get("is_cluster_representative") or not h.get("cluster_skipped", False)]
    return []


cluster_hosts = cluster_live_hosts

