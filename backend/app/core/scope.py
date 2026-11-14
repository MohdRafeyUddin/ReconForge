import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("reconforge.core.scope")


def normalize_seed_domain(seed: str) -> str:
    """
    Normalizes seed domains (e.g. '*.example.com', '*example.com',
    'https://*.example.com:443') to a clean root domain ('example.com').
    """
    if not seed or not isinstance(seed, str):
        return ""
    s = seed.strip().lower()
    if "://" in s:
        try:
            parsed = urlparse(s)
            s = parsed.hostname or parsed.netloc or parsed.path
        except Exception:
            pass
    if ":" in s and not s.startswith("["):
        s = s.split(":")[0]
    while s.startswith("*.") or s.startswith("*"):
        if s.startswith("*."):
            s = s[2:]
        elif s.startswith("*"):
            s = s[1:]
        s = s.strip()
    return s.strip("/.").strip()


def _extract_host(target: str) -> str:
    """Extract clean hostname or IP from target string (domain, IP, URL, or host:port)."""
    if not target or not isinstance(target, str):
        return ""
    target = target.strip()
    if "://" in target:
        try:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc or ""
            return host.lower().strip()
        except Exception:
            pass
    if ":" in target and not target.startswith("["):
        # Split host:port if not IPv6
        parts = target.split(":", 1)
        # Check if first part looks like port or IP
        if not parts[0].isdigit():
            target = parts[0]
    return target.lower().strip().rstrip("/")


def _parse_ip_or_network(target: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse string as IP address or CIDR network object."""
    target = target.strip()
    try:
        if "/" in target:
            return ipaddress.ip_network(target, strict=False)
        else:
            ip = ipaddress.ip_address(target)
            return ipaddress.ip_network(f"{ip}/{32 if ip.version == 4 else 128}", strict=False)
    except ValueError:
        return None


def _matches_host_rule(host: str, rule: str) -> bool:
    """
    Check if a hostname matches a rule.
    Supports:
      - exact: 'example.com', 'api.example.com'
      - wildcard: '*.example.com' (matches 'api.example.com', 'sub.api.example.com', but NOT 'example.com')
      - prefix wildcard: '*example.com'
    """
    host = host.lower().strip()
    rule = rule.lower().strip()

    if not host or not rule:
        return False

    if host == rule:
        return True

    if rule.startswith("*."):
        root = rule[2:]
        if host.endswith(f".{root}"):
            return True
    elif rule.startswith("*"):
        suffix = rule[1:]
        if host.endswith(suffix):
            return True

    return False


def build_scope_regex(rules: List[str]) -> Optional[str]:
    """
    Builds a regex pattern for crawler scope restriction (e.g. Katana -cs or -cos).
    Matches URLs based on hostname/IP rules:
      - '*.example.com' -> only subdomains of example.com (does not match example.com alone)
      - 'example.com' -> exact host example.com
      - '10.0.0.1' -> exact IP
    """
    if not rules:
        return None

    patterns: List[str] = []
    for r in rules:
        if not r or not isinstance(r, str):
            continue
        cleaned = r.strip().lower()
        if not cleaned:
            continue

        net = _parse_ip_or_network(cleaned)
        if net:
            if net.num_addresses == 1:
                ip_esc = re.escape(str(net.network_address))
                patterns.append(rf"https?://{ip_esc}(?::\d+)?(?:/.*)?$")
            continue

        if cleaned.startswith("*."):
            root = cleaned[2:]
            root_esc = re.escape(root)
            # Require at least one subdomain label preceding root
            patterns.append(rf"https?://(?:[a-zA-Z0-9_\-]+\.)+{root_esc}(?::\d+)?(?:/.*)?$")
        elif cleaned.startswith("*"):
            suffix = cleaned[1:]
            suffix_esc = re.escape(suffix)
            patterns.append(rf"https?://[a-zA-Z0-9_\-\.]*{suffix_esc}(?::\d+)?(?:/.*)?$")
        else:
            host_esc = re.escape(cleaned)
            patterns.append(rf"https?://{host_esc}(?::\d+)?(?:/.*)?$")

    if not patterns:
        return None

    if len(patterns) == 1:
        return patterns[0]
    return f"(?:{'|'.join(patterns)})"


def _matches_rule(target: str, rule: str) -> bool:
    """
    Check if a target (host, URL, IP) matches a scope rule.
    Rule can be a hostname, wildcard domain, or IP/CIDR.
    """
    host = _extract_host(target)
    rule = rule.strip()

    if not host or not rule:
        return False

    # 1. Check IP / CIDR matching
    rule_net = _parse_ip_or_network(rule)
    host_ip = None
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        pass

    if rule_net and host_ip:
        return host_ip in rule_net

    # 2. Check Hostname / Wildcard matching
    return _matches_host_rule(host, rule)


def is_in_scope(target: str, scope: Optional[Dict[str, Any]]) -> bool:
    """
    Evaluates whether a target is within scope.
    Rules:
      - 'out_of_scope' ALWAYS wins. If target matches any out-of-scope rule, returns False.
      - If 'in_scope' is non-empty, target must match at least one in-scope rule.
      - If 'in_scope' is empty but scope exists: fail-closed if out-of-scope defined,
        or allow if scope config is wholly empty.
      - If scope is None or empty dicts: scope is unconfigured, returns True.
    """
    if not target or not isinstance(target, str):
        return False

    if not scope:
        return True

    in_scope_rules: List[str] = [
        r.strip() for r in (scope.get("in_scope") or []) if r and r.strip()
    ]
    out_of_scope_rules: List[str] = [
        r.strip() for r in (scope.get("out_of_scope") or []) if r and r.strip()
    ]

    # If no rules whatsoever are configured, scope is considered unconfigured
    if not in_scope_rules and not out_of_scope_rules:
        return True

    # 1. OUT OF SCOPE ALWAYS WINS
    for oos in out_of_scope_rules:
        if _matches_rule(target, oos):
            logger.debug("[scope] Target '%s' dropped by OUT_OF_SCOPE rule: %s", target, oos)
            return False

    # 2. IN SCOPE CHECK
    if in_scope_rules:
        for ins in in_scope_rules:
            if _matches_rule(target, ins):
                return True
        # Target was not in any in-scope rule
        logger.debug("[scope] Target '%s' dropped because not matched in IN_SCOPE rules", target)
        return False

    # Only out_of_scope was defined and target didn't match it
    return True


def is_ip_in_scope(ip_str: str, scope: Optional[Dict[str, Any]]) -> bool:
    """Specialized check for resolved IP addresses against scope (especially CIDRs).

    Rules:
      - If IP matches any out_of_scope CIDR or IP rule -> False (dropped).
      - If in_scope contains CIDR or IP rules:
          - IP must match at least one of the in_scope CIDR/IP rules.
      - If in_scope contains ONLY domain/hostname rules and no CIDR/IP rules,
        then any IP not explicitly out-of-scope is considered valid/in-scope (True).
    """
    if not ip_str or not isinstance(ip_str, str):
        return False
    if not scope:
        return True

    ip = None
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    out_rules = [r.strip() for r in (scope.get("out_of_scope") or []) if r and r.strip()]
    in_rules = [r.strip() for r in (scope.get("in_scope") or []) if r and r.strip()]

    # 1. Check out_of_scope IP / CIDRs
    for rule in out_rules:
        net = _parse_ip_or_network(rule)
        if net and ip in net:
            logger.debug("[scope] Resolved IP '%s' dropped by out_of_scope rule: %s", ip_str, rule)
            return False

    # 2. Check in_scope IP / CIDRs
    in_ip_rules = [r for r in in_rules if _parse_ip_or_network(r) is not None]
    if in_ip_rules:
        for rule in in_ip_rules:
            net = _parse_ip_or_network(rule)
            if net and ip in net:
                return True
        logger.debug("[scope] Resolved IP '%s' dropped because not matched in in_scope IP/CIDR rules", ip_str)
        return False

    return True


def filter_scope(
    targets: List[str], scope: Optional[Dict[str, Any]]
) -> Tuple[List[str], List[str]]:
    """
    Filters a list of targets against scope rules.
    Returns:
      (kept_targets, dropped_targets)
    Preserves input order while removing duplicates.
    """
    if not targets:
        return [], []

    if not scope or (
        not (scope.get("in_scope") or []) and not (scope.get("out_of_scope") or [])
    ):
        return list(dict.fromkeys(targets)), []

    kept: List[str] = []
    dropped: List[str] = []
    seen: Set[str] = set()

    for item in targets:
        if not item or not isinstance(item, str):
            continue
        cleaned = item.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)

        if is_in_scope(cleaned, scope):
            kept.append(cleaned)
        else:
            dropped.append(cleaned)

    return kept, dropped


# ==============================================================================
# Non-Routable & Private IP Restrictions (Loopback, RFC1918, Link-Local, CGNAT, Cloud-Metadata)
# ==============================================================================

DISALLOWED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),    # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),   # RFC1918
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local / Cloud metadata (e.g. 169.254.169.254)
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local (RFC4193)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def is_disallowed_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Checks if an IP address belongs to loopback, RFC1918, link-local,
    CGNAT, or cloud-metadata ranges.
    Returns (True, reason) if disallowed, (False, None) if permissible.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, None
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        for net in DISALLOWED_IP_NETWORKS:
            if ip in net:
                return True, f"disallowed IP {ip} in {net}"
    except ValueError:
        pass
    return False, None


# ==============================================================================
# Hostname Validation Before DNS (Strict RFC, Length, Encoded Fragments)
# ==============================================================================

RFC_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")


def validate_hostname(hostname: str, root_domain: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Strictly validates a hostname before DNS resolution:
      - Strict RFC regex (labels contain only alphanumeric and hyphens, no leading/trailing hyphens)
      - Reject names with encoded fragments (e.g. 'u003e', '%', '\\', '<', '>', etc.)
      - Reject labels over 63 characters and total hostname over 253 characters
      - Reject names where the root domain appears twice (e.g. sub.example.com.example.com)
    """
    if not hostname or not isinstance(hostname, str):
        return False, "empty_hostname"
    h = hostname.strip().lower().rstrip(".")
    if not h:
        return False, "empty_hostname"

    # Reject encoded fragments or illegal URL/HTML artifacts
    if re.search(r"(?:u003[0-9a-f]|%[0-9a-f]{2}|[\\<>\"'/?:#&@~`!$^*+=\[\]{}();,|])", h, re.IGNORECASE):
        return False, "contains_encoded_or_illegal_characters"

    if len(h) > 253:
        return False, "hostname_exceeds_253_chars"

    labels = h.split(".")
    if len(labels) < 2:
        return False, "fewer_than_two_labels"

    for label in labels:
        if not label:
            return False, "empty_label"
        if len(label) > 63:
            return False, f"label_exceeds_63_chars: {label[:12]}..."
        if not RFC_LABEL_REGEX.match(label):
            return False, f"invalid_rfc_label: {label}"

    # Reject names where root domain appears twice
    candidate_root = root_domain.lower() if root_domain else ".".join(labels[-2:])
    if candidate_root and h.count(candidate_root) > 1:
        return False, f"root_domain_appears_multiple_times: {candidate_root}"

    return True, None


# ==============================================================================
# URL Validation & Sanitization Before Storage
# ==============================================================================

def sanitize_url(url: Any) -> str:
    """
    Sanitizes URL before validation:
      1. Trim whitespace.
      2. Trim trailing ) ' " ] and punctuation: ')]}\'\">.,;:'
      3. Strip default ports (:80 for http, :443 for https).
    """
    if not url or not isinstance(url, str):
        return ""

    u = url.strip()
    trailing_chars = ")]}'\">.,;:"
    while u and u[-1] in trailing_chars:
        u = u[:-1].strip()

    if not u:
        return ""

    try:
        parsed = urlparse(u)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc
        if scheme in ("http", "https") and netloc:
            if scheme == "http" and netloc.endswith(":80"):
                new_netloc = netloc[:-3]
                u = u.replace(f"http://{netloc}", f"http://{new_netloc}", 1)
            elif scheme == "https" and netloc.endswith(":443"):
                new_netloc = netloc[:-4]
                u = u.replace(f"https://{netloc}", f"https://{new_netloc}", 1)
    except Exception:
        pass

    return u


def is_valid_url(url: Any) -> Tuple[bool, Optional[str]]:
    """
    Requirement 5: Validate every URL before it is stored.
    Sanitizes before rejecting (trim trailing ) ' " ] and punctuation, strip default :80/:443).
    Reject only:
      1. Nested schemes ("http://" or "https://" in path or query).
      2. ":/" right after the host (e.g. host ending in ":" or ":/" directly after netloc).
      3. Invalid hostnames.
    """
    if not url or not isinstance(url, str):
        return False, "empty_or_non_string"

    trimmed = sanitize_url(url)
    if not trimmed:
        return False, "empty_after_sanitization"

    lower_trimmed = trimmed.lower()

    # Must start with http:// or https://
    if not (lower_trimmed.startswith("http://") or lower_trimmed.startswith("https://")):
        return False, "must_start_with_http_or_https"

    # Reject whitespace or control characters
    if any(c in trimmed for c in ("\r", "\n", "\t", " ")):
        return False, "contains_whitespace_or_control_chars"

    # Reject WSL error strings
    if "wsl" in lower_trimmed and ("error" in lower_trimmed or "execvpe" in lower_trimmed):
        return False, "wsl_error_text"

    try:
        parsed = urlparse(trimmed)
    except Exception as e:
        return False, f"urlparse_failed: {e}"

    if parsed.scheme.lower() not in ("http", "https"):
        return False, "invalid_scheme"

    if not parsed.netloc or not parsed.hostname:
        return False, "missing_netloc_or_hostname"

    # Hostname validation (IP or valid domain label)
    host = parsed.hostname.lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        valid_h, reason = validate_hostname(host)
        if not valid_h:
            return False, f"invalid_hostname: {reason}"

    # Reject ":/" right after host (e.g. http://example.com:/path or parsed.netloc ending with :)
    if parsed.netloc.endswith(":"):
        return False, "colon_slash_right_after_host"

    path_and_rest = trimmed[len(parsed.scheme) + 3 + len(parsed.netloc):]
    if path_and_rest.startswith(":/"):
        return False, "colon_slash_right_after_host"

    # Reject nested schemes in path or query
    path_and_rest_lower = path_and_rest.lower()
    if "http://" in path_and_rest_lower or "https://" in path_and_rest_lower:
        return False, "path_contains_nested_scheme"

    return True, None


def get_root_domain(host: str, seed_domains: Optional[List[str]] = None) -> str:
    """Extract root domain for a given hostname."""
    h = host.strip().lower().rstrip(".")
    if not h:
        return ""
    if seed_domains:
        for s in seed_domains:
            s_clean = s.strip().lower().lstrip("*.").strip().rstrip(".")
            if s_clean and (h == s_clean or h.endswith(f".{s_clean}")):
                return s_clean
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    # Known 2-part ccTLDs
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "edu", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

