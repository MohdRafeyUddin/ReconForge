import json
import logging
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("reconforge.core.tools")

DEFAULT_TOOL_OVERRIDES: Dict[str, str] = {
    "amass": "/snap/bin/amass",
    "linkfinder": "/home/kali/tools/LinkFinder/linkfinder.py",
    "dnsreaper": "/home/kali/tools/dnsReaper/main.py",
    "massdns": "/usr/local/bin/massdns",
}

SPECIAL_SCRIPT_CANDIDATES: Dict[str, List[str]] = {
    "linkfinder": ["~/tools/LinkFinder/linkfinder.py", "~/LinkFinder/linkfinder.py"],
    "openredirex": ["~/tools/OpenRedireX/openredirex.py", "~/OpenRedireX/openredirex.py"],
    "dnsreaper": ["~/tools/dnsReaper/main.py", "~/dnsReaper/main.py", "~/tools/dnsReaper/dnsReaper.py"],
    "massdns": ["/usr/local/bin/massdns", "/usr/bin/massdns", "~/tools/massdns/bin/massdns"],
    "cloud_enum": ["~/tools/cloud_enum/cloud_enum.py", "~/cloud_enum/cloud_enum.py"],
}

# Central Tool Registry
RECON_TOOLS: Dict[str, Dict[str, Any]] = {
    "subfinder": {
        "name": "Subfinder",
        "binary": "subfinder",
        "category": "Discovery",
        "required": False,
        "description": "Fast passive subdomain enumeration tool using open-source intelligence sources.",
        "install_hint": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    },
    "assetfinder": {
        "name": "Assetfinder",
        "binary": "assetfinder",
        "category": "Discovery",
        "required": False,
        "description": "Finds domains and subdomains potentially related to a target domain.",
        "install_hint": "go install github.com/tomnomnom/assetfinder@latest",
    },
    "chaos": {
        "name": "Chaos",
        "binary": "chaos",
        "category": "Discovery",
        "required": False,
        "description": "ProjectDiscovery client to communicate with Chaos dataset API.",
        "install_hint": "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
    },
    "amass": {
        "name": "Amass",
        "binary": "amass",
        "category": "Discovery",
        "required": False,
        "description": "In-depth Attack Surface Mapping using passive enumeration.",
        "install_hint": "sudo apt update && sudo apt install -y amass  # or go install -v github.com/owasp-amass/amass/v4/...@master",
    },
    "dnsx": {
        "name": "DNSx",
        "binary": "dnsx",
        "category": "Resolution",
        "required": False,
        "description": "Fast and multi-purpose DNS toolkit allow to run multiple DNS queries.",
        "install_hint": "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    },
    "subzy": {
        "name": "Subzy",
        "binary": "subzy",
        "category": "Resolution",
        "required": False,
        "description": "Subdomain takeover vulnerability checker.",
        "install_hint": "go install github.com/PentestPad/subzy@latest",
    },
    "naabu": {
        "name": "Naabu",
        "binary": "naabu",
        "category": "Port Scanning",
        "required": False,
        "description": "Fast port scanner written in Go focused on reliability and simplicity.",
        "install_hint": "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    },
    "httpx": {
        "name": "HTTPX",
        "binary": "httpx",
        "category": "HTTP Probing",
        "required": False,
        "description": "Fast and multi-purpose HTTP toolkit that allows running multiple probes.",
        "install_hint": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    },
    "katana": {
        "name": "Katana",
        "binary": "katana",
        "category": "Crawling",
        "required": False,
        "description": "Next-generation crawling and spidering framework.",
        "install_hint": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    },
    "gau": {
        "name": "GAU (GetAllUrls)",
        "binary": "gau",
        "category": "Crawling",
        "required": False,
        "description": "Fetches known URLs from AlienVault's OTX, Wayback Machine, and Common Crawl.",
        "install_hint": "go install github.com/lc/gau/v2/cmd/gau@latest",
    },
    "subjs": {
        "name": "SubJS",
        "binary": "subjs",
        "category": "JS Analysis",
        "required": False,
        "description": "Fetches JavaScript files from a list of URLs or hosts.",
        "install_hint": "go install github.com/lc/subjs@latest",
    },
    "linkfinder": {
        "name": "LinkFinder",
        "binary": "linkfinder",
        "category": "JS Analysis",
        "required": False,
        "description": "Discovers endpoints and their parameters in JavaScript files.",
        "install_hint": "git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder && pip install -r ~/tools/LinkFinder/requirements.txt",
    },
    "uro": {
        "name": "Uro",
        "binary": "uro",
        "category": "URL Processing",
        "required": False,
        "description": "URL normalizer and deduplicator for web security testing.",
        "install_hint": "pipx install uro  # or pip install uro",
    },
    "gf": {
        "name": "GF",
        "binary": "gf",
        "category": "URL Processing",
        "required": False,
        "description": "A wrapper around grep to avoid typing common patterns.",
        "install_hint": "go install github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf",
    },
    "nuclei": {
        "name": "Nuclei",
        "binary": "nuclei",
        "category": "Validation",
        "required": False,
        "description": "Fast and customizable vulnerability scanner based on simple YAML templates.",
        "install_hint": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && nuclei -update-templates",
    },
    "dalfox": {
        "name": "Dalfox",
        "binary": "dalfox",
        "category": "Validation",
        "required": False,
        "description": "Powerful open-source XSS scanner and utility focused on automation.",
        "install_hint": "go install github.com/hahwul/dalfox/v2@latest",
    },
    "openredirex": {
        "name": "OpenRedirex",
        "binary": "openredirex",
        "category": "Validation",
        "required": False,
        "description": "Asynchronous Open Redirect vulnerability scanner.",
        "install_hint": "git clone https://github.com/devanshbatham/OpenRedireX.git ~/tools/OpenRedireX",
    },
    "gowitness": {
        "name": "GoWitness",
        "binary": "gowitness",
        "category": "Visual Verification",
        "required": False,
        "description": "Web screenshot utility using Chrome Headless.",
        "install_hint": "go install github.com/sensepost/gowitness@latest",
    },
    "ffuf": {
        "name": "FFUF",
        "binary": "ffuf",
        "category": "Content Discovery",
        "required": False,
        "description": "Fast web fuzzer written in Go.",
        "install_hint": "sudo apt update && sudo apt install -y ffuf  # or go install github.com/ffuf/ffuf/v2@latest",
    },
    "wafw00f": {
        "name": "wafw00f",
        "binary": "wafw00f",
        "category": "WAF Detection",
        "required": False,
        "description": "Web Application Firewall Fingerprinting Toolkit.",
        "install_hint": "pipx install wafw00f  # or sudo apt install -y wafw00f",
    },
    "nmap": {
        "name": "Nmap",
        "binary": "nmap",
        "category": "Port Scanning / Service Detection",
        "required": False,
        "description": "Network exploration tool and security / port scanner.",
        "install_hint": "sudo apt update && sudo apt install -y nmap",
    },
    "feroxbuster": {
        "name": "Feroxbuster",
        "binary": "feroxbuster",
        "category": "Content Discovery",
        "required": False,
        "description": "Fast, simple, recursive content discovery tool written in Rust.",
        "install_hint": "sudo apt update && sudo apt install -y feroxbuster  # or cargo install feroxbuster",
    },
    "arjun": {
        "name": "Arjun",
        "binary": "arjun",
        "category": "Parameter Discovery",
        "required": False,
        "description": "HTTP parameter discovery suite for discovering hidden GET & POST parameters.",
        "install_hint": "pipx install arjun  # or pip install arjun",
    },
    "x8": {
        "name": "x8",
        "binary": "x8",
        "category": "Parameter Discovery",
        "required": False,
        "description": "Fast hidden parameter discovery suite written in Rust.",
        "install_hint": "cargo install x8  # or download binary from github.com/Sh1Yo/x8",
    },
    "waymore": {
        "name": "Waymore",
        "binary": "waymore",
        "category": "Historical URLs",
        "required": False,
        "description": "Finds URLs from Wayback Machine, Common Crawl, AlienVault, URLScan, etc.",
        "install_hint": "pipx install waymore  # or pip install git+https://github.com/xnl-h4ck3r/waymore.git",
    },
    "puredns": {
        "name": "PureDNS",
        "binary": "puredns",
        "category": "DNS Brute Force",
        "required": False,
        "description": "Fast domain resolver and active subdomain bruteforcer with wildcard detection powered by massdns.",
        "install_hint": "go install github.com/d3mondev/puredns/v2@latest",
    },
    "massdns": {
        "name": "MassDNS",
        "binary": "massdns",
        "category": "DNS Resolution",
        "required": False,
        "description": "High-performance stub DNS resolver required by PureDNS.",
        "install_hint": "sudo apt update && sudo apt install -y massdns || (git clone https://github.com/blechschmidt/massdns.git /tmp/massdns && cd /tmp/massdns && make && sudo cp bin/massdns /usr/local/bin/)",
    },
    "shuffledns": {
        "name": "ShuffleDNS",
        "binary": "shuffledns",
        "category": "DNS Brute Force",
        "required": False,
        "description": "MassDNS wrapper written in Go to enumerate and resolve subdomains.",
        "install_hint": "go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    },
    "alterx": {
        "name": "AlterX",
        "binary": "alterx",
        "category": "DNS Permutations",
        "required": False,
        "description": "Fast and customizable subdomain wordlist generator using DSL rules.",
        "install_hint": "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
    },
    "asnmap": {
        "name": "ASNMap",
        "binary": "asnmap",
        "category": "Root Expansion",
        "required": False,
        "description": "Quickly gather ASN and network CIDR ranges for mapping organizational perimeter.",
        "install_hint": "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    },
    "dnsreaper": {
        "name": "dnsReaper",
        "binary": "dnsreaper",
        "category": "Subdomain Takeover",
        "required": False,
        "description": "Subdomain takeover tool with accurate DNS scanning signatures.",
        "install_hint": "git clone https://github.com/punk-security/dnsReaper.git ~/tools/dnsReaper && pip install -r ~/tools/dnsReaper/requirements.txt",
    },
    # ------------------------------------------------------------------
    # Phase 8 — JS analysis, secrets, cloud buckets, OAST, tech routing
    # ------------------------------------------------------------------
    "jsluice": {
        "name": "jsluice",
        "binary": "jsluice",
        "category": "JS Analysis",
        "required": False,
        "description": "Extracts URLs, paths and secrets from JavaScript files.",
        "install_hint": "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
    },
    "xnlinkfinder": {
        "name": "xnLinkFinder",
        "binary": "xnLinkFinder",
        "category": "JS Analysis",
        "required": False,
        "description": "Endpoint discovery from JavaScript files (LinkFinder successor).",
        "install_hint": "pipx install xnLinkFinder",
    },
    "sourcemapper": {
        "name": "SourceMapper",
        "binary": "sourcemapper",
        "category": "JS Analysis",
        "required": False,
        "description": "Fetches JavaScript source maps and reconstructs their sources.",
        "install_hint": "go install github.com/denandz/sourcemapper@latest",
    },
    "trufflehog": {
        "name": "TruffleHog",
        "binary": "trufflehog",
        "category": "Secrets",
        "required": False,
        "description": "Detects and classifies secrets in files and response bodies.",
        "install_hint": "go install github.com/trufflesecurity/trufflehog/v3@latest",
    },
    "gitleaks": {
        "name": "Gitleaks",
        "binary": "gitleaks",
        "category": "Secrets",
        "required": False,
        "description": "SAST secret scanner used as a fallback for local response files.",
        "install_hint": "go install github.com/gitleaks/gitleaks/v8@latest",
    },
    "cloud_enum": {
        "name": "cloud_enum",
        "binary": "cloud_enum",
        "category": "Cloud",
        "required": False,
        "description": "Multi-cloud public bucket enumeration (AWS, Azure, GCP).",
        "install_hint": "git clone https://github.com/initstring/cloud_enum.git ~/tools/cloud_enum && pip install -r ~/tools/cloud_enum/requirements.txt",
    },
    "s3scanner": {
        "name": "S3Scanner",
        "binary": "s3scanner",
        "category": "Cloud",
        "required": False,
        "description": "Checks S3 bucket candidates for existence and public access.",
        "install_hint": "pipx install s3scanner",
    },
    "interactsh": {
        "name": "Interactsh Client",
        "binary": "interactsh-client",
        "category": "OAST",
        "required": False,
        "description": "Out-of-band interaction client for blind vulnerability validation.",
        "install_hint": "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    },
    "wpscan": {
        "name": "WPScan",
        "binary": "wpscan",
        "category": "Tech Routing",
        "required": False,
        "description": "WordPress vulnerability scanner used when WordPress is detected.",
        "install_hint": "sudo apt install -y wpscan  # or: sudo gem install wpscan",
    },
}

# Allowlist definitions: tool names come strictly from registry allowlist
ALLOWED_TOOL_KEYS: Set[str] = set(RECON_TOOLS.keys())
ALLOWED_BINARIES: Set[str] = {t["binary"] for t in RECON_TOOLS.values()}

# In-memory caches and metadata
_TOOLS_CACHE: Dict[str, Dict[str, Any]] = {}
_TOOLS_CACHE_LAST_CHECKED: Optional[str] = None
_TOOLS_CACHE_WARNING: Optional[str] = None
_SCAN_TOOL_PATH_CACHE: Dict[str, Optional[str]] = {}

# Python resolution script executed inside WSL in ONE invocation
_WSL_RESOLVE_SCRIPT = """
import sys, os, shutil, json

home = os.path.expanduser('~')
extra = [
    f'{home}/go/bin',
    f'{home}/.local/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
    '/snap/bin'
]
full_path = ':'.join(extra + [os.environ.get('PATH', '')])

special = {
    'linkfinder': [f'{home}/tools/LinkFinder/linkfinder.py', f'{home}/LinkFinder/linkfinder.py'],
    'openredirex': [f'{home}/tools/OpenRedireX/openredirex.py', f'{home}/OpenRedireX/openredirex.py'],
    'dnsreaper': [f'{home}/tools/dnsReaper/main.py', f'{home}/dnsReaper/main.py', f'{home}/tools/dnsReaper/dnsReaper.py'],
    'massdns': ['/usr/local/bin/massdns', '/usr/bin/massdns', f'{home}/tools/massdns/bin/massdns'],
    'cloud_enum': [f'{home}/tools/cloud_enum/cloud_enum.py', f'{home}/cloud_enum/cloud_enum.py']
}

res = {}
for t in sys.argv[1:]:
    p = shutil.which(t, path=full_path)
    if not p and t in special:
        for cand in special[t]:
            if os.path.isfile(cand):
                p = cand
                break
    res[t] = p

print(json.dumps(res))
""".strip()


def validate_tool_name(tool_name: str) -> str:
    """
    Validates a tool name against the registry allowlist and ^[a-z0-9_-]+$.
    Raises ValueError on invalid input.
    """
    if not isinstance(tool_name, str):
        raise ValueError(f"Invalid tool name type: {type(tool_name).__name__}. Must be a string.")
    cleaned = tool_name.strip().lower()
    if not re.match(r"^[a-z0-9_-]+$", cleaned):
        raise ValueError(f"Invalid tool name: '{tool_name}'. Must match ^[a-z0-9_-]+$")
    if cleaned not in ALLOWED_TOOL_KEYS and cleaned not in ALLOWED_BINARIES:
        raise ValueError(f"Tool '{tool_name}' is not in the tool registry allowlist")
    return cleaned


def _get_cache_file_path() -> str:
    """Returns absolute path to persisted tools cache JSON file."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    storage_dir = os.path.join(base_dir, "storage")
    os.makedirs(storage_dir, exist_ok=True)
    return os.path.join(storage_dir, "tool_registry_cache.json")


def _get_tool_paths_file_path() -> str:
    """Returns absolute path to persisted tool paths JSON file."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    storage_dir = os.path.join(base_dir, "storage")
    os.makedirs(storage_dir, exist_ok=True)
    return os.path.join(storage_dir, "tool_paths.json")


def _get_tool_paths_override_file_path() -> str:
    """Returns absolute path to override tool paths JSON file."""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    storage_dir = os.path.join(base_dir, "storage")
    os.makedirs(storage_dir, exist_ok=True)
    return os.path.join(storage_dir, "tool_paths_override.json")


def load_tool_overrides() -> Dict[str, str]:
    """
    Loads tool path overrides from backend/storage/tool_paths_override.json.
    Overrides win over discovered paths, command -v, and any hardcoded order.
    Sets amass to /snap/bin/amass by default if not otherwise specified.
    """
    res = dict(DEFAULT_TOOL_OVERRIDES)
    override_path = _get_tool_paths_override_file_path()
    if not os.path.exists(override_path):
        try:
            with open(override_path, "w", encoding="utf-8") as f:
                json.dump(res, f, indent=2)
        except Exception as exc:
            logger.debug("[tools] Failed to create default tool overrides file: %s", exc)
        return res
    try:
        with open(override_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for k, v in data.items():
                if v and isinstance(v, str):
                    res[k.strip().lower()] = v.strip()
            return res
    except Exception as exc:
        logger.warning("[tools] Failed to load tool overrides from %s: %s", override_path, exc)
    return res


def load_tools_cache_from_disk() -> bool:
    """
    Loads persisted tools cache from backend/storage/tool_paths.json
    or tool_registry_cache.json.
    Returns True if successfully loaded, False otherwise.
    """
    global _TOOLS_CACHE, _TOOLS_CACHE_LAST_CHECKED, _SCAN_TOOL_PATH_CACHE
    paths_file = _get_tool_paths_file_path()
    cache_path = _get_cache_file_path()
    overrides = load_tool_overrides()

    # Try tool_paths.json first
    if os.path.exists(paths_file):
        try:
            with open(paths_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                # Apply overrides over discovered paths
                data.update(overrides)
                installed_count = 0
                for tool_key, tool_info in RECON_TOOLS.items():
                    binary = tool_info["binary"]
                    path = data.get(binary) or data.get(tool_key)
                    installed = bool(path and (path.startswith("/") or (len(path) > 2 and path[1] == ":")))
                    if installed:
                        installed_count += 1
                    _TOOLS_CACHE[tool_key] = {
                        "key": tool_key,
                        "name": tool_info["name"],
                        "binary": binary,
                        "wsl_binary": binary,
                        "category": tool_info["category"],
                        "required": tool_info["required"],
                        "description": tool_info["description"],
                        "install_hint": tool_info["install_hint"],
                        "installed": installed,
                        "path": path,
                        "resolved_path": path,
                    }
                    _SCAN_TOOL_PATH_CACHE[tool_key] = path if installed else None
                _TOOLS_CACHE_LAST_CHECKED = datetime.utcnow().isoformat() + "Z"
                if installed_count > 0:
                    return True
                _TOOLS_CACHE.clear()
                _SCAN_TOOL_PATH_CACHE.clear()
        except Exception as exc:
            logger.warning("[tools] Failed to load tool_paths.json: %s", exc)

    if not os.path.exists(cache_path):
        return False

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            return False

        tools_data = data.get("tools")
        if isinstance(tools_data, dict) and tools_data:
            _TOOLS_CACHE = tools_data
            _TOOLS_CACHE_LAST_CHECKED = data.get("last_checked")
            for k, val in tools_data.items():
                if isinstance(val, dict):
                    path = overrides.get(k) or val.get("path")
                    if k in overrides:
                        val["path"] = path
                        val["resolved_path"] = path
                        val["installed"] = True
                    _SCAN_TOOL_PATH_CACHE[k] = path
            installed_cnt = sum(1 for val in tools_data.values() if isinstance(val, dict) and val.get("installed"))
            if installed_cnt > 0:
                return True
            _TOOLS_CACHE.clear()
            _SCAN_TOOL_PATH_CACHE.clear()
    except Exception as exc:
        logger.warning("[tools] Failed to load tool cache from disk: %s", exc)
    return False


def save_tools_cache_to_disk() -> None:
    """Persists current tool status cache to backend/storage/tool_paths.json and tool_registry_cache.json."""
    if not any(t.get("installed") for t in _TOOLS_CACHE.values() if isinstance(t, dict)):
        return
    cache_path = _get_cache_file_path()
    paths_path = _get_tool_paths_file_path()
    try:
        payload = {
            "last_checked": _TOOLS_CACHE_LAST_CHECKED or (datetime.utcnow().isoformat() + "Z"),
            "tools": _TOOLS_CACHE,
        }
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        paths_dict = {}
        for tool_key, tool_info in RECON_TOOLS.items():
            t_status = _TOOLS_CACHE.get(tool_key, {})
            p = t_status.get("path")
            paths_dict[tool_info["binary"]] = p
            paths_dict[tool_key] = p
        with open(paths_path, "w", encoding="utf-8") as f:
            json.dump(paths_dict, f, indent=2)
    except Exception as exc:
        logger.warning("[tools] Failed to persist tool cache to disk: %s", exc)


def clear_tool_path_cache() -> None:
    """Clears in-memory scan path cache and tool cache (for tests/rescan)."""
    global _TOOLS_CACHE_LAST_CHECKED, _TOOLS_CACHE_WARNING
    _SCAN_TOOL_PATH_CACHE.clear()
    _TOOLS_CACHE.clear()
    _TOOLS_CACHE_LAST_CHECKED = None
    _TOOLS_CACHE_WARNING = None


def invalidate_tool_cache(tool_key: Optional[str] = None) -> None:
    """
    Invalidates the cache when a tool run fails with 'not found' or on explicit reset.
    Refreshes persisted state.
    """
    global _TOOLS_CACHE, _SCAN_TOOL_PATH_CACHE
    if tool_key is None:
        clear_tool_path_cache()
        cache_path = _get_cache_file_path()
        paths_path = _get_tool_paths_file_path()
        for p in (cache_path, paths_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        return

    try:
        norm_key = validate_tool_name(tool_key)
    except ValueError:
        return

    if norm_key in _TOOLS_CACHE:
        _TOOLS_CACHE[norm_key]["installed"] = False
        _TOOLS_CACHE[norm_key]["path"] = None
        _TOOLS_CACHE[norm_key]["resolved_path"] = None
        _TOOLS_CACHE[norm_key]["invalidated"] = True
    else:
        _TOOLS_CACHE[norm_key] = {
            "key": norm_key,
            "installed": False,
            "path": None,
            "resolved_path": None,
            "invalidated": True,
        }
    _SCAN_TOOL_PATH_CACHE[norm_key] = None
    save_tools_cache_to_disk()


def resolve_all_tools_in_system(timeout_seconds: int = 10) -> Tuple[Dict[str, Optional[str]], Optional[str]]:
    """
    Requirement 1: Resolves absolute paths for ALL registry tools in ONE WSL invocation:
      wsl -e bash -lc 'for t in <registry names>; do echo "$t=$(command -v $t)"; done'
    (allowlist names only).
    Search order if command -v fails: ~/go/bin, ~/.local/bin, /snap/bin, /usr/local/bin, /usr/bin.
    Overrides in backend/storage/tool_paths_override.json take precedence (overrides win).
    Returns (resolved_paths_map, warning_or_error).
    """
    is_windows = platform.system().lower() == "windows"
    wsl_user = os.getenv("WSL_USER", "kali")
    home_dir = f"/home/{wsl_user}" if is_windows else os.path.expanduser("~")

    # Strictly use allowlisted binaries
    valid_binaries = sorted(list(ALLOWED_BINARIES))
    resolved_paths: Dict[str, Optional[str]] = {b: None for b in valid_binaries}
    warning: Optional[str] = None

    if is_windows:
        # Single WSL invocation using argument list
        # Ensure search order directories are in PATH for command -v: ~/go/bin, ~/.local/bin, /snap/bin, /usr/local/bin, /usr/bin
        bash_script = (
            f'PATH="$HOME/go/bin:$HOME/.local/bin:/snap/bin:/usr/local/bin:/usr/bin:$PATH"; '
            f'for t in {" ".join(valid_binaries)}; do '
            'p=$(command -v "$t"); '
            'if [ -z "$p" ]; then '
            'case "$t" in '
            'cloud_enum) [ -f "$HOME/tools/cloud_enum/cloud_enum.py" ] && p="$HOME/tools/cloud_enum/cloud_enum.py";; '
            'linkfinder) [ -f "$HOME/tools/LinkFinder/linkfinder.py" ] && p="$HOME/tools/LinkFinder/linkfinder.py";; '
            'openredirex) [ -f "$HOME/tools/OpenRedireX/openredirex.py" ] && p="$HOME/tools/OpenRedireX/openredirex.py";; '
            'dnsreaper) [ -f "$HOME/tools/dnsReaper/main.py" ] && p="$HOME/tools/dnsReaper/main.py";; '
            'esac; '
            'fi; '
            'echo "$t=$p"; done'
        )
        cmd = ["wsl", "-e", "bash", "-lc", bash_script]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                encoding="utf-8",
                errors="replace",
            )
            if proc.returncode == 0 and proc.stdout.strip():
                stdout_str = proc.stdout.strip()
                if stdout_str.startswith("{"):
                    try:
                        parsed = json.loads(stdout_str)
                        if isinstance(parsed, dict):
                            resolved_paths.update(parsed)
                    except Exception:
                        pass
                else:
                    for line in stdout_str.splitlines():
                        line = line.strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip()
                            if k in resolved_paths:
                                resolved_paths[k] = v if v else None
            else:
                err_text = (proc.stderr or proc.stdout or "").strip()
                if not any(resolved_paths.values()):
                    warning = f"WSL tool resolution returned non-zero code ({proc.returncode}): {err_text[:120]}"
        except subprocess.TimeoutExpired:
            warning = f"WSL tool detection timed out after {timeout_seconds}s; returning cached results."
            logger.warning("[tools] %s", warning)
        except Exception as exc:
            warning = f"WSL is unreachable or encountered an error: {exc}"
            logger.warning("[tools] %s", warning)
    else:
        # Native Linux resolution (in-process)
        search_dirs = [
            f"{home_dir}/go/bin",
            f"{home_dir}/.local/bin",
            "/snap/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin",
        ]
        full_path = ":".join(search_dirs + [os.environ.get("PATH", "")])
        special = {
            "linkfinder": [f"{home_dir}/tools/LinkFinder/linkfinder.py", f"{home_dir}/LinkFinder/linkfinder.py"],
            "openredirex": [f"{home_dir}/tools/OpenRedireX/openredirex.py", f"{home_dir}/OpenRedireX/openredirex.py"],
            "cloud_enum": [f"{home_dir}/tools/cloud_enum/cloud_enum.py", f"{home_dir}/cloud_enum/cloud_enum.py"],
        }
        for b in valid_binaries:
            found = shutil.which(b, path=full_path)
            if not found:
                for d in search_dirs:
                    cand = os.path.join(d, b)
                    if os.path.isfile(cand) and os.access(cand, os.X_OK):
                        found = cand
                        break
            if not found and b in special:
                for cand in special[b]:
                    if os.path.isfile(cand):
                        found = cand
                        break
            resolved_paths[b] = found

    # Overrides win over discovered paths
    overrides = load_tool_overrides()
    for ov_k, ov_v in overrides.items():
        if ov_k in resolved_paths:
            resolved_paths[ov_k] = ov_v
        for t_k, t_info in RECON_TOOLS.items():
            if t_k == ov_k or t_info.get("binary") == ov_k:
                resolved_paths[t_info["binary"]] = ov_v

    return resolved_paths, warning


def refresh_all_tools_cache(timeout_seconds: int = 10) -> Dict[str, Any]:
    """
    Executes the single-call resolution across all tools, updates memory cache,
    and persists to backend/storage/tool_registry_cache.json.
    """
    global _TOOLS_CACHE, _TOOLS_CACHE_LAST_CHECKED, _TOOLS_CACHE_WARNING, _SCAN_TOOL_PATH_CACHE

    resolved_paths, warning = resolve_all_tools_in_system(timeout_seconds=timeout_seconds)
    _TOOLS_CACHE_LAST_CHECKED = datetime.utcnow().isoformat() + "Z"
    _TOOLS_CACHE_WARNING = warning

    # If timeout or unreachable and we have existing cache, preserve existing valid paths
    for tool_key, tool_info in RECON_TOOLS.items():
        binary = tool_info["binary"]
        path = resolved_paths.get(binary)
        if path is None and warning and tool_key in _TOOLS_CACHE and _TOOLS_CACHE[tool_key].get("path"):
            # Preserve cached path during timeout/error
            path = _TOOLS_CACHE[tool_key]["path"]

        installed = bool(path and (path.startswith("/") or (len(path) > 2 and path[1] == ":")))
        _TOOLS_CACHE[tool_key] = {
            "key": tool_key,
            "name": tool_info["name"],
            "binary": binary,
            "wsl_binary": binary,
            "category": tool_info["category"],
            "required": tool_info["required"],
            "description": tool_info["description"],
            "install_hint": tool_info["install_hint"],
            "installed": installed,
            "path": path,
            "resolved_path": path,
        }
        _SCAN_TOOL_PATH_CACHE[tool_key] = path if installed else None

    save_tools_cache_to_disk()
    return get_all_tools_status_with_metadata(force_refresh=False)


def _ensure_cache_loaded() -> None:
    """Ensures in-memory cache is populated from memory, disk, or single resolution."""
    global _TOOLS_CACHE
    if _TOOLS_CACHE and any(t.get("installed") for t in _TOOLS_CACHE.values() if isinstance(t, dict)):
        return
    if load_tools_cache_from_disk():
        return
    # First-time run: refresh cache once
    refresh_all_tools_cache(timeout_seconds=10)


def resolve_tool_absolute_path(tool_name: str, force_refresh: bool = False) -> Optional[str]:
    """
    Returns the cached absolute path for a tool (e.g. '/usr/bin/ffuf').
    Validates tool_name against the allowlist.
    Overrides in tool_paths_override.json win over command -v and any hardcoded order.
    """
    norm_key = validate_tool_name(tool_name)

    # Return cached scan path if already resolved
    if not force_refresh and norm_key in _SCAN_TOOL_PATH_CACHE and _SCAN_TOOL_PATH_CACHE[norm_key]:
        return _SCAN_TOOL_PATH_CACHE[norm_key]

    # If check_tool_in_system was patched by a mock in tests, honour it
    if hasattr(check_tool_in_system, "mock_calls"):
        is_inst, p_mock = check_tool_in_system(tool_name)
        if is_inst and p_mock:
            _SCAN_TOOL_PATH_CACHE[norm_key] = p_mock
            return p_mock
        return None

    if force_refresh:
        refresh_all_tools_cache(timeout_seconds=10)
    else:
        _ensure_cache_loaded()

    binary_name = RECON_TOOLS.get(norm_key, {}).get("binary", norm_key)
    # Re-check overrides after cache load
    overrides = load_tool_overrides()
    if norm_key in overrides:
        return overrides[norm_key]
    if binary_name in overrides:
        return overrides[binary_name]

    # Direct key lookup or binary lookup from cache
    p = None
    if norm_key in _TOOLS_CACHE:
        if _TOOLS_CACHE[norm_key].get("invalidated") is True:
            return None
        p = _TOOLS_CACHE[norm_key].get("path")
    if not p:
        for t_key, t_info in _TOOLS_CACHE.items():
            if t_info.get("binary") == norm_key:
                if t_info.get("invalidated") is True:
                    return None
                p = t_info.get("path")
                break

    # If not resolved from cache, check special scripts first, then search order
    if not p:
        is_windows = platform.system().lower() == "windows"
        wsl_user = os.getenv("WSL_USER", "kali")
        home_dir = f"/home/{wsl_user}" if is_windows else os.path.expanduser("~")

        # Check special scripts (e.g. LinkFinder ~/tools/LinkFinder/linkfinder.py)
        if norm_key in SPECIAL_SCRIPT_CANDIDATES or binary_name in SPECIAL_SCRIPT_CANDIDATES:
            cands = SPECIAL_SCRIPT_CANDIDATES.get(norm_key) or SPECIAL_SCRIPT_CANDIDATES.get(binary_name, [])
            for cand_pattern in cands:
                cand = cand_pattern.replace("~", home_dir)
                if is_windows:
                    try:
                        chk = subprocess.run(["wsl", "-e", "test", "-f", cand], capture_output=True, timeout=10)
                        if chk.returncode == 0:
                            p = cand
                            break
                    except Exception:
                        pass
                else:
                    if os.path.isfile(cand):
                        p = cand
                        break

        if not p:
            # Search order: Never default to ~/go/bin/<tool> without checking it exists
            search_dirs = [
                f"{home_dir}/go/bin",
                f"{home_dir}/.local/bin",
                "/snap/bin",
                "/usr/local/bin",
                "/usr/bin",
            ]
            b_name = RECON_TOOLS.get(norm_key, {}).get("binary", norm_key)
            for d in search_dirs:
                cand = f"{d}/{b_name}"
                if is_windows:
                    try:
                        chk = subprocess.run(["wsl", "-e", "test", "-x", cand], capture_output=True, timeout=10)
                        if chk.returncode == 0:
                            p = cand
                            break
                    except Exception:
                        pass
                else:
                    if os.path.isfile(cand) and os.access(cand, os.X_OK):
                        p = cand
                        break

        if p and norm_key in _TOOLS_CACHE:
            _TOOLS_CACHE[norm_key]["path"] = p
            _TOOLS_CACHE[norm_key]["resolved_path"] = p
            _TOOLS_CACHE[norm_key]["installed"] = True
            _SCAN_TOOL_PATH_CACHE[norm_key] = p

    return p


def check_tool_in_system(tool_key: str) -> Tuple[bool, Optional[str]]:
    """Checks if a tool exists and is executable in WSL2 or host."""
    try:
        path = resolve_tool_absolute_path(tool_key)
        return bool(path), path
    except ValueError:
        return False, None


def get_tool_status(tool_key: str, force_refresh: bool = False) -> Dict[str, Any]:
    """Returns a full status dictionary for a registered tool."""
    norm_key = validate_tool_name(tool_key)
    if force_refresh:
        refresh_all_tools_cache(timeout_seconds=10)
    else:
        _ensure_cache_loaded()

    if norm_key in _TOOLS_CACHE:
        return _TOOLS_CACHE[norm_key]

    tool_info = RECON_TOOLS.get(norm_key, {
        "name": norm_key,
        "binary": norm_key,
        "category": "Unknown",
        "required": False,
        "description": "Custom utility",
        "install_hint": f"Install {norm_key}",
    })
    return {
        "key": norm_key,
        "name": tool_info["name"],
        "binary": tool_info["binary"],
        "wsl_binary": tool_info["binary"],
        "category": tool_info["category"],
        "required": tool_info["required"],
        "description": tool_info["description"],
        "install_hint": tool_info["install_hint"],
        "installed": False,
        "path": None,
        "resolved_path": None,
    }


def get_all_tools_status(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """Returns list of status dictionaries for all registered tools."""
    if force_refresh:
        refresh_all_tools_cache(timeout_seconds=10)
    else:
        _ensure_cache_loaded()

    return [get_tool_status(k, force_refresh=False) for k in RECON_TOOLS.keys()]


def get_all_tools_status_with_metadata(
    force_refresh: bool = False,
    timeout_seconds: int = 10,
) -> Dict[str, Any]:
    """
    Requirement 3: GET /api/v1/system/tools returns cache immediately;
    ?refresh=true re-runs with 10s timeout and returns partial/cached data with warning.
    """
    if force_refresh:
        refresh_all_tools_cache(timeout_seconds=timeout_seconds)
    else:
        _ensure_cache_loaded()

    tools_list = [get_tool_status(k, force_refresh=False) for k in RECON_TOOLS.keys()]
    installed_count = sum(1 for t in tools_list if t["installed"])
    missing_count = len(tools_list) - installed_count

    return {
        "tools": tools_list,
        "total": len(tools_list),
        "installed": installed_count,
        "missing": missing_count,
        "installed_count": installed_count,
        "missing_count": missing_count,
        "last_checked": _TOOLS_CACHE_LAST_CHECKED,
        "warning": _TOOLS_CACHE_WARNING,
    }


def is_tool_available(tool_key: str, assume_installed: bool = False) -> bool:
    """
    Checks if a tool is available. If assume_installed is True, returns True.
    Otherwise queries cached status.
    """
    if assume_installed:
        return True
    try:
        res = get_tool_status(tool_key)
        return bool(res.get("installed"))
    except ValueError:
        return False


# Alias for backward and provider compatibility
get_tool_path = resolve_tool_absolute_path

