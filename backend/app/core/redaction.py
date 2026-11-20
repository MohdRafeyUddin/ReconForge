import re
from typing import List

# Patterns matching sensitive header keys
SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "token",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
    "secret",
}

# Regex to redact sensitive query parameter values in URLs or logs
SENSITIVE_PARAM_REGEX = re.compile(
    r"((?:token|api_key|apikey|secret|key|access_token|auth|password|passwd|bearer)=)([^&\s'\"]+)",
    re.IGNORECASE,
)

# Regex to redact Bearer tokens
BEARER_REGEX = re.compile(
    r"(Bearer\s+)[A-Za-z0-9_\-\.]{8,}",
    re.IGNORECASE,
)

# Regex for common secret/auth header lines in text
HEADER_LINE_REGEX = re.compile(
    r"((?:Authorization|Cookie|X-API-Key|ApiKey|Token|X-Auth-Token):\s*)([^\r\n]+)",
    re.IGNORECASE,
)

# Well-known secret formats that must never reach logs, WebSocket events,
# exports or API responses.
SECRET_VALUE_REGEXES = (
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
)

SENSITIVE_FLAG_NAMES = {
    "-token", "--token", "-itoken", "--itoken",
    "-interactsh-token", "--interactsh-token",
    "-oast-token", "--oast-token",
    "-secret", "--secret", "-secret-key", "--secret-key",
    "-key", "--key", "-api-key", "--api-key", "-apikey", "--apikey",
    "-api_key", "--api_key", "-access-key", "--access-key",
    "-client-token", "--client-token", "-auth", "--auth",
    "-password", "--password", "-pass", "--pass", "-pwd", "--pwd",
}


def redact_text(text: str) -> str:
    """Redacts sensitive tokens, credentials, and headers from arbitrary log strings."""
    if not text or not isinstance(text, str):
        return text

    # Redact Bearer tokens
    text = BEARER_REGEX.sub(r"\1[REDACTED]", text)

    # Redact query params
    text = SENSITIVE_PARAM_REGEX.sub(r"\1[REDACTED]", text)

    # Redact header lines
    def _header_repl(m):
        header_prefix = m.group(1)
        return f"{header_prefix}[REDACTED]"

    text = HEADER_LINE_REGEX.sub(_header_repl, text)

    # Redact well-known secret value formats anywhere in the text
    for secret_regex in SECRET_VALUE_REGEXES:
        text = secret_regex.sub("[REDACTED]", text)

    return text


def redact_payload(value):
    """Recursively redacts secret-like strings in events/log payloads."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if str(key).lower() in ("raw", "secret", "secret_value") else redact_payload(val))
            for key, val in value.items()
        }
    return value


def redact_cmd_args(args: List[str]) -> List[str]:
    """
    Safely redacts command line argument lists before printing to logs
    or broadcasting over WebSockets.
    """
    if not args:
        return []

    redacted: List[str] = []
    i = 0
    while i < len(args):
        arg = args[i]

        # Check header flags like -H, --header, --headers
        if arg in ("-H", "--header", "-header", "--headers") and i + 1 < len(args):
            next_arg = args[i + 1]
            if "\n" in next_arg:
                lines = next_arg.split("\n")
                redacted_lines = []
                for ln in lines:
                    if ":" in ln:
                        k, v = ln.split(":", 1)
                        if k.strip().lower() in SENSITIVE_HEADER_KEYS:
                            redacted_lines.append(f"{k.strip()}: [REDACTED]")
                            continue
                    redacted_lines.append(redact_text(ln))
                redacted.append(arg)
                redacted.append("\n".join(redacted_lines))
                i += 2
                continue
            elif ":" in next_arg:
                key, val = next_arg.split(":", 1)
                if key.strip().lower() in SENSITIVE_HEADER_KEYS:
                    redacted.append(arg)
                    redacted.append(f"{key.strip()}: [REDACTED]")
                    i += 2
                    continue
            redacted.append(arg)
            redacted.append(redact_text(next_arg))
            i += 2
            continue

        # Check cookie flags like -C, -cookie, --cookie
        if arg in ("-C", "-cookie", "--cookie") and i + 1 < len(args):
            redacted.append(arg)
            redacted.append("[REDACTED]")
            i += 2
            continue

        # --flag=value forms of secret-like flags
        if arg.startswith("-") and "=" in arg:
            flag = arg.split("=", 1)[0].lower()
            if flag in SENSITIVE_FLAG_NAMES:
                redacted.append(f"{arg.split('=', 1)[0]}=[REDACTED]")
                i += 1
                continue

        # Check token / secret flags
        if arg.lower() in SENSITIVE_FLAG_NAMES and i + 1 < len(args):
            redacted.append(arg)
            redacted.append("[REDACTED]")
            i += 2
            continue

        # Check single combined arguments like -H"Authorization: Bearer ..."
        if (arg.startswith("-H") or arg.startswith("--header=")) and ":" in arg:
            prefix, header_val = (arg.split("=", 1) if arg.startswith("--header=") else (arg[:2], arg[2:].lstrip()))
            if ":" in header_val:
                key, val = header_val.split(":", 1)
                if key.strip().lower() in SENSITIVE_HEADER_KEYS:
                    redacted.append(f"{prefix} \"{key.strip()}: [REDACTED]\"")
                    i += 1
                    continue

        # Redact general token patterns in arguments (e.g. URLs with ?token=...)
        redacted.append(redact_text(arg))
        i += 1

    return redacted


SECRET_METADATA_FORBIDDEN_KEYS = {
    "raw", "secret", "secret_value", "secretvalue", "match", "matched",
    "value", "token", "password", "credential", "credentials", "key",
    "private_key", "access_key", "payload",
}


def mask_secret_value(value: str, prefix_len: int = 4) -> str:
    """
    Returns a non-reversible display mask for a secret.

    Only a very short prefix is retained so operators can distinguish findings
    without exposing the credential. The full value is never returned.
    """
    if not value or not isinstance(value, str):
        return ""
    cleaned = value.strip()
    if not cleaned:
        return ""
    if len(cleaned) <= prefix_len:
        return "*" * len(cleaned)
    return f"{cleaned[:prefix_len]}{'*' * min(8, max(4, len(cleaned) - prefix_len))}"


def scrub_secret_metadata(metadata: dict) -> dict:
    """
    Defensive sanitizer for secret assets before persistence/broadcast.

    Removes keys that could contain a raw credential and forces any display
    prefix through mask_secret_value. Never raises.
    """
    if not isinstance(metadata, dict):
        return {}
    scrubbed = {}
    for key, val in metadata.items():
        key_l = str(key).lower()
        if key_l in SECRET_METADATA_FORBIDDEN_KEYS:
            continue
        if key_l in ("prefix", "masked_value", "masked", "masked_preview"):
            scrubbed[key] = mask_secret_value(str(val or ""))
            continue
        if isinstance(val, dict):
            scrubbed[key] = scrub_secret_metadata(val)
        elif isinstance(val, list):
            scrubbed[key] = [
                scrub_secret_metadata(v) if isinstance(v, dict)
                else redact_text(v) if isinstance(v, str)
                else v
                for v in val
            ]
        elif isinstance(val, str):
            scrubbed[key] = redact_text(val)
        else:
            scrubbed[key] = val
    return scrubbed
