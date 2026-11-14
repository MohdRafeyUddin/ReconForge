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

    return text


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

        # Check token / secret flags
        if arg in ("-token", "--token", "-secret", "--secret", "-key", "--key", "-api-key") and i + 1 < len(args):
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
