"""Input validation helpers shared by the UI and the scanners.

Kept free of Qt imports so the logic can be unit-tested without a display.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

# nmap options that write files or load code from disk. A free-text "custom
# flags" box plus these equals arbitrary file write / local script execution.
FORBIDDEN_NMAP_OPTIONS = frozenset({
    "-oN", "-oX", "-oG", "-oS", "-oA", "-iL",
    "--datadir", "--servicedb", "--versiondb", "--script-args-file",
    "--stylesheet", "--resume", "--excludefile",
})

# A target is never a shell string, so these have no business being there.
FORBIDDEN_CHARS = frozenset(";|&`$()<>\\\n\r\t")

HOSTNAME_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9\-]{1,63}(?:\.[a-zA-Z0-9\-]{1,63})*\.?$"
)
IP_RANGE_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")


class InvalidFlags(ValueError):
    """Raised when custom nmap flags are unsafe or malformed."""


def is_valid_target(text: str) -> bool:
    """True for an IP, a CIDR block, an IP range or a plausible hostname."""
    text = (text or "").strip()
    if not text or any(ch.isspace() for ch in text):
        return False
    if text.startswith("-") or any(ch in FORBIDDEN_CHARS for ch in text):
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(text, strict=False)
        return True
    except ValueError:
        pass
    if IP_RANGE_RE.match(text):
        return True
    if HOSTNAME_RE.match(text):
        return not text.isdigit()
    return False


def sanitize_custom_flags(text: str) -> list[str]:
    """Split free-text nmap flags into argv tokens, refusing unsafe ones.

    Raises InvalidFlags instead of silently dropping the offending token so the
    user sees why the scan did not start.
    """
    text = (text or "").strip()
    if not text:
        return []
    for ch in text:
        if ch in FORBIDDEN_CHARS:
            raise InvalidFlags(
                "shell metacharacters are not allowed in custom flags"
            )
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise InvalidFlags(f"unbalanced quotes: {exc}") from exc

    for token in tokens:
        option = token.split("=", 1)[0]
        if option in FORBIDDEN_NMAP_OPTIONS:
            raise InvalidFlags(f"{option} is not allowed in custom flags")
        if option == "--script" and "=" in token:
            raise InvalidFlags(
                "use the script checkboxes instead of --script=<file>"
            )
        if "/" in token:
            raise InvalidFlags("paths are not allowed in custom flags")
    return tokens
