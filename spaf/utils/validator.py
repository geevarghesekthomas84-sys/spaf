import re
import ipaddress
from urllib.parse import urlparse

# Reject scans that are accidentally (or maliciously) enormous. A target may be
# a single host or a modest network, never the whole internet. Default caps:
MAX_CIDR_HOSTS = 65536          # /16 for IPv4; anything larger is "overly broad"
MAX_PROMPT_CHARS = 4000         # agent goal / free-text payload cap
MAX_TARGET_CHARS = 253          # DNS name limit; URLs validated separately

# Regex for domain validation
DOMAIN_REGEX = re.compile(
    r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
    r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
)

def validate_domain(domain: str) -> bool:
    """
    Validates if a string is a valid domain name.
    """
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain))

def validate_ip(ip_str: str) -> bool:
    """
    Validates if a string is a valid IP address and not a restricted one.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # Reject loopback, link-local, private (optional, but often good for pentest tools)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        return True
    except ValueError:
        return False

def validate_target(target: str) -> bool:
    """
    Validates if a target is either a valid domain or a valid IP.
    """
    return validate_domain(target) or validate_ip(target)

def validate_url(url: str) -> bool:
    """
    Validates if a URL has a valid scheme (http/https) and netloc.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except Exception:
        return False

def sanitize_domain(domain: str) -> str:
    """
    Sanitizes domain input by removing protocol and trailing slashes.
    """
    domain = domain.lower().strip()
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    return domain.split('/')[0]


# ── Overly-broad / abusive input rejection ───────────────────────────────────
_WILDCARD_TARGETS = {"*", "0.0.0.0", "0.0.0.0/0", "::/0", "::", "any", "all",
                     "internet", "0/0"}


def is_overly_broad_target(target: str) -> bool:
    """
    True if a target would fan out far beyond a single engagement — a wildcard,
    the whole address space, or a CIDR larger than ``MAX_CIDR_HOSTS``.

    This is a guard against accidental or abusive mass scanning; it is independent
    of (and additional to) engagement-scope enforcement.
    """
    if not target:
        return True
    t = target.strip().lower()
    if t in _WILDCARD_TARGETS:
        return True
    # A bare CIDR: count the hosts it covers.
    try:
        net = ipaddress.ip_network(t, strict=False)
        return net.num_addresses > MAX_CIDR_HOSTS
    except ValueError:
        pass
    # A leading-dot or lone-TLD "domain" (".com", "com") is too broad.
    if t.startswith(".") or ("." not in t and not validate_ip(t)):
        # single label that isn't an IP (e.g. "com", "localhost") — reject as a
        # scan target; callers that want localhost use mock mode.
        return True
    return False


def validate_scan_target(target: str) -> tuple[bool, str]:
    """
    Gate a scan target at the input boundary.

    Returns ``(ok, reason)``. ``ok`` is False for empty, malformed, over-length,
    or overly-broad targets, with a human-readable reason.
    """
    if not target or not target.strip():
        return False, "empty target"
    t = target.strip()
    if len(t) > 2048:
        return False, "target too long"
    host = sanitize_domain(t) if "://" in t else t.split("/")[0]
    if is_overly_broad_target(t) or is_overly_broad_target(host):
        return False, "target is overly broad (wildcard or huge CIDR) — narrow it"
    if "://" in t:
        if not validate_url(t):
            return False, "malformed URL"
        return True, ""
    # bare host or CIDR
    try:
        ipaddress.ip_network(t, strict=False)
        return True, ""
    except ValueError:
        pass
    if validate_target(host):
        return True, ""
    return False, "not a valid domain, IP, URL, or CIDR"


def validate_prompt_payload(text: str, *, max_len: int = MAX_PROMPT_CHARS) -> tuple[bool, str]:
    """Reject free-text payloads (agent goals, notes) that are too long or binary."""
    if text is None:
        return True, ""
    if len(text) > max_len:
        return False, f"payload exceeds {max_len} characters"
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
        return False, "payload contains control characters"
    return True, ""
