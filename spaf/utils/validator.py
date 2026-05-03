import re
import ipaddress
from urllib.parse import urlparse

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
