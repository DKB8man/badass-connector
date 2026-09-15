"""Proxy diagnostics for direct runner-to-target requests."""

from urllib import request as urllib_request
from urllib.parse import urlparse


def bypassed_system_proxy_note(url: str) -> str:
    """Describe a relevant system proxy without exposing its URL or credentials."""
    try:
        proxies = urllib_request.getproxies()
    except Exception:
        return ""

    scheme = urlparse(url).scheme.lower()
    if not scheme or not any(proxies.get(key) for key in (scheme, "all")):
        return ""

    return (
        " System proxy settings were detected for this URL but were bypassed; "
        "the runner attempted a direct connection to the target."
    )