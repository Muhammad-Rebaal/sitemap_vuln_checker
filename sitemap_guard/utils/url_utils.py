"""
URL normalization, deduplication, and scope enforcement utilities.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication.

    - Lowercases scheme and host
    - Removes fragments
    - Removes trailing slash (except root)
    - Sorts query parameters
    - Removes default ports (80, 443)
    """
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Remove default ports
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]

    # Normalize path
    path = parsed.path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    if not path:
        path = "/"

    # Sort query parameters
    query = parsed.query
    if query:
        params = parse_qs(query, keep_blank_values=True)
        sorted_params = sorted(params.items())
        query = urlencode(sorted_params, doseq=True)

    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def is_same_domain(url: str, base_domain: str, allow_subdomains: bool = False) -> bool:
    """Check if a URL belongs to the same domain scope."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower().split(":")[0]
        if allow_subdomains:
            return host == base_domain or host.endswith(f".{base_domain}")
        return host == base_domain
    except Exception:
        return False


def extract_domain(url: str) -> str:
    """Extract the domain from a URL."""
    parsed = urlparse(url)
    return parsed.netloc.lower().split(":")[0]


def resolve_url(base_url: str, relative_url: str) -> str:
    """Resolve a relative URL against a base URL."""
    return urljoin(base_url, relative_url)


def is_valid_http_url(url: str) -> bool:
    """Check if a URL is a valid HTTP/HTTPS URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


# Pre-built sets for fast lookup (avoid re-creating each call)
_SKIP_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".ogg",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".css", ".js", ".json", ".xml", ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".dmg", ".apk", ".iso", ".map",
})

_SKIP_SCHEMES = frozenset({"mailto:", "tel:", "javascript:", "data:", "ftp:", "file:"})


def should_skip_url(url: str) -> bool:
    """Check if a URL should be skipped during crawling."""
    url_lower = url.lower()

    for scheme in _SKIP_SCHEMES:
        if url_lower.startswith(scheme):
            return True

    path = urlparse(url_lower).path
    # Fast extension check: find last dot
    dot_idx = path.rfind(".")
    if dot_idx != -1:
        ext = path[dot_idx:]
        if ext in _SKIP_EXTENSIONS:
            return True

    return False


def get_url_path(url: str) -> str:
    """Extract just the path component from a URL."""
    return urlparse(url).path
