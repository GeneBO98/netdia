from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from urllib.parse import urlparse

import httpx

from netdia.models import WebsiteFinding


TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
FAVICON_RE = re.compile(
    r"""<link[^>]+rel=["'](?:shortcut\s+icon|icon)["'][^>]+href=["']([^"']+)["']""",
    re.IGNORECASE,
)
FAVICON_RE_ALT = re.compile(
    r"""<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut\s+icon|icon)["']""",
    re.IGNORECASE,
)
LIKELY_WEB_PORTS = {80, 81, 443, 444, 591, 8000, 8080, 8081, 8443, 8888, 9000, 5000, 3000}


def safe_reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_title(html: str) -> str | None:
    match = TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def extract_favicon(html: str, base_url: str) -> str | None:
    """Extract favicon URL from HTML link tags."""
    match = FAVICON_RE.search(html) or FAVICON_RE_ALT.search(html)
    if not match:
        return None
    href = match.group(1)
    if href.startswith("http://") or href.startswith("https://"):
        return href
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        origin += f":{parsed.port}"
    if href.startswith("//"):
        return f"{parsed.scheme}:{href}"
    if href.startswith("/"):
        return f"{origin}{href}"
    return f"{origin}/{href}"


def extract_tls_names_from_cert(cert: dict[str, object]) -> list[str]:
    names: set[str] = set()
    for item in cert.get("subjectAltName", []):
        if isinstance(item, tuple) and len(item) == 2 and item[0] == "DNS":
            names.add(str(item[1]).strip())
    for rdn in cert.get("subject", []):
        if not isinstance(rdn, (list, tuple)):
            continue
        for entry in rdn:
            if isinstance(entry, tuple) and len(entry) == 2:
                key, value = entry
                if key == "commonName":
                    names.add(str(value).strip())
    return sorted(name for name in names if name)


def fetch_tls_names(ip: str, port: int, timeout: float = 4.0) -> list[str]:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
            certificate = secure_sock.getpeercert()
    return extract_tls_names_from_cert(certificate)


def should_probe_web(service_name: str | None, port: int) -> bool:
    normalized = (service_name or "").lower()
    return port in LIKELY_WEB_PORTS or "http" in normalized or "ssl" in normalized or "caddy" in normalized


def probe_http_service(ip: str, port: int, service_name: str | None = None) -> list[WebsiteFinding]:
    findings: list[WebsiteFinding] = []
    if not should_probe_web(service_name, port):
        return findings

    if port in {443, 8443} or "https" in (service_name or "").lower():
        schemes = ["https", "http"]
    else:
        schemes = ["http", "https"]

    tls_names: list[str] = []
    if "https" in schemes:
        try:
            tls_names = fetch_tls_names(ip, port)
        except OSError:
            tls_names = []

    for scheme in schemes:
        url = f"{scheme}://{ip}:{port}"
        try:
            with httpx.Client(
                follow_redirects=True,
                verify=False,
                timeout=5.0,
                headers={"User-Agent": "Netdia/0.1"},
            ) as client:
                response = client.get(url)
        except httpx.HTTPError:
            continue

        final_url = str(response.url)
        final_host = urlparse(final_url).hostname or ip
        html = response.text
        title = extract_title(html)
        favicon_url = extract_favicon(html, final_url)
        redirect_target = final_url if final_url != url else None
        server_header = response.headers.get("server")

        findings.append(
            WebsiteFinding(
                hostname=final_host,
                scheme=scheme,
                source="http_probe",
                title=title,
                server_header=server_header,
                redirect_target=redirect_target,
                tls_names=tls_names,
                favicon_url=favicon_url,
            )
        )
        for name in tls_names:
            findings.append(
                WebsiteFinding(
                    hostname=name,
                    scheme="https",
                    source="tls_san",
                    server_header=server_header,
                    tls_names=tls_names,
                )
            )
        break

    deduped: dict[tuple[str, str, str], WebsiteFinding] = {}
    for finding in findings:
        key = (finding.hostname, finding.scheme, finding.source)
        if key not in deduped:
            deduped[key] = finding
    return list(deduped.values())


def probe_caddy_domain(hostname: str, scheme: str = "https") -> tuple[str | None, str | None]:
    """Probe a Caddy domain to get its page title and favicon URL.
    Returns (title, favicon_url)."""
    try:
        url = f"{scheme}://{hostname}"
        with httpx.Client(
            follow_redirects=True,
            verify=False,
            timeout=5.0,
            headers={"User-Agent": "Netdia/0.1"},
        ) as client:
            response = client.get(url)

        html = response.text
        title = extract_title(html)
        favicon_url = extract_favicon(html, str(response.url))

        # Fall back to /favicon.ico if no link tag found
        if not favicon_url:
            try:
                fallback = f"{url}/favicon.ico"
                with httpx.Client(
                    follow_redirects=True,
                    verify=False,
                    timeout=5.0,
                    headers={"User-Agent": "Netdia/0.1"},
                ) as head_client:
                    head_resp = head_client.head(fallback)
                if head_resp.status_code < 400:
                    favicon_url = fallback
            except Exception:
                pass

        return (title, favicon_url)
    except Exception:
        return (None, None)
