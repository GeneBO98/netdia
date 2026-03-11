from __future__ import annotations

from collections.abc import Iterable


HOST_CATEGORY_ICONS = {
    "firewall": "shield",
    "wireless": "wifi",
    "server": "server",
    "storage": "database",
    "reverse_proxy": "route",
    "database": "cylinder",
    "media": "play",
    "generic": "grid",
    "website": "globe",
}

HOST_CATEGORY_COLORS = {
    "firewall": "#e76f51",
    "wireless": "#f4a261",
    "server": "#2a9d8f",
    "storage": "#264653",
    "reverse_proxy": "#287271",
    "database": "#6d597a",
    "media": "#7f5539",
    "generic": "#577590",
    "website": "#457b9d",
}


def classify_host(service_names: Iterable[str], ports: Iterable[int], os_guess: str | None = None) -> str:
    names = {name.lower() for name in service_names if name}
    port_set = set(ports)
    os_guess = (os_guess or "").lower()

    if {53, 67, 68}.intersection(port_set) or "opnsense" in os_guess or "router" in os_guess:
        return "firewall"
    if {554, 32400, 8096}.intersection(port_set):
        return "media"
    if {445, 2049, 111}.intersection(port_set):
        return "storage"
    if any(name in names for name in {"mysql", "postgresql", "mongodb", "redis", "postgres"}):
        return "database"
    if {80, 443}.intersection(port_set) and any(name in names for name in {"http", "https", "caddy", "nginx", "traefik"}):
        return "reverse_proxy"
    if {22, 80, 443}.intersection(port_set):
        return "server"
    return "generic"


def classify_service(service_name: str | None, port: int, product: str | None = None) -> str:
    value = " ".join(part for part in [service_name or "", product or ""] if part).lower()
    if "http" in value or "caddy" in value or "nginx" in value or port in {80, 443, 8080, 8443, 8000, 5000, 3000}:
        return "reverse_proxy"
    if any(token in value for token in {"mysql", "postgres", "redis", "mongodb"}):
        return "database"
    if port in {445, 2049, 111}:
        return "storage"
    if port in {32400, 8096, 554}:
        return "media"
    return "generic"


def icon_for_category(category: str) -> str:
    return HOST_CATEGORY_ICONS.get(category, HOST_CATEGORY_ICONS["generic"])


def color_for_category(category: str) -> str:
    return HOST_CATEGORY_COLORS.get(category, HOST_CATEGORY_COLORS["generic"])
