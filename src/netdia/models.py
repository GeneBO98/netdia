from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class DiscoveredHost:
    ip: str
    mac_address: str | None = None
    dns_name: str | None = None
    os_guess: str | None = None


@dataclass(slots=True)
class DiscoveredService:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None


@dataclass(slots=True)
class ScannedHost:
    ip: str
    mac_address: str | None = None
    dns_name: str | None = None
    os_guess: str | None = None
    services: list[DiscoveredService] = field(default_factory=list)


@dataclass(slots=True)
class WebsiteFinding:
    hostname: str
    scheme: str
    source: str
    title: str | None = None
    server_header: str | None = None
    redirect_target: str | None = None
    tls_names: list[str] = field(default_factory=list)
    upstream_target: str | None = None
    favicon_url: str | None = None


@dataclass(slots=True)
class ScanSummary:
    scan_id: int
    hosts: int
    services: int
    websites: int
