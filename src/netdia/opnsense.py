from __future__ import annotations

import logging
from typing import Any

import httpx

from netdia.config import OPNsenseConfig
from netdia.models import WebsiteFinding

logger = logging.getLogger(__name__)


def _selected_value(field: Any) -> str | None:
    """Extract the selected value from an OPNsense dict-of-options field."""
    if isinstance(field, str):
        return field if field else None
    if isinstance(field, dict):
        for key, val in field.items():
            if isinstance(val, dict) and val.get("selected"):
                return key if key else None
    return None


class OPNsenseCaddyClient:
    def __init__(self, config: OPNsenseConfig):
        self.config = config

    def fetch_websites(self) -> list[WebsiteFinding]:
        if not self.config.enabled:
            return []
        auth = (self.config.key, self.config.secret)
        domains: dict[str, dict[str, Any]] = {}
        upstream_map: dict[str, str] = {}

        with httpx.Client(
            base_url=self.config.url,
            auth=auth,
            verify=self.config.verify_ssl,
            timeout=15.0,
        ) as client:
            # Get the full config which has both domains and handlers
            try:
                response = client.get("/api/caddy/reverse_proxy/get")
                response.raise_for_status()
                full_config = response.json()
                rp = full_config.get("caddy", {}).get("reverseproxy", {})

                # Walk all groups to find domains and handlers
                for group_key, group_val in rp.items():
                    if not isinstance(group_val, dict):
                        continue
                    for uuid, entry in group_val.items():
                        if not isinstance(entry, dict):
                            continue
                        # Domain entries have FromDomain
                        if "FromDomain" in entry and entry.get("enabled") == "1":
                            domains[uuid] = entry
                        # Handler entries have ToDomain and reverse (link to domain)
                        if "ToDomain" in entry:
                            to_ip = _selected_value(entry.get("ToDomain"))
                            to_port = entry.get("ToPort", "")
                            reverse_field = entry.get("reverse", {})
                            if to_ip and isinstance(reverse_field, dict):
                                upstream = f"{to_ip}:{to_port}" if to_port else to_ip
                                for domain_uuid in reverse_field:
                                    upstream_map[domain_uuid] = upstream

                logger.info(
                    "OPNsense full config: %d domains, %d handler mappings",
                    len(domains),
                    len(upstream_map),
                )
            except Exception as exc:
                logger.warning("Failed to fetch full caddy config: %s", exc)

            # Fallback to searchReverseProxy if full config failed
            if not domains:
                try:
                    response = client.post(
                        "/api/caddy/ReverseProxy/searchReverseProxy", json={}
                    )
                    response.raise_for_status()
                    payload = response.json()
                    for row in payload.get("rows", []):
                        if row.get("enabled") == "1" and row.get("FromDomain"):
                            domains[row.get("uuid", "")] = row
                    logger.info("searchReverseProxy fallback: %d domains", len(domains))
                except Exception as exc:
                    logger.warning("Failed to fetch reverse proxy list: %s", exc)

        results: list[WebsiteFinding] = []
        for uuid, row in domains.items():
            hostname = row.get("FromDomain")
            if not hostname:
                continue

            disable_tls = row.get("DisableTls")
            if isinstance(disable_tls, list):
                scheme = "http" if any(
                    item.get("selected") and "http://" in str(item.get("value", ""))
                    for item in disable_tls
                    if isinstance(item, dict)
                ) else "https"
            elif isinstance(disable_tls, str):
                scheme = "http" if disable_tls == "1" else "https"
            else:
                scheme = "https"

            description = row.get("description")
            if isinstance(description, dict):
                description = None

            upstream_target = upstream_map.get(uuid)
            results.append(
                WebsiteFinding(
                    hostname=hostname,
                    scheme=scheme,
                    source="opnsense_caddy",
                    title=description or None,
                    upstream_target=upstream_target,
                )
            )
            logger.info("Found Caddy site: %s -> %s", hostname, upstream_target)

        logger.info("OPNsense/Caddy: returning %d websites", len(results))
        return results
