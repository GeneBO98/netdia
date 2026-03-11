from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from collections import defaultdict
from collections.abc import Iterable
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netdia.classification import color_for_category, icon_for_category


def utcnow() -> str:
    return datetime.now(UTC).isoformat()


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    @contextmanager
    def connect(self):
        with self._lock:
            connection = self._get_connection()
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def init(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cidr TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    settings_json TEXT NOT NULL,
                    error_summary TEXT,
                    stage TEXT,
                    status_message TEXT,
                    progress_current INTEGER NOT NULL DEFAULT 0,
                    progress_total INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    mac_address TEXT,
                    dns_name TEXT,
                    os_guess TEXT,
                    category TEXT NOT NULL,
                    display_name_override TEXT,
                    icon_override TEXT,
                    category_override TEXT,
                    last_seen_scan_id INTEGER,
                    FOREIGN KEY(last_seen_scan_id) REFERENCES scan_runs(id)
                );

                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    scan_run_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service_name TEXT,
                    product TEXT,
                    version TEXT,
                    extrainfo TEXT,
                    category TEXT NOT NULL,
                    icon TEXT NOT NULL,
                    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE,
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
                    UNIQUE(host_id, scan_run_id, port, protocol)
                );

                CREATE TABLE IF NOT EXISTS service_overrides (
                    host_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    display_name_override TEXT,
                    icon_override TEXT,
                    category_override TEXT,
                    PRIMARY KEY(host_id, port, protocol),
                    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS websites (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_id INTEGER,
                    scan_run_id INTEGER NOT NULL,
                    hostname TEXT NOT NULL,
                    scheme TEXT NOT NULL,
                    source TEXT NOT NULL,
                    title TEXT,
                    server_header TEXT,
                    redirect_target TEXT,
                    tls_names_json TEXT NOT NULL,
                    upstream_target TEXT,
                    favicon_url TEXT,
                    FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL,
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
                    UNIQUE(service_id, scan_run_id, hostname, scheme, source)
                );

                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    level TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
                );
                """
            )
            self._ensure_scan_run_columns(connection)
            self._ensure_website_columns(connection)

    def _ensure_scan_run_columns(self, connection: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(scan_runs)").fetchall()
        }
        additions = {
            "stage": "ALTER TABLE scan_runs ADD COLUMN stage TEXT",
            "status_message": "ALTER TABLE scan_runs ADD COLUMN status_message TEXT",
            "progress_current": "ALTER TABLE scan_runs ADD COLUMN progress_current INTEGER NOT NULL DEFAULT 0",
            "progress_total": "ALTER TABLE scan_runs ADD COLUMN progress_total INTEGER NOT NULL DEFAULT 0",
        }
        for name, statement in additions.items():
            if name not in columns:
                connection.execute(statement)

    def _ensure_website_columns(self, connection: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(websites)").fetchall()
        }
        if "favicon_url" not in columns:
            connection.execute("ALTER TABLE websites ADD COLUMN favicon_url TEXT")

    def ensure_default_target(self) -> None:
        with self.connect() as connection:
            count = connection.execute("SELECT COUNT(*) AS count FROM scan_targets").fetchone()["count"]
            if count == 0:
                connection.execute(
                    "INSERT INTO scan_targets (cidr, enabled, created_at) VALUES (?, ?, ?)",
                    ("192.168.1.0/24", 1, utcnow()),
                )

    def reconcile_incomplete_scans(self) -> None:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, status
                FROM scan_runs
                WHERE status IN ('queued', 'running', 'cancelling')
                ORDER BY id
                """
            ).fetchall()
        for row in rows:
            scan_id = int(row["id"])
            status = str(row["status"])
            if status == "cancelling":
                self.update_scan_run(
                    scan_id,
                    status="cancelled",
                    stage="cancelled",
                    status_message="Marked cancelled after server restart",
                    finished=True,
                )
                self.add_scan_event(
                    scan_id,
                    level="warning",
                    stage="cancelled",
                    message="Marked cancelled after server restart",
                )
            else:
                self.update_scan_run(
                    scan_id,
                    status="failed",
                    stage="failed",
                    status_message="Scan interrupted by server restart",
                    error_summary="Server restarted while scan was in progress",
                    finished=True,
                )
                self.add_scan_event(
                    scan_id,
                    level="warning",
                    stage="failed",
                    message="Scan interrupted by server restart",
                )

    def list_targets(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM scan_targets ORDER BY cidr").fetchall()
        return [dict(row) for row in rows]

    def add_target(self, cidr: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO scan_targets (cidr, enabled, created_at) VALUES (?, ?, ?)",
                (cidr, 1, utcnow()),
            )
            row = connection.execute("SELECT * FROM scan_targets WHERE cidr = ?", (cidr,)).fetchone()
        return dict(row)

    def update_target(self, target_id: int, enabled: bool) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute(
                "UPDATE scan_targets SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, target_id),
            )
            row = connection.execute("SELECT * FROM scan_targets WHERE id = ?", (target_id,)).fetchone()
        return dict(row)

    def delete_target(self, target_id: int) -> bool:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM scan_targets WHERE id = ?", (target_id,))
        return cursor.rowcount > 0

    def enabled_cidrs(self) -> list[str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT cidr FROM scan_targets WHERE enabled = 1 ORDER BY cidr"
            ).fetchall()
        return [row["cidr"] for row in rows]

    def create_scan_run(self, settings: dict[str, Any]) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scan_runs (
                    status, started_at, settings_json, stage, status_message, progress_current, progress_total
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                ("queued", utcnow(), json.dumps(settings), "queued", "Queued scan", 0, 0),
            )
            scan_id = int(cursor.lastrowid)
        self.add_scan_event(scan_id, level="info", stage="queued", message="Scan queued", metadata=settings)
        return scan_id

    def update_scan_run(
        self,
        scan_id: int,
        *,
        status: str,
        error_summary: str | None = None,
        finished: bool = False,
        stage: str | None = None,
        status_message: str | None = None,
        progress_current: int | None = None,
        progress_total: int | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE scan_runs
                SET
                    status = ?,
                    error_summary = ?,
                    stage = COALESCE(?, stage),
                    status_message = COALESCE(?, status_message),
                    progress_current = COALESCE(?, progress_current),
                    progress_total = COALESCE(?, progress_total),
                    finished_at = CASE WHEN ? THEN ? ELSE finished_at END
                WHERE id = ?
                """,
                (
                    status,
                    error_summary,
                    stage,
                    status_message,
                    progress_current,
                    progress_total,
                    1 if finished else 0,
                    utcnow(),
                    scan_id,
                ),
            )

    def add_scan_event(
        self,
        scan_id: int,
        *,
        level: str,
        stage: str,
        message: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO scan_events (scan_run_id, created_at, level, stage, message, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, utcnow(), level, stage, message, json.dumps(metadata or {})),
            )

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM scan_runs WHERE id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            counts = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM hosts WHERE last_seen_scan_id = ?) AS hosts,
                    (SELECT COUNT(*) FROM services WHERE scan_run_id = ?) AS services,
                    (SELECT COUNT(*) FROM websites WHERE scan_run_id = ?) AS websites
                """,
                (scan_id, scan_id, scan_id),
            ).fetchone()
        payload = dict(row)
        payload.update(dict(counts))
        payload["settings"] = json.loads(payload.pop("settings_json"))
        return payload

    def list_scan_events(self, scan_id: int, limit: int = 250) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM scan_events
                WHERE scan_run_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (scan_id, limit),
            ).fetchall()
        payload = []
        for row in reversed(rows):
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            payload.append(item)
        return payload

    def latest_scan(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id FROM scan_runs WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return self.get_scan(int(row["id"]))

    def latest_scan_run(self) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT id FROM scan_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return self.get_scan(int(row["id"]))

    def upsert_host(
        self,
        scan_id: int,
        *,
        ip: str,
        mac_address: str | None,
        dns_name: str | None,
        os_guess: str | None,
        category: str,
    ) -> int:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO hosts (ip, mac_address, dns_name, os_guess, category, last_seen_scan_id)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac_address = excluded.mac_address,
                    dns_name = excluded.dns_name,
                    os_guess = excluded.os_guess,
                    category = excluded.category,
                    last_seen_scan_id = excluded.last_seen_scan_id
                """,
                (ip, mac_address, dns_name, os_guess, category, scan_id),
            )
            row = connection.execute("SELECT id FROM hosts WHERE ip = ?", (ip,)).fetchone()
        return int(row["id"])

    def insert_service(
        self,
        scan_id: int,
        *,
        host_id: int,
        port: int,
        protocol: str,
        state: str,
        service_name: str | None,
        product: str | None,
        version: str | None,
        extrainfo: str | None,
        category: str,
        icon: str,
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO services (
                    host_id, scan_run_id, port, protocol, state, service_name, product,
                    version, extrainfo, category, icon
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host_id,
                    scan_id,
                    port,
                    protocol,
                    state,
                    service_name,
                    product,
                    version,
                    extrainfo,
                    category,
                    icon,
                ),
            )
            return int(cursor.lastrowid)

    def insert_website(
        self,
        scan_id: int,
        *,
        service_id: int | None,
        hostname: str,
        scheme: str,
        source: str,
        title: str | None,
        server_header: str | None,
        redirect_target: str | None,
        tls_names: list[str],
        upstream_target: str | None,
        favicon_url: str | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO websites (
                    service_id, scan_run_id, hostname, scheme, source, title,
                    server_header, redirect_target, tls_names_json, upstream_target,
                    favicon_url
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    service_id,
                    scan_id,
                    hostname,
                    scheme,
                    source,
                    title,
                    server_header,
                    redirect_target,
                    json.dumps(sorted(set(tls_names))),
                    upstream_target,
                    favicon_url,
                ),
            )

    def update_host_override(
        self,
        host_id: int,
        *,
        display_name: str | None,
        icon: str | None,
        category: str | None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE hosts
                SET display_name_override = ?, icon_override = ?, category_override = ?
                WHERE id = ?
                """,
                (display_name, icon, category, host_id),
            )

    def update_service_override(
        self,
        host_id: int,
        port: int,
        protocol: str,
        *,
        display_name: str | None,
        icon: str | None,
        category: str | None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO service_overrides (
                    host_id, port, protocol, display_name_override, icon_override, category_override
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id, port, protocol) DO UPDATE SET
                    display_name_override = excluded.display_name_override,
                    icon_override = excluded.icon_override,
                    category_override = excluded.category_override
                """,
                (host_id, port, protocol, display_name, icon, category),
            )

    def host_detail(self, host_id: int) -> dict[str, Any] | None:
        latest = self.latest_scan()
        if latest is None:
            return None
        scan_id = latest["id"]
        with self.connect() as connection:
            host = connection.execute(
                "SELECT * FROM hosts WHERE id = ? AND last_seen_scan_id = ?",
                (host_id, scan_id),
            ).fetchone()
            if host is None:
                return None
            services = connection.execute(
                """
                SELECT s.*, so.display_name_override, so.icon_override, so.category_override
                FROM services s
                LEFT JOIN service_overrides so
                    ON so.host_id = s.host_id AND so.port = s.port AND so.protocol = s.protocol
                WHERE s.host_id = ? AND s.scan_run_id = ?
                ORDER BY s.port
                """,
                (host_id, scan_id),
            ).fetchall()
            websites = connection.execute(
                """
                SELECT w.*
                FROM websites w
                LEFT JOIN services s ON s.id = w.service_id
                WHERE w.scan_run_id = ? AND (s.host_id = ? OR w.service_id IS NULL)
                ORDER BY w.hostname
                """,
                (scan_id, host_id),
            ).fetchall()
        host_payload = dict(host)
        host_payload["label"] = host_payload["display_name_override"] or host_payload["dns_name"] or host_payload["ip"]
        host_payload["category"] = host_payload["category_override"] or host_payload["category"]
        host_payload["icon"] = host_payload["icon_override"] or icon_for_category(host_payload["category"])
        host_payload["services"] = []
        for service in services:
            item = dict(service)
            item["display_name"] = item["display_name_override"] or item["service_name"] or f"{item['protocol']}/{item['port']}"
            item["category"] = item["category_override"] or item["category"]
            item["icon"] = item["icon_override"] or item["icon"]
            host_payload["services"].append(item)
        host_payload["websites"] = []
        for website in websites:
            item = dict(website)
            item["tls_names"] = json.loads(item.pop("tls_names_json"))
            host_payload["websites"].append(item)
        return host_payload

    def list_websites(self) -> list[dict[str, Any]]:
        latest = self.latest_scan()
        if latest is None:
            return []
        scan_id = latest["id"]
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    w.*,
                    h.ip,
                    h.dns_name,
                    s.port,
                    s.protocol
                FROM websites w
                LEFT JOIN services s ON s.id = w.service_id
                LEFT JOIN hosts h ON h.id = s.host_id
                WHERE w.scan_run_id = ?
                ORDER BY w.hostname
                """,
                (scan_id,),
            ).fetchall()
        payload = []
        for row in rows:
            item = dict(row)
            item["tls_names"] = json.loads(item.pop("tls_names_json"))
            payload.append(item)
        return payload

    def topology(self) -> dict[str, Any]:
        latest = self.latest_scan()
        if latest is None:
            return {"latest_scan": None, "subnets": [], "caddy_sites": [], "inventory": []}
        scan_id = latest["id"]
        with self.connect() as connection:
            hosts = connection.execute(
                "SELECT * FROM hosts WHERE last_seen_scan_id = ? ORDER BY ip",
                (scan_id,),
            ).fetchall()
            services = connection.execute(
                """
                SELECT s.*, h.ip, h.dns_name, so.display_name_override, so.icon_override, so.category_override
                FROM services s
                JOIN hosts h ON h.id = s.host_id
                LEFT JOIN service_overrides so
                    ON so.host_id = s.host_id AND so.port = s.port AND so.protocol = s.protocol
                WHERE s.scan_run_id = ?
                ORDER BY h.ip, s.port
                """,
                (scan_id,),
            ).fetchall()
            websites = connection.execute(
                """
                SELECT w.*, s.host_id, s.port, s.protocol, h.ip
                FROM websites w
                LEFT JOIN services s ON s.id = w.service_id
                LEFT JOIN hosts h ON h.id = s.host_id
                WHERE w.scan_run_id = ?
                ORDER BY w.hostname
                """,
                (scan_id,),
            ).fetchall()

        # Build lookup structures
        services_by_host: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
        websites_by_host: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
        caddy_sites: list[dict[str, Any]] = []
        inventory: list[dict[str, Any]] = []
        websites_by_service: defaultdict[int | None, list[str]] = defaultdict(list)

        for website in websites:
            websites_by_service[website["service_id"]].append(website["hostname"])

        # Index services by host
        for service in services:
            category = service["category_override"] or service["category"]
            icon = service["icon_override"] or service["icon"]
            label = service["display_name_override"] or service["service_name"] or f"{service['protocol']}/{service['port']}"
            services_by_host[service["host_id"]].append({
                "id": service["id"],
                "port": service["port"],
                "protocol": service["protocol"],
                "label": label,
                "product": service["product"],
                "version": service["version"],
            })
            inventory.append({
                "host_id": service["host_id"],
                "ip": service["ip"],
                "dns_name": service["dns_name"],
                "port": service["port"],
                "protocol": service["protocol"],
                "service_name": label,
                "product": service["product"],
                "websites": sorted(websites_by_service.get(service["id"], [])),
            })

        # Map service_id -> host_id for website association
        service_host_map: dict[int, int] = {}
        for service in services:
            service_host_map[service["id"]] = service["host_id"]

        # Index websites by host, separate caddy orphans
        for website in websites:
            w_data = {
                "id": website["id"],
                "hostname": website["hostname"],
                "scheme": website["scheme"],
                "title": website["title"],
                "favicon_url": website["favicon_url"] if "favicon_url" in website.keys() else None,
                "source": website["source"],
                "upstream_target": website["upstream_target"],
            }
            if website["service_id"] and website["service_id"] in service_host_map:
                host_id = service_host_map[website["service_id"]]
                websites_by_host[host_id].append(w_data)
            elif website["source"] == "opnsense_caddy":
                caddy_sites.append(w_data)
            elif website["host_id"]:
                websites_by_host[website["host_id"]].append(w_data)

        # Group hosts by subnet
        subnet_map: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for host in hosts:
            category = host["category_override"] or host["category"]
            label = host["display_name_override"] or host["dns_name"] or host["ip"]
            icon = host["icon_override"] or icon_for_category(category)
            color = color_for_category(category)
            subnet = ".".join(host["ip"].split(".")[:3]) + ".0/24" if "." in host["ip"] else "network"
            host_data = {
                "id": host["id"],
                "ip": host["ip"],
                "label": label,
                "category": category,
                "icon": icon,
                "color": color,
                "mac_address": host["mac_address"],
                "os_guess": host["os_guess"],
                "services": services_by_host.get(host["id"], []),
                "websites": websites_by_host.get(host["id"], []),
            }
            subnet_map[subnet].append(host_data)

        subnets = [
            {"cidr": cidr, "hosts": host_list}
            for cidr, host_list in sorted(subnet_map.items())
        ]

        return {
            "latest_scan": latest,
            "subnets": subnets,
            "caddy_sites": caddy_sites,
            "inventory": inventory,
        }

    def preferred_reverse_proxy_service(self, scan_id: int) -> int | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT s.id
                FROM services s
                JOIN hosts h ON h.id = s.host_id
                WHERE s.scan_run_id = ? AND s.port IN (80, 443, 2019)
                ORDER BY CASE WHEN h.category = 'firewall' THEN 0 ELSE 1 END, s.port DESC
                LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
        return None if row is None else int(row["id"])

    def latest_service_id_for_endpoint(self, scan_id: int, endpoint: str | None) -> int | None:
        if not endpoint or ":" not in endpoint:
            return None
        host, raw_port = endpoint.rsplit(":", 1)
        if not raw_port.isdigit():
            return None
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT s.id
                FROM services s
                JOIN hosts h ON h.id = s.host_id
                WHERE s.scan_run_id = ? AND h.ip = ? AND s.port = ?
                LIMIT 1
                """,
                (scan_id, host, int(raw_port)),
            ).fetchone()
        return None if row is None else int(row["id"])
