from __future__ import annotations

import ipaddress
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import threading

from netdia.classification import classify_host, classify_service, icon_for_category
from netdia.config import Settings
from netdia.database import Database
from netdia.enrichment import probe_caddy_domain, probe_http_service, safe_reverse_dns
from netdia.models import ScanSummary
from netdia.nmap_runner import NmapScanner, ScanCancelledError
from netdia.opnsense import OPNsenseCaddyClient


class ScanManager:
    def __init__(self, settings: Settings, database: Database):
        self.settings = settings
        self.database = database
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="netdia-scan")
        self.jobs: dict[int, Future[ScanSummary]] = {}
        self._lock = threading.Lock()
        self.active_scanners: dict[int, NmapScanner] = {}
        self.cancel_requests: set[int] = set()

    def start_scan(self, cidrs: list[str] | None = None) -> int:
        scan_targets = cidrs or self.database.enabled_cidrs()
        scan_id = self.database.create_scan_run({"cidrs": scan_targets})
        future = self.executor.submit(self.run_scan, scan_id, scan_targets)
        self.jobs[scan_id] = future
        return scan_id

    def _set_scanner(self, scan_id: int, scanner: NmapScanner | None) -> None:
        with self._lock:
            if scanner is None:
                self.active_scanners.pop(scan_id, None)
            else:
                self.active_scanners[scan_id] = scanner

    def cancel_scan(self, scan_id: int) -> dict[str, object] | None:
        scan = self.database.get_scan(scan_id)
        if scan is None:
            return None
        if scan["status"] in {"completed", "failed", "cancelled"}:
            return scan
        with self._lock:
            self.cancel_requests.add(scan_id)
            scanner = self.active_scanners.get(scan_id)
            future = self.jobs.get(scan_id)
        if future is not None and future.cancel():
            self.database.update_scan_run(
                scan_id,
                status="cancelled",
                stage="cancelled",
                status_message="Scan cancelled before it started",
                finished=True,
            )
            self.database.add_scan_event(
                scan_id,
                level="warning",
                stage="cancelled",
                message="Scan cancelled before start",
            )
            with self._lock:
                self.cancel_requests.discard(scan_id)
            return self.database.get_scan(scan_id)
        if scanner is not None:
            scanner.cancel()
        self.database.update_scan_run(
            scan_id,
            status="cancelling",
            stage="cancelling",
            status_message="Cancelling scan...",
        )
        self.database.add_scan_event(
            scan_id,
            level="warning",
            stage="cancelling",
            message="Cancellation requested",
        )
        return self.database.get_scan(scan_id)

    def _is_cancel_requested(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self.cancel_requests

    def _raise_if_cancelled(self, scan_id: int) -> None:
        if self._is_cancel_requested(scan_id):
            raise ScanCancelledError("Scan cancelled")

    def _progress(
        self,
        scan_id: int,
        *,
        stage: str,
        message: str,
        progress_current: int | None = None,
        progress_total: int | None = None,
        level: str = "info",
        metadata: dict[str, object] | None = None,
    ) -> None:
        self._raise_if_cancelled(scan_id)
        self.database.update_scan_run(
            scan_id,
            status="running",
            stage=stage,
            status_message=message,
            progress_current=progress_current,
            progress_total=progress_total,
        )
        self.database.add_scan_event(
            scan_id,
            level=level,
            stage=stage,
            message=message,
            metadata=metadata,
        )

    def run_scan(self, scan_id: int, cidrs: list[str] | None = None) -> ScanSummary:
        scan_targets = cidrs or self.database.enabled_cidrs()
        try:
            self._progress(
                scan_id,
                stage="discovering",
                message=f"Discovering active hosts in {', '.join(scan_targets)}",
                progress_current=0,
                progress_total=0,
                metadata={"cidrs": scan_targets},
            )
            scanner = NmapScanner()
            self._set_scanner(scan_id, scanner)
            opnsense_client = OPNsenseCaddyClient(self.settings.opnsense)
            discovered = scanner.discover(scan_targets)
            self._raise_if_cancelled(scan_id)
            discovered_hosts = [host.ip for host in discovered]
            self._progress(
                scan_id,
                stage="scanning_hosts",
                message=f"Discovered {len(discovered_hosts)} active host(s); starting per-host port scans",
                progress_current=0,
                progress_total=len(discovered_hosts),
                metadata={"hosts": discovered_hosts},
            )
            host_count = 0
            service_count = 0
            website_count = 0
            total = len(discovered_hosts)
            completed = 0
            completed_lock = threading.Lock()

            def _scan_single_host(host_ip: str) -> None:
                nonlocal host_count, service_count, website_count, completed
                if self._is_cancel_requested(scan_id):
                    return

                def _nmap_progress(phase: str, percent: float, _ip: str = host_ip) -> None:
                    self.database.update_scan_run(
                        scan_id,
                        status="running",
                        stage="scanning_hosts",
                        status_message=f"Scanning {_ip} — {phase} {percent:.0f}% ({completed}/{total} done)",
                        progress_current=completed,
                        progress_total=total,
                    )

                self.database.add_scan_event(
                    scan_id,
                    level="info",
                    stage="scanning_hosts",
                    message=f"Starting port scan: {host_ip}",
                    metadata={"host": host_ip, "step": "nmap_port_scan"},
                )
                host_scanner = NmapScanner()
                self._set_scanner(scan_id, host_scanner)
                host = host_scanner.scan_host(host_ip, on_progress=_nmap_progress)
                if self._is_cancel_requested(scan_id):
                    return
                with completed_lock:
                    completed += 1
                if host is None:
                    self.database.add_scan_event(
                        scan_id,
                        level="warning",
                        stage="completed_host",
                        message=f"Finished {host_ip}: no open TCP services ({completed}/{total})",
                        metadata={"host": host_ip, "result": "no_open_services"},
                    )
                    self.database.update_scan_run(
                        scan_id,
                        status="running",
                        stage="scanning_hosts",
                        status_message=f"Completed {host_ip} ({completed}/{total})",
                        progress_current=completed,
                        progress_total=total,
                    )
                    return
                dns_name = host.dns_name or safe_reverse_dns(host.ip)
                category = classify_host(
                    service_names=[service.service_name or "" for service in host.services],
                    ports=[service.port for service in host.services],
                    os_guess=host.os_guess,
                )
                host_id = self.database.upsert_host(
                    scan_id,
                    ip=host.ip,
                    mac_address=host.mac_address,
                    dns_name=dns_name,
                    os_guess=host.os_guess,
                    category=category,
                )
                with completed_lock:
                    host_count += 1
                self.database.add_scan_event(
                    scan_id,
                    level="info",
                    stage="persisting_host",
                    message=f"Persisting {host.ip} with {len(host.services)} open service(s)",
                    metadata={"host": host.ip, "service_count": len(host.services)},
                )
                for service in host.services:
                    service_category = classify_service(service.service_name, service.port, service.product)
                    service_id = self.database.insert_service(
                        scan_id,
                        host_id=host_id,
                        port=service.port,
                        protocol=service.protocol,
                        state=service.state,
                        service_name=service.service_name,
                        product=service.product,
                        version=service.version,
                        extrainfo=service.extrainfo,
                        category=service_category,
                        icon=icon_for_category(service_category),
                    )
                    with completed_lock:
                        service_count += 1
                    self.database.add_scan_event(
                        scan_id,
                        level="info",
                        stage="probing_web",
                        message=f"Checking {host.ip}:{service.port}/{service.protocol} for web metadata",
                        metadata={"host": host.ip, "port": service.port, "protocol": service.protocol},
                    )
                    for finding in probe_http_service(host.ip, service.port, service.service_name):
                        self.database.insert_website(
                            scan_id,
                            service_id=service_id,
                            hostname=finding.hostname,
                            scheme=finding.scheme,
                            source=finding.source,
                            title=finding.title,
                            server_header=finding.server_header,
                            redirect_target=finding.redirect_target,
                            tls_names=finding.tls_names,
                            upstream_target=finding.upstream_target,
                            favicon_url=None,
                        )
                        with completed_lock:
                            website_count += 1
                        self.database.add_scan_event(
                            scan_id,
                            level="info",
                            stage="probing_web",
                            message=f"Found website {finding.hostname} on {host.ip}:{service.port}",
                            metadata={"host": host.ip, "port": service.port, "hostname": finding.hostname},
                        )
                self.database.add_scan_event(
                    scan_id,
                    level="info",
                    stage="completed_host",
                    message=f"Finished {host.ip} ({completed}/{total})",
                    metadata={"host": host.ip, "result": "completed"},
                )
                self.database.update_scan_run(
                    scan_id,
                    status="running",
                    stage="scanning_hosts",
                    status_message=f"Completed {host.ip} ({completed}/{total})",
                    progress_current=completed,
                    progress_total=total,
                )

            max_parallel = min(5, total)
            with ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="nmap-host") as host_pool:
                futures = {host_pool.submit(_scan_single_host, ip): ip for ip in discovered_hosts}
                for future in as_completed(futures):
                    if self._is_cancel_requested(scan_id):
                        raise ScanCancelledError("Scan cancelled")
                    exc = future.exception()
                    if exc is not None and not isinstance(exc, ScanCancelledError):
                        self.database.add_scan_event(
                            scan_id,
                            level="error",
                            stage="scanning_hosts",
                            message=f"Error scanning {futures[future]}: {exc}",
                            metadata={"host": futures[future], "error": str(exc)},
                        )

            preferred_service_id = self.database.preferred_reverse_proxy_service(scan_id)
            if self.settings.opnsense.enabled:
                self._raise_if_cancelled(scan_id)
                self._progress(
                    scan_id,
                    stage="opnsense",
                    message="Importing hosted sites from OPNsense/Caddy",
                    progress_current=host_count,
                    progress_total=max(host_count, len(discovered_hosts)),
                    metadata={"opnsense": self.settings.opnsense.url},
                )
            all_caddy_findings = list(opnsense_client.fetch_websites())

            # Filter Caddy sites to those with upstream targets in scanned subnets
            scanned_networks = []
            for cidr in scan_targets:
                try:
                    scanned_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass

            def _upstream_in_scanned_subnets(finding):
                if not finding.upstream_target:
                    return False
                host_part = finding.upstream_target.rsplit(":", 1)[0] if ":" in finding.upstream_target else finding.upstream_target
                try:
                    addr = ipaddress.ip_address(host_part)
                    return any(addr in net for net in scanned_networks)
                except ValueError:
                    return False

            # Also include sites with no upstream (we can't filter them)
            caddy_findings = [f for f in all_caddy_findings if _upstream_in_scanned_subnets(f) or not f.upstream_target]

            self.database.add_scan_event(
                scan_id,
                level="info",
                stage="opnsense",
                message=f"Filtered {len(caddy_findings)}/{len(all_caddy_findings)} Caddy sites to scanned subnets",
                metadata={"total": len(all_caddy_findings), "filtered": len(caddy_findings)},
            )

            # Probe Caddy domains in parallel for titles and favicons
            def _probe_finding(f):
                return (f, probe_caddy_domain(f.hostname, f.scheme))

            probed_results: list[tuple] = []
            with ThreadPoolExecutor(max_workers=5, thread_name_prefix="caddy-probe") as probe_pool:
                probe_futures = {probe_pool.submit(_probe_finding, f): f for f in caddy_findings}
                for pf in as_completed(probe_futures):
                    try:
                        probed_results.append(pf.result())
                    except Exception:
                        probed_results.append((probe_futures[pf], (None, None)))

            for finding, (probed_title, favicon_url) in probed_results:
                self._raise_if_cancelled(scan_id)
                title = probed_title if probed_title else finding.title
                service_id = self.database.latest_service_id_for_endpoint(scan_id, finding.upstream_target) or preferred_service_id
                self.database.insert_website(
                    scan_id,
                    service_id=service_id,
                    hostname=finding.hostname,
                    scheme=finding.scheme,
                    source=finding.source,
                    title=title,
                    server_header=finding.server_header,
                    redirect_target=finding.redirect_target,
                    tls_names=finding.tls_names,
                    upstream_target=finding.upstream_target,
                    favicon_url=favicon_url,
                )
                website_count += 1
                self.database.add_scan_event(
                    scan_id,
                    level="info",
                    stage="opnsense",
                    message=f"Imported website {finding.hostname} from OPNsense/Caddy",
                    metadata={"hostname": finding.hostname, "upstream_target": finding.upstream_target},
                )

            self.database.update_scan_run(
                scan_id,
                status="completed",
                stage="completed",
                status_message=f"Completed scan with {host_count} hosts, {service_count} services, and {website_count} websites",
                progress_current=max(host_count, len(discovered_hosts)),
                progress_total=max(host_count, len(discovered_hosts)),
                finished=True,
            )
            self.database.add_scan_event(
                scan_id,
                level="info",
                stage="completed",
                message=f"Scan completed: {host_count} hosts, {service_count} services, {website_count} websites",
                metadata={"hosts": host_count, "services": service_count, "websites": website_count},
            )
            return ScanSummary(scan_id=scan_id, hosts=host_count, services=service_count, websites=website_count)
        except ScanCancelledError:
            self.database.update_scan_run(
                scan_id,
                status="cancelled",
                stage="cancelled",
                status_message="Scan cancelled",
                finished=True,
            )
            self.database.add_scan_event(
                scan_id,
                level="warning",
                stage="cancelled",
                message="Scan cancelled",
            )
            return ScanSummary(scan_id=scan_id, hosts=0, services=0, websites=0)
        except Exception as error:  # pragma: no cover - runtime safeguard
            self.database.update_scan_run(
                scan_id,
                status="failed",
                stage="failed",
                status_message=str(error),
                error_summary=str(error),
                finished=True,
            )
            self.database.add_scan_event(
                scan_id,
                level="error",
                stage="failed",
                message=str(error),
            )
            raise
        finally:
            self._set_scanner(scan_id, None)
            with self._lock:
                self.cancel_requests.discard(scan_id)

    def status(self, scan_id: int) -> dict[str, object] | None:
        return self.database.get_scan(scan_id)
