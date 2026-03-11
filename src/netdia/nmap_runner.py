from __future__ import annotations

import os
import re
import signal
import shutil
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterable

from netdia.models import DiscoveredHost, DiscoveredService, ScannedHost

NmapProgressCallback = Callable[[str, float], None]


class NmapUnavailableError(RuntimeError):
    pass


class ScanCancelledError(RuntimeError):
    pass


def ensure_nmap() -> str:
    nmap_path = shutil.which("nmap")
    if nmap_path is None:
        raise NmapUnavailableError("nmap was not found on PATH")
    return nmap_path


def parse_host_discovery_xml(xml_text: str) -> list[DiscoveredHost]:
    root = ET.fromstring(xml_text)
    results: list[DiscoveredHost] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.attrib.get("state") != "up":
            continue
        ip = None
        mac_address = None
        dns_name = None
        for address in host_el.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip = address.attrib.get("addr")
            if address.attrib.get("addrtype") == "mac":
                mac_address = address.attrib.get("addr")
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hostname = hostnames.find("hostname")
            if hostname is not None:
                dns_name = hostname.attrib.get("name")
        if ip:
            results.append(DiscoveredHost(ip=ip, mac_address=mac_address, dns_name=dns_name))
    return results


def parse_port_scan_xml(xml_text: str) -> list[ScannedHost]:
    root = ET.fromstring(xml_text)
    results: list[ScannedHost] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.attrib.get("state") != "up":
            continue
        ip = None
        mac_address = None
        dns_name = None
        os_guess = None
        for address in host_el.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip = address.attrib.get("addr")
            if address.attrib.get("addrtype") == "mac":
                mac_address = address.attrib.get("addr")
        hostnames = host_el.find("hostnames")
        if hostnames is not None:
            hostname = hostnames.find("hostname")
            if hostname is not None:
                dns_name = hostname.attrib.get("name")
        os_el = host_el.find("os")
        if os_el is not None:
            match = os_el.find("osmatch")
            if match is not None:
                os_guess = match.attrib.get("name")
        if ip is None:
            continue
        host = ScannedHost(ip=ip, mac_address=mac_address, dns_name=dns_name, os_guess=os_guess)
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.attrib.get("state") != "open":
                continue
            service_el = port_el.find("service")
            host.services.append(
                DiscoveredService(
                    port=int(port_el.attrib["portid"]),
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    state=state_el.attrib.get("state", "open"),
                    service_name=None if service_el is None else service_el.attrib.get("name"),
                    product=None if service_el is None else service_el.attrib.get("product"),
                    version=None if service_el is None else service_el.attrib.get("version"),
                    extrainfo=None if service_el is None else service_el.attrib.get("extrainfo"),
                )
            )
        results.append(host)
    return results


class NmapScanner:
    def __init__(self) -> None:
        self.nmap_path = ensure_nmap()
        self._lock = threading.Lock()
        self._cancel_requested = False
        self._current_process: subprocess.Popen[str] | None = None

    def cancel(self) -> None:
        with self._lock:
            self._cancel_requested = True
            process = self._current_process
        self._terminate_process(process)

    def cancelled(self) -> bool:
        with self._lock:
            return self._cancel_requested

    def _run(
        self,
        args: list[str],
        on_progress: NmapProgressCallback | None = None,
    ) -> str:
        if self.cancelled():
            raise ScanCancelledError("Scan cancelled")
        process = subprocess.Popen(
            [self.nmap_path, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        with self._lock:
            self._current_process = process
        stderr_lines: list[str] = []

        def _read_stderr() -> None:
            assert process.stderr is not None
            for line in process.stderr:
                stderr_lines.append(line)
                if on_progress is not None:
                    self._parse_stats_line(line, on_progress)

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stderr_thread.start()
        try:
            while True:
                if self.cancelled():
                    self._terminate_process(process)
                    raise ScanCancelledError("Scan cancelled")
                if process.poll() is not None:
                    break
                time.sleep(0.2)
            assert process.stdout is not None
            stdout = process.stdout.read()
            stderr_thread.join(timeout=3)
        finally:
            with self._lock:
                self._current_process = None
        if self.cancelled():
            raise ScanCancelledError("Scan cancelled")
        stderr_text = "".join(stderr_lines)
        if process.returncode != 0:
            raise RuntimeError(stderr_text.strip() or stdout.strip() or "nmap command failed")
        return stdout

    _STATS_RE = re.compile(
        r"About (\d+(?:\.\d+)?)% done",
    )
    _PHASE_RE = re.compile(
        r"undergoing (.+?)$",
        re.MULTILINE,
    )

    def _parse_stats_line(
        self,
        line: str,
        on_progress: NmapProgressCallback,
    ) -> None:
        pct_match = self._STATS_RE.search(line)
        if pct_match is None:
            return
        percent = float(pct_match.group(1))
        phase_match = self._PHASE_RE.search(line)
        phase = phase_match.group(1).strip() if phase_match else "scanning"
        on_progress(phase, percent)

    def _terminate_process(self, process: subprocess.Popen[str] | None) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            except OSError:
                process.kill()
            process.wait(timeout=2)

    def discover(self, cidrs: Iterable[str]) -> list[DiscoveredHost]:
        xml_text = self._run(["-sn", "-n", "-oX", "-", *cidrs])
        return parse_host_discovery_xml(xml_text)

    def scan_host(
        self,
        host: str,
        on_progress: NmapProgressCallback | None = None,
    ) -> ScannedHost | None:
        xml_text = self._run(
            [
                "-Pn", "-n", "-sV",
                "--top-ports", "1000",
                "-T4",
                "--min-rate", "1000",
                "--open",
                "--stats-every", "2s",
                "-oX", "-",
                host,
            ],
            on_progress=on_progress,
        )
        results = parse_port_scan_xml(xml_text)
        return results[0] if results else None

    def scan_hosts(self, hosts: Iterable[str]) -> list[ScannedHost]:
        results: list[ScannedHost] = []
        for host in hosts:
            scanned = self.scan_host(host)
            if scanned is not None:
                results.append(scanned)
        return results
