from pathlib import Path

from netdia.nmap_runner import parse_host_discovery_xml, parse_port_scan_xml


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_host_discovery_xml() -> None:
    hosts = parse_host_discovery_xml((FIXTURES / "nmap_discovery.xml").read_text())
    assert [host.ip for host in hosts] == ["192.168.1.10", "192.168.1.20"]
    assert hosts[0].mac_address == "AA:BB:CC:DD:EE:FF"
    assert hosts[0].dns_name == "caddy.local"


def test_parse_port_scan_xml() -> None:
    hosts = parse_port_scan_xml((FIXTURES / "nmap_ports.xml").read_text())
    assert len(hosts) == 2
    assert hosts[0].dns_name == "caddy.local"
    assert hosts[0].services[0].product == "Caddy"
    assert hosts[1].services[0].port == 5432
