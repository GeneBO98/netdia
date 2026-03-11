from pathlib import Path

from fastapi.testclient import TestClient

from netdia.app import create_app
from netdia.classification import icon_for_category
from netdia.database import Database


def build_seeded_app(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "netdia.db"
    database = Database(db_path)
    database.init()
    database.add_target("192.168.1.0/24")
    scan_id = database.create_scan_run({"cidrs": ["192.168.1.0/24"]})
    database.update_scan_run(scan_id, status="completed", finished=True)
    host_id = database.upsert_host(
        scan_id,
        ip="192.168.1.10",
        mac_address=None,
        dns_name="caddy.local",
        os_guess="Linux 5.x",
        category="reverse_proxy",
    )
    service_id = database.insert_service(
        scan_id,
        host_id=host_id,
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
        product="Caddy",
        version="2.8.4",
        extrainfo=None,
        category="reverse_proxy",
        icon=icon_for_category("reverse_proxy"),
    )
    database.insert_website(
        scan_id,
        service_id=service_id,
        hostname="lab.example.com",
        scheme="https",
        source="tls_san",
        title=None,
        server_header="Caddy",
        redirect_target=None,
        tls_names=["lab.example.com"],
        upstream_target=None,
    )
    database.add_scan_event(
        scan_id,
        level="info",
        stage="completed",
        message="Seeded scan completed",
    )

    app = create_app()
    app.state.database = database
    return TestClient(app)


def test_topology_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETDIA_DB_PATH", str(tmp_path / "netdia.db"))
    client = build_seeded_app(tmp_path)
    response = client.get("/api/topology/latest")
    assert response.status_code == 200
    payload = response.json()
    assert payload["latest_scan"]["hosts"] == 1
    assert any(node["data"]["kind"] == "website" for node in payload["nodes"])


def test_host_detail_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETDIA_DB_PATH", str(tmp_path / "netdia.db"))
    client = build_seeded_app(tmp_path)
    response = client.get("/api/hosts/1")
    assert response.status_code == 200
    payload = response.json()
    assert payload["label"] == "caddy.local"
    assert payload["services"][0]["port"] == 443


def test_scan_event_and_latest_endpoints(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETDIA_DB_PATH", str(tmp_path / "netdia.db"))
    client = build_seeded_app(tmp_path)

    latest = client.get("/api/scans/latest")
    assert latest.status_code == 200
    assert latest.json()["status"] == "completed"

    events = client.get("/api/scans/1/events")
    assert events.status_code == 200
    payload = events.json()
    assert payload[-1]["message"] == "Seeded scan completed"


def test_cancel_scan_endpoint_marks_scan_cancelling(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("NETDIA_DB_PATH", str(tmp_path / "netdia.db"))
    client = build_seeded_app(tmp_path)

    setup_db = Database(tmp_path / "netdia.db")
    running_scan_id = setup_db.create_scan_run({"cidrs": ["192.168.1.0/24"]})
    setup_db.update_scan_run(
        running_scan_id,
        status="running",
        stage="scanning_hosts",
        status_message="Scanning host 1/3: 192.168.1.10",
        progress_current=0,
        progress_total=3,
    )

    response = client.post(f"/api/scans/{running_scan_id}/cancel")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "cancelling"

    events = client.get(f"/api/scans/{running_scan_id}/events")
    assert events.status_code == 200
    assert events.json()[-1]["message"] == "Cancellation requested"


def test_app_startup_reconciles_incomplete_scans(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "netdia.db"
    monkeypatch.setenv("NETDIA_DB_PATH", str(db_path))

    database = Database(db_path)
    database.init()
    scan_id = database.create_scan_run({"cidrs": ["192.168.1.0/24"]})
    database.update_scan_run(
        scan_id,
        status="cancelling",
        stage="cancelling",
        status_message="Cancelling scan...",
    )

    client = TestClient(create_app())
    latest = client.get("/api/scans/latest")

    assert latest.status_code == 200
    payload = latest.json()
    assert payload["id"] == scan_id
    assert payload["status"] == "cancelled"
    assert payload["status_message"] == "Marked cancelled after server restart"
