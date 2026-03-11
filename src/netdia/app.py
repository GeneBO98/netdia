from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from netdia.config import load_settings
from netdia.database import Database
from netdia.scan_service import ScanManager


def create_app() -> FastAPI:
    settings = load_settings()
    database = Database(settings.db_path)
    database.init()
    database.ensure_default_target()
    database.reconcile_incomplete_scans()
    scan_manager = ScanManager(settings, database)

    app = FastAPI(title="Netdia")
    app.state.settings = settings
    app.state.database = database
    app.state.scan_manager = scan_manager

    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/api/targets")
    def list_targets() -> list[dict[str, Any]]:
        return database.list_targets()

    @app.post("/api/targets")
    def add_target(payload: dict[str, Any]) -> dict[str, Any]:
        cidr = str(payload.get("cidr", "")).strip()
        if not cidr:
            raise HTTPException(status_code=400, detail="cidr is required")
        return database.add_target(cidr)

    @app.patch("/api/targets/{target_id}")
    def update_target(target_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return database.update_target(target_id, bool(payload.get("enabled", True)))

    @app.post("/api/scans")
    def start_scan(payload: dict[str, Any] | None = None) -> dict[str, Any]:
        cidrs = None
        if payload:
            raw_cidrs = payload.get("cidrs")
            if isinstance(raw_cidrs, list):
                cidrs = [str(item) for item in raw_cidrs if str(item).strip()]
        scan_id = scan_manager.start_scan(cidrs)
        scan = database.get_scan(scan_id)
        return {"scan_id": scan_id, "status": scan["status"] if scan else "queued"}

    @app.get("/api/scans/latest")
    def latest_scan_run() -> dict[str, Any]:
        scan = database.latest_scan_run()
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan

    @app.get("/api/scans/{scan_id}")
    def get_scan(scan_id: int) -> dict[str, Any]:
        scan = scan_manager.status(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan

    @app.post("/api/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: int) -> dict[str, Any]:
        scan = scan_manager.cancel_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return scan

    @app.get("/api/scans/{scan_id}/events")
    def get_scan_events(scan_id: int) -> list[dict[str, Any]]:
        scan = scan_manager.status(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return database.list_scan_events(scan_id)

    @app.get("/api/topology/latest")
    def topology() -> dict[str, Any]:
        return database.topology()

    @app.get("/api/hosts/{host_id}")
    def host_detail(host_id: int) -> dict[str, Any]:
        payload = database.host_detail(host_id)
        if payload is None:
            raise HTTPException(status_code=404, detail="host not found")
        return payload

    @app.get("/api/websites")
    def list_websites() -> list[dict[str, Any]]:
        return database.list_websites()

    @app.patch("/api/hosts/{host_id}/overrides")
    def update_host_override(host_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        database.update_host_override(
            host_id,
            display_name=payload.get("display_name"),
            icon=payload.get("icon"),
            category=payload.get("category"),
        )
        detail = database.host_detail(host_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="host not found")
        return detail

    @app.patch("/api/services/{service_id}/overrides")
    def update_service_override(service_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        latest = database.latest_scan()
        if latest is None:
            raise HTTPException(status_code=404, detail="service not found")
        with database.connect() as connection:
            row = connection.execute(
                "SELECT host_id, port, protocol FROM services WHERE id = ? AND scan_run_id = ?",
                (service_id, latest["id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="service not found")
        database.update_service_override(
            int(row["host_id"]),
            int(row["port"]),
            str(row["protocol"]),
            display_name=payload.get("display_name"),
            icon=payload.get("icon"),
            category=payload.get("category"),
        )
        return {"ok": True}

    return app
