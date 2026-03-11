from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from netdia.app import create_app
from netdia.config import load_settings
from netdia.database import Database
from netdia.scan_service import ScanManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netdia")
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Start the Netdia web server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)

    scan = subparsers.add_parser("scan", help="Run a scan headlessly")
    scan.add_argument("cidrs", nargs="*")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        uvicorn.run("netdia.app:create_app", factory=True, host=args.host, port=args.port)
        return

    settings = load_settings()
    database = Database(settings.db_path)
    database.init()
    database.ensure_default_target()
    manager = ScanManager(settings, database)
    cidrs = args.cidrs or database.enabled_cidrs()
    scan_id = database.create_scan_run({"cidrs": cidrs, "mode": "cli"})
    summary = manager.run_scan(scan_id, cidrs)
    sys.stdout.write(json.dumps(summary.__dict__, indent=2) + "\n")
