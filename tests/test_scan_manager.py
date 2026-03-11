from pathlib import Path

from netdia.config import OPNsenseConfig, Settings
from netdia.database import Database
from netdia.scan_service import ScanManager


class CancelledFuture:
    def cancel(self) -> bool:
        return True


def test_cancel_scan_marks_queued_job_cancelled(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        db_path=tmp_path / "netdia.db",
        opnsense=OPNsenseConfig(),
    )
    database = Database(settings.db_path)
    database.init()
    manager = ScanManager(settings, database)

    scan_id = database.create_scan_run({"cidrs": ["192.168.1.0/24"]})
    manager.jobs[scan_id] = CancelledFuture()  # type: ignore[assignment]

    payload = manager.cancel_scan(scan_id)

    assert payload is not None
    assert payload["status"] == "cancelled"
    events = database.list_scan_events(scan_id)
    assert events[-1]["message"] == "Scan cancelled before start"
