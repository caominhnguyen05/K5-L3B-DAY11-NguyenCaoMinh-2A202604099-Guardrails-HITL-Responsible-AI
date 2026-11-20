"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store the request and its start time for a later output record."""
        key = request_id or user_id
        started = datetime.now(timezone.utc).timestamp()
        self._open[key] = started
        self._open[f"{key}:input"] = text

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Append a completed interaction with decision and latency metadata."""
        key = request_id or user_id
        started = self._open.pop(key, None)
        input_text = self._open.pop(f"{key}:input", None)
        finished = datetime.now(timezone.utc).timestamp()
        if started is None:
            started = finished

        self.logs.append(
            {
                "request_id": request_id,
                "user_id": user_id,
                "input": input_text,
                "output": text,
                "blocked": blocked,
                "layer": layer,
                "started_at": datetime.fromtimestamp(
                    started, tz=timezone.utc
                ).isoformat(),
                "timestamp": utc_now_iso(),
                "latency_ms": round((finished - started) * 1000, 3),
            }
        )

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
