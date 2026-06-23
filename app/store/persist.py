"""Tiny disk-backed job persistence so a batch survives the window sleeping.

Each job is one JSON file under JOBS_DIR, written atomically (temp + replace).
The worker checkpoints after every chunk, so if the app is interrupted the job
can be resumed from the last completed chunk when the user reopens the tab.

On Streamlit Community Cloud the container disk persists across short sleeps
(not across a full redeploy/cold-start) — enough to resume an interrupted batch
in the common case; a cold-start falls back to the partial results already shown.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/tmp/ev_jobs"))
JOBS_DIR.mkdir(parents=True, exist_ok=True)

_LOCK = threading.Lock()


def _path(job_id: str) -> Path:
    return JOBS_DIR / f"{job_id}.json"


def save(rec: dict) -> None:
    p = _path(rec["id"])
    tmp = p.with_suffix(".tmp")
    with _LOCK:
        tmp.write_text(json.dumps(rec))
        tmp.replace(p)


def load(job_id: str) -> dict | None:
    p = _path(job_id)
    if not p.exists():
        return None
    try:
        with _LOCK:
            return json.loads(p.read_text())
    except Exception:
        return None
