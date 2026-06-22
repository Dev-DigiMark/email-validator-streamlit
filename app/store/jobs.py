"""Ported from backend/src/store/jobs.ts.

In-memory job store: create/get/update, add_result, increment_count, counts +
per-stage progress. Counts and progress are kept as plain dicts so the runner
can mutate them cheaply; results are ValidationResult model instances mutated
in place during Stage 4 (mirrors the TS Object.assign on job.results refs).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from app.models import ValidationResult

# Status strings that are valid count fields (mirror routes/results.ts).
VALID_STATUSES = ["valid", "invalid", "reserved", "do_not_use", "duplicate"]


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, dict[str, Any]] = {}

    def create(self, id: str, filename: str, email_count: int) -> dict[str, Any]:
        state: dict[str, Any] = {
            "id": id,
            "filename": filename,
            "status": "pending",
            "results": [],
            "counts": {
                "total": email_count,
                "processed": 0,
                "valid": 0,
                "invalid": 0,
                "reserved": 0,
                "do_not_use": 0,
                "duplicate": 0,
                "promoted_to_valid": 0,
                "demoted_to_invalid": 0,
            },
            "startedAt": datetime.now(),
            "completedAt": None,
            "error": None,
            "progress": None,
        }
        self._jobs[id] = state
        return state

    def get(self, id: str) -> Optional[dict[str, Any]]:
        return self._jobs.get(id)

    def update(self, id: str, **updates: Any) -> None:
        job = self._jobs.get(id)
        if not job:
            return
        job.update(updates)

    def increment_count(self, id: str, field: str, amount: int = 1) -> None:
        job = self._jobs.get(id)
        if not job:
            return
        counts = job["counts"]
        counts[field] += amount
        counts["processed"] = min(
            counts["total"],
            counts["valid"]
            + counts["invalid"]
            + counts["reserved"]
            + counts["do_not_use"]
            + counts["duplicate"],
        )

    def add_result(self, id: str, result: ValidationResult) -> None:
        job = self._jobs.get(id)
        if not job:
            return
        job["results"].append(result)

    def get_filtered_results(
        self,
        id: str,
        status: Optional[str] = None,
        sub_status: Optional[str] = None,
        promoted: Optional[bool] = None,
        demoted: Optional[bool] = None,
    ) -> list[ValidationResult]:
        job = self._jobs.get(id)
        if not job:
            return []
        results: list[ValidationResult] = job["results"]
        if status:
            results = [r for r in results if r.status == status]
        if sub_status:
            results = [r for r in results if r.sub_status == sub_status]
        if promoted is True:
            results = [r for r in results if r.promoted_from_reserved is True]
        if demoted is True:
            results = [r for r in results if r.demoted_from_reserved is True]
        return results

    def delete(self, id: str) -> None:
        self._jobs.pop(id, None)

    def list(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in job.items() if k != "results"} for job in self._jobs.values()]


job_store = JobStore()
