"""FastAPI app exposing the 4-stage pipeline (replaces the Fastify routes).

POST /validate        — JSON {emails:[...]} or CSV/XLSX upload; creates a job,
                        launches run_pipeline as an asyncio background task,
                        returns {jobId, total}.
GET  /jobs/{id}       — {status, counts, progress} for polling.
GET  /results/{id}    — full results array.
GET  /export/{id}     — stream results as csv|xlsx (pandas/openpyxl).
"""
from __future__ import annotations

import asyncio
import io
import uuid

import pandas as pd
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from app.config import CONFIG
from app.pipeline.runner import run_pipeline
from app.store.jobs import job_store

app = FastAPI(title="Email Validation Tool")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CONFIG["server"]["corsOrigin"], "*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

EXPORT_COLUMNS = [
    "email", "status", "sub_status", "score", "confidence", "flags",
    "did_you_mean", "mx_record", "smtp_provider", "smtp_response", "smtp_response_code",
    "is_free_provider", "is_role_address", "is_disposable",
    "promoted_from_reserved", "demoted_from_reserved", "score_breakdown",
]


def _extract_emails(data: bytes, filename: str) -> list[str]:
    """papaparse-equivalent extraction: read every cell, keep email-like values
    in order. Works for headed/headerless CSV and XLSX alike."""
    buf = io.BytesIO(data)
    if filename.lower().endswith((".xlsx", ".xls")):
        df = pd.read_excel(buf, header=None, dtype=str)
    else:
        df = pd.read_csv(buf, header=None, dtype=str)
    emails: list[str] = []
    for value in df.to_numpy().flatten():
        if isinstance(value, str):
            s = value.strip()
            if "@" in s:
                emails.append(s)
    return emails


@app.post("/validate")
async def validate(request: Request):
    content_type = request.headers.get("content-type", "")
    emails: list[str] = []
    filename = "paste-input"

    if "multipart/form-data" in content_type:
        form = await request.form()
        upload = form.get("file")
        if upload is None:
            return JSONResponse(status_code=400, content={"error": "No file provided", "code": "NO_FILE"})
        filename = upload.filename or "upload"
        data = await upload.read()
        try:
            emails = _extract_emails(data, filename)
        except Exception as err:
            return JSONResponse(status_code=400, content={"error": "Failed to parse file", "code": "PARSE_ERROR", "detail": str(err)})
    else:
        body = await request.json()
        raw = body.get("emails") if isinstance(body, dict) else None
        if not isinstance(raw, list) or len(raw) == 0:
            return JSONResponse(status_code=400, content={"error": "emails array is required", "code": "MISSING_EMAILS"})
        emails = [e.strip() for e in raw if isinstance(e, str) and e.strip()]

    if len(emails) == 0:
        return JSONResponse(status_code=400, content={"error": "No valid email addresses found", "code": "NO_EMAILS"})
    if len(emails) > CONFIG["pipeline"]["maxEmailsPerJob"]:
        return JSONResponse(status_code=400, content={
            "error": f"Too many emails. Maximum is {CONFIG['pipeline']['maxEmailsPerJob']}",
            "code": "TOO_MANY_EMAILS",
        })

    job_id = str(uuid.uuid4())
    job_store.create(job_id, filename, len(emails))

    async def _run() -> None:
        try:
            await run_pipeline(emails, job_id)
        except Exception as err:  # mirror fire-and-forget error handling
            job_store.update(job_id, status="failed", error=str(err))

    asyncio.create_task(_run())

    return JSONResponse(status_code=202, content={"jobId": job_id, "total": len(emails)})


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    job = job_store.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found", "code": "NOT_FOUND"})
    return {"status": job["status"], "counts": job["counts"], "progress": job["progress"]}


@app.get("/logs/{job_id}")
async def get_logs(job_id: str):
    job = job_store.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found", "code": "NOT_FOUND"})
    return {"jobId": job_id, "logs": job.get("logs", [])}


@app.get("/results/{job_id}")
async def get_results(job_id: str):
    job = job_store.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found", "code": "NOT_FOUND"})
    return {
        "results": [r.model_dump() for r in job["results"]],
        "total": len(job["results"]),
        "counts": job["counts"],
    }


def _flatten(r) -> dict:
    return {
        "email": r.email,
        "status": r.status,
        "sub_status": r.sub_status,
        "score": r.score,
        "confidence": r.confidence,
        "flags": ", ".join(r.flags),
        "did_you_mean": r.did_you_mean or "",
        "mx_record": r.mx_record or "",
        "smtp_provider": r.smtp_provider or "",
        "smtp_response": r.smtp_response or "",
        "smtp_response_code": r.smtp_response_code if r.smtp_response_code is not None else "",
        "is_free_provider": r.is_free_provider,
        "is_role_address": r.is_role_address,
        "is_disposable": r.is_disposable,
        "promoted_from_reserved": "yes" if r.promoted_from_reserved else "no",
        "demoted_from_reserved": "yes" if r.demoted_from_reserved else "no",
        "score_breakdown": "; ".join(f"{s.signal}:{s.points}" for s in r.score_breakdown) if r.score_breakdown else "",
    }


@app.get("/export/{job_id}")
async def export(job_id: str, format: str = "csv"):
    job = job_store.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"error": "Job not found", "code": "NOT_FOUND"})

    fmt = format.lower()
    if fmt not in ("csv", "xlsx"):
        return JSONResponse(status_code=400, content={"error": "Format must be csv or xlsx", "code": "INVALID_FORMAT"})

    rows = [_flatten(r) for r in job["results"]]
    df = pd.DataFrame(rows, columns=EXPORT_COLUMNS)
    base_name = job["filename"].rsplit(".", 1)[0] or "results"

    if fmt == "csv":
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        content = buf.getvalue().encode("utf-8")
        media = "text/csv"
        filename = f"{base_name}_all.csv"
    else:
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Results")
        content = buf.getvalue()
        media = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        filename = f"{base_name}_all.xlsx"

    return StreamingResponse(
        io.BytesIO(content),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
