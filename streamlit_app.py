"""Streamlit-only email-validation app with resumable, disk-checkpointed jobs.

The job is a durable record identified by a job_id carried in the URL (?job=...).
A background worker processes the emails in CHUNKS and checkpoints to disk after
each chunk. If the window sleeps / goes black / is reopened, the page re-attaches
to the job by its URL id and the worker RESUMES from the last checkpoint instead
of dying — so a long 5k batch survives interruptions and finishes.

Run locally:  streamlit run streamlit_app.py
Deploy:       Streamlit Cloud, main file = streamlit_app.py. SMTP needs port 25.
"""
from __future__ import annotations

import asyncio
import base64
import io
import re
import threading
import time
import uuid

import pandas as pd
import streamlit as st

from app.checks.dns import check_domain
from app.checks.smtp import check_mailbox
from app.pipeline.runner import run_pipeline
from app.store import persist
from app.store.jobs import job_store

# ── Config ─────────────────────────────────────────────────────────────────
CHUNK_SIZE = 100  # emails per checkpoint; smaller = more frequent saves

STATUS_KEYS = [
    "valid", "invalid", "reserved", "do_not_use", "duplicate",
    "promoted_to_valid", "demoted_to_invalid",
]

STATUS_LABELS = {
    "valid": "Valid",
    "invalid": "Invalid",
    "reserved": "Risky",
    "do_not_use": "Do not use",
    "duplicate": "Duplicate",
}

STATUS_DISPLAY = {"reserved": "risky"}

DISPLAY_COLUMNS = [
    "email", "status", "sub_status", "score", "confidence", "flags",
    "did_you_mean", "mx_record", "smtp_provider", "smtp_response",
    "smtp_response_code", "is_free_provider", "is_role_address", "is_disposable",
    "promoted_from_reserved", "demoted_from_reserved", "score_breakdown",
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

st.set_page_config(page_title="EmailVerify", page_icon="✉️", layout="wide")


def _status_label(status: str) -> str:
    return STATUS_DISPLAY.get(status, status)


# ── Durable master-job store (memory cache + disk) ─────────────────────────
_MASTER: dict[str, dict] = {}
_MASTER_LOCK = threading.Lock()
_ACTIVE: set[str] = set()  # job_ids with a live worker thread in THIS process


def get_master(job_id: str) -> dict | None:
    """Return the job record from the in-memory cache, loading from disk (e.g.
    after a cold start / reopen) if it isn't cached yet."""
    rec = _MASTER.get(job_id)
    if rec is None:
        rec = persist.load(job_id)
        if rec is not None:
            _MASTER[job_id] = rec
    return rec


def save_master(rec: dict) -> None:
    _MASTER[rec["id"]] = rec
    persist.save(rec)


# ── Email parsing (keep original columns) ──────────────────────────────────
def _norm(email: str | None) -> str:
    return (email or "").lower().strip()


def _first_email(cell) -> str | None:
    if isinstance(cell, str):
        found = EMAIL_RE.findall(cell)
        if found:
            return found[0]
    return None


def _row_email(cell) -> str | None:
    if not isinstance(cell, str):
        return None
    s = cell.strip()
    if not s:
        return None
    found = EMAIL_RE.findall(s)
    return found[0] if found else s


def parse_upload(name: str, data: bytes):
    """Read the file keeping its original columns; return (df, row_emails) with
    one email (or None) per row aligned to the dataframe."""
    name = name.lower()
    reader = pd.read_excel if name.endswith((".xlsx", ".xls")) else pd.read_csv
    df = reader(io.BytesIO(data), dtype=str)

    def col_score(col) -> int:
        return sum(1 for v in df[col].tolist() if _first_email(v))

    if len(df.columns) == 0:
        return df, []
    email_col = max(df.columns, key=col_score)
    if col_score(email_col) == 0:
        return df, []
    if isinstance(email_col, str) and EMAIL_RE.findall(email_col):
        df = reader(io.BytesIO(data), header=None, dtype=str)
        email_col = max(df.columns, key=col_score)

    row_emails = [_row_email(v) for v in df[email_col].tolist()]
    return df, row_emails


def build_result_df(results: list[dict], in_df: pd.DataFrame, row_emails: list) -> pd.DataFrame:
    """Original file + a single added/updated `status` column."""
    status_by_email: dict[str, str] = {}
    for r in results:
        e = _norm(r.get("email"))
        if not e:
            continue
        if e not in status_by_email or r.get("status") != "duplicate":
            status_by_email[e] = _status_label(r.get("status", ""))

    out = in_df.copy()
    statuses = [status_by_email.get(_norm(e), "") if e else "" for e in row_emails]
    target = next(
        (c for c in out.columns if isinstance(c, str) and c.strip().lower() == "status"),
        None,
    )
    out[target or "status"] = statuses
    return out


def df_to_xlsx(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    return buf.getvalue()


# ── Chunked worker (resumable) ─────────────────────────────────────────────
async def _validate_chunk(emails: list[str]):
    """Run the full pipeline on one chunk via a throwaway sub-job; return
    (result_dicts, status_counts)."""
    sub_id = uuid.uuid4().hex
    job_store.create(sub_id, "chunk", len(emails))
    try:
        await run_pipeline(emails, sub_id)
        sub = job_store.get(sub_id)
        results = [r.model_dump() for r in sub["results"]]
        counts = {k: sub["counts"].get(k, 0) for k in STATUS_KEYS}
        return results, counts
    finally:
        job_store.delete(sub_id)


def _worker(job_id: str) -> None:
    """Process remaining chunks, checkpointing after each. Resumes from
    rec['done'] so an interrupted job continues instead of restarting."""
    try:
        while True:
            rec = get_master(job_id)
            if rec is None:
                return
            emails = rec["emails"]
            done = rec["done"]
            if done >= len(emails):
                rec["status"] = "complete"
                rec["counts"]["processed"] = done
                save_master(rec)
                return

            chunk = emails[done:done + CHUNK_SIZE]
            try:
                results, counts = asyncio.run(_validate_chunk(chunk))
            except Exception as err:  # noqa: BLE001
                rec = get_master(job_id) or rec
                rec["status"] = "failed"
                rec["error"] = str(err)
                save_master(rec)
                return

            rec = get_master(job_id) or rec
            rec["results"].extend(results)
            for k in STATUS_KEYS:
                rec["counts"][k] = rec["counts"].get(k, 0) + counts.get(k, 0)
            rec["done"] = done + len(chunk)
            rec["counts"]["processed"] = rec["done"]
            rec["status"] = "complete" if rec["done"] >= len(emails) else "running"
            save_master(rec)
    finally:
        with _MASTER_LOCK:
            _ACTIVE.discard(job_id)


def ensure_worker(job_id: str) -> None:
    """Start (or restart, after a reopen/cold-start) the worker if the job is
    unfinished and not already being processed in this process."""
    with _MASTER_LOCK:
        if job_id in _ACTIVE:
            return
        rec = get_master(job_id)
        if not rec or rec["status"] in ("complete", "failed"):
            return
        _ACTIVE.add(job_id)
    threading.Thread(target=_worker, args=(job_id,), daemon=True).start()


def create_job(emails: list[str], name: str, input_bytes: bytes | None) -> str:
    job_id = uuid.uuid4().hex
    rec = {
        "id": job_id,
        "filename": name,
        "total": len(emails),
        "emails": emails,
        "results": [],
        "done": 0,
        "status": "running",
        "error": None,
        "counts": {**{k: 0 for k in STATUS_KEYS}, "total": len(emails), "processed": 0},
        "input_b64": base64.b64encode(input_bytes).decode() if input_bytes else None,
        "input_name": name if input_bytes else None,
    }
    save_master(rec)
    ensure_worker(job_id)
    return job_id


# ── SMTP port-25 self-test ─────────────────────────────────────────────────
def smtp_selftest(email: str) -> dict:
    async def _run() -> dict:
        domain = email.split("@", 1)[1]
        dns = await check_domain(domain)
        if not dns.mx_record:
            return {"ok": False, "detail": f"No MX record for {domain}"}
        res = await check_mailbox(email, dns.mx_record)
        return {"ok": bool(res.smtp_accessible), "mx": dns.mx_record,
                "code": res.smtp_response_code, "sub_status": res.sub_status}

    return asyncio.run(_run())


# ── Result rendering ───────────────────────────────────────────────────────
def _to_dataframe(results: list[dict]) -> pd.DataFrame:
    rows = []
    for r in results:
        flags = r.get("flags") or []
        breakdown = r.get("score_breakdown") or []
        rows.append({
            "email": r.get("email", ""),
            "status": _status_label(r.get("status", "")),
            "sub_status": r.get("sub_status", ""),
            "score": r.get("score"),
            "confidence": r.get("confidence", ""),
            "flags": ", ".join(flags) if isinstance(flags, list) else flags,
            "did_you_mean": r.get("did_you_mean") or "",
            "mx_record": r.get("mx_record") or "",
            "smtp_provider": r.get("smtp_provider") or "",
            "smtp_response": r.get("smtp_response") or "",
            "smtp_response_code": r.get("smtp_response_code")
            if r.get("smtp_response_code") is not None else "",
            "is_free_provider": r.get("is_free_provider"),
            "is_role_address": r.get("is_role_address"),
            "is_disposable": r.get("is_disposable"),
            "promoted_from_reserved": "yes" if r.get("promoted_from_reserved") else "no",
            "demoted_from_reserved": "yes" if r.get("demoted_from_reserved") else "no",
            "score_breakdown": "; ".join(
                f"{s.get('signal')}:{s.get('points')}" for s in breakdown
            ) if isinstance(breakdown, list) else "",
        })
    df = pd.DataFrame(rows)
    cols = [c for c in DISPLAY_COLUMNS if c in df.columns]
    return df[cols] if cols else df


def render_results(rec: dict) -> None:
    results = rec["results"]
    if not results:
        return
    df = _to_dataframe(results)

    fcol1, fcol2 = st.columns(2)
    status_opts = ["(all)"] + sorted(df["status"].dropna().unique().tolist()) if "status" in df else ["(all)"]
    sub_opts = ["(all)"] + sorted(df["sub_status"].dropna().unique().tolist()) if "sub_status" in df else ["(all)"]
    sel_status = fcol1.selectbox("Filter by status", status_opts, key=f"st_{rec['id']}")
    sel_sub = fcol2.selectbox("Filter by sub_status", sub_opts, key=f"sub_{rec['id']}")

    view = df
    if sel_status != "(all)":
        view = view[view["status"] == sel_status]
    if sel_sub != "(all)":
        view = view[view["sub_status"] == sel_sub]

    st.dataframe(view, use_container_width=True, hide_index=True)

    # Build download: original columns + status for uploads, else the rich table.
    if rec.get("input_b64"):
        in_df, row_emails = parse_upload(
            rec["input_name"] or "upload.csv", base64.b64decode(rec["input_b64"])
        )
        allowed = {_norm(e) for e in view["email"].tolist()}
        result_df = build_result_df(results, in_df, row_emails)
        keep = [bool(e) and _norm(e) in allowed for e in row_emails]
        download_df = result_df[pd.Series(keep, index=result_df.index)]
    else:
        download_df = view

    fname = "results"
    if sel_status != "(all)":
        fname += f"_{sel_status}"
    if sel_sub != "(all)":
        fname += f"_{sel_sub}"

    dcol1, dcol2 = st.columns(2)
    dcol1.caption(f"Exporting {len(download_df)} rows")
    dcol1.download_button(
        "⬇ Download CSV", data=download_df.to_csv(index=False).encode("utf-8"),
        file_name=f"{fname}.csv", mime="text/csv", key=f"csv_{rec['id']}",
    )
    dcol2.download_button(
        "⬇ Download XLSX", data=df_to_xlsx(download_df),
        file_name=f"{fname}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key=f"xlsx_{rec['id']}",
    )


def render_job(job_id: str) -> str | None:
    rec = get_master(job_id)
    if not rec:
        st.warning("Job not found (it may have expired after a full restart). "
                   "Re-upload to start again.")
        return None

    # Auto-resume: if it's unfinished, make sure a worker is running (this is
    # what restarts processing after a reopen / cold start).
    ensure_worker(job_id)

    total = rec["total"]
    done = rec["counts"].get("processed", 0)
    status = rec["status"]

    if status == "complete":
        st.success(f"Complete · {done}/{total} processed")
    elif status == "failed":
        st.error(f"Job failed: {rec.get('error') or 'unknown error'}")
    else:
        st.info(f"Processing · {done}/{total} — runs on the server and resumes "
                f"automatically if this tab sleeps or is reopened.")
    st.progress(done / total if total else 0.0)

    cols = st.columns(len(STATUS_LABELS))
    for col, (k, label) in zip(cols, STATUS_LABELS.items()):
        col.metric(label, rec["counts"].get(k, 0))

    promoted = rec["counts"].get("promoted_to_valid", 0)
    demoted = rec["counts"].get("demoted_to_invalid", 0)
    if promoted or demoted:
        st.caption(f"Promotions: {promoted} promoted to valid · {demoted} demoted to invalid")

    render_results(rec)
    return status


# ── Page ───────────────────────────────────────────────────────────────────
st.title("✉️ EmailVerify")
st.caption("Validate email lists in minutes. Jobs are resumable — safe to close and reopen.")

with st.expander("🔌 SMTP port-25 self-test", expanded=False):
    test_email = st.text_input("Probe a real address to confirm port 25 egress",
                               value="postmaster@gmail.com", key="selftest_email")
    if st.button("Run port-25 test", disabled=not test_email.strip()):
        with st.spinner("Connecting on port 25…"):
            try:
                out = smtp_selftest(test_email.strip())
            except Exception as err:  # noqa: BLE001
                out = {"ok": False, "detail": str(err)}
        if out.get("ok"):
            st.success(f"Port 25 reachable ✓  MX={out.get('mx')}  "
                       f"code={out.get('code')}  sub_status={out.get('sub_status')}")
        else:
            st.error("Port 25 NOT reachable — "
                     f"{out.get('detail') or out.get('sub_status')}.")

tab_single, tab_csv = st.tabs(["Single email", "CSV / Excel upload"])

with tab_single:
    email = st.text_input("Email address", placeholder="someone@example.com")
    if st.button("Validate email", type="primary", disabled=not email.strip()):
        jid = create_job([email.strip()], "single", None)
        st.query_params["job"] = jid
        st.rerun()

with tab_csv:
    st.write("Upload a CSV/XLSX. The result file keeps your original columns and "
             "adds (or updates) a single `status` column.")
    upload = st.file_uploader("Choose file", type=["csv", "xlsx", "xls"])
    if st.button("Validate file", type="primary", disabled=upload is None):
        data = upload.getvalue()
        _, row_emails = parse_upload(upload.name, data)
        emails = [e for e in row_emails if e]
        if not emails:
            st.error("No email-like cells found in that file.")
        else:
            jid = create_job(emails, upload.name, data)
            st.query_params["job"] = jid
            st.rerun()

# ── Active job (re-attached by URL ?job=...) ───────────────────────────────
job_id = st.query_params.get("job")
if job_id:
    st.divider()
    cols = st.columns([4, 1])
    cols[0].subheader(f"Job {job_id[:12]}…")
    if cols[1].button("Clear"):
        st.query_params.clear()
        st.rerun()

    status = render_job(job_id)

    # Poll only while running; stops once complete/failed. The worker keeps
    # going server-side regardless, so reopening the URL resumes the view.
    if status not in ("complete", "failed", None):
        st.caption(f"↻ refreshing — {time.strftime('%H:%M:%S')}")
        time.sleep(1)
        st.rerun()
    elif status is not None:
        st.caption(f"■ idle — polling stopped (last update {time.strftime('%H:%M:%S')})")
