"""Streamlit-only email-validation app (single process, no backend).

Repo-root entrypoint for Streamlit Cloud. The 4-stage pipeline runs IN-PROCESS:
streamlit_app.py imports app.pipeline.runner and calls run_pipeline directly in
a background thread, writing progress/results into the in-memory job_store. The
UI fragment polls that store every second. There is NO FastAPI server and NO
BACKEND_URL — SMTP probes egress straight from this process on port 25.

Run locally:
    streamlit run streamlit_app.py

Deploy: Streamlit Community Cloud, main file = streamlit_app.py. SMTP mailbox
verification requires outbound port 25 from wherever this process runs.
"""
from __future__ import annotations

import asyncio
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
from app.store.jobs import job_store

# ── Stages / labels / columns (frontend feature parity) ────────────────────
STAGES = [
    ("stage1", "Pre-flight checks", "Syntax, duplicates, lists"),
    ("stage2", "DNS verification", "MX records, SPF/DMARC, blacklists"),
    ("stage3", "Mailbox verification", "SMTP handshake, catch-all detection"),
    ("stage4", "Confidence scoring", "Promoting high-confidence leads"),
]

STATUS_LABELS = {
    "valid": "Valid",
    "invalid": "Invalid",
    "reserved": "Risky",
    "do_not_use": "Do not use",
    "duplicate": "Duplicate",
}

# Internal status string -> user-facing label. The pipeline/model/exports keep
# "reserved"; the UI shows "risky" because it reads better for unverifiable leads.
STATUS_DISPLAY = {"reserved": "risky"}


def _status_label(status: str) -> str:
    return STATUS_DISPLAY.get(status, status)

DISPLAY_COLUMNS = [
    "email", "status", "sub_status", "score", "confidence", "flags",
    "did_you_mean", "mx_record", "smtp_provider", "smtp_response",
    "smtp_response_code", "is_free_provider", "is_role_address", "is_disposable",
    "promoted_from_reserved", "demoted_from_reserved", "score_breakdown",
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

st.set_page_config(page_title="EmailVerify", page_icon="✉️", layout="wide")


# ── In-process job launch ──────────────────────────────────────────────────
def _run_in_thread(emails: list[str], job_id: str) -> None:
    """Run the async pipeline in its own event loop on a daemon thread so the
    Streamlit script/fragment never blocks. The job_store singleton is shared
    module state, so the UI thread sees progress as it's written."""
    asyncio.run(run_pipeline(emails, job_id))


def start_job(emails: list[str], filename: str) -> str:
    job_id = uuid.uuid4().hex
    job_store.create(job_id, filename, len(emails))
    threading.Thread(
        target=_run_in_thread, args=(emails, job_id), daemon=True
    ).start()
    return job_id


def _norm(email: str | None) -> str:
    return (email or "").lower().strip()


def _first_email(cell) -> str | None:
    """Clean email match in a cell, or None — used to detect the email column."""
    if isinstance(cell, str):
        found = EMAIL_RE.findall(cell)
        if found:
            return found[0]
    return None


def _row_email(cell) -> str | None:
    """The email to validate for a row: a clean match if present, otherwise the
    raw non-empty cell (so malformed entries like `user@@x.com` still get
    validated and come back invalid, rather than being dropped)."""
    if not isinstance(cell, str):
        return None
    s = cell.strip()
    if not s:
        return None
    found = EMAIL_RE.findall(s)
    return found[0] if found else s


def parse_upload(name: str, data: bytes):
    """Read the uploaded file preserving its original columns, identify the
    email-bearing column, and return (original_df, row_emails) where row_emails
    holds one email (or None) per row aligned to the dataframe — so we can map
    validation statuses back onto the user's own rows later."""
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

    # Headerless heuristic: if the detected column's *name* is itself an email,
    # the file had no header row (pandas ate the first email) — re-read raw.
    if isinstance(email_col, str) and EMAIL_RE.findall(email_col):
        df = reader(io.BytesIO(data), header=None, dtype=str)
        email_col = max(df.columns, key=col_score)

    row_emails = [_row_email(v) for v in df[email_col].tolist()]
    return df, row_emails


def build_result_df(results: list[dict], in_df: pd.DataFrame, row_emails: list) -> pd.DataFrame:
    """Return the original file with a single `status` column added (or the
    existing one updated). Each row's status is looked up by its email; the real
    verdict wins over a `duplicate` marker so repeated rows all show the verdict."""
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


# ── SMTP port-25 self-test ─────────────────────────────────────────────────
def smtp_selftest(email: str) -> dict:
    async def _run() -> dict:
        domain = email.split("@", 1)[1]
        dns = await check_domain(domain)
        if not dns.mx_record:
            return {"ok": False, "detail": f"No MX record for {domain}"}
        res = await check_mailbox(email, dns.mx_record)
        return {
            "ok": bool(res.smtp_accessible),
            "mx": dns.mx_record,
            "code": res.smtp_response_code,
            "sub_status": res.sub_status,
            "response": res.smtp_response,
        }

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


def render_results(job_id: str) -> None:
    job = job_store.get(job_id)
    if not job:
        return
    results = [r.model_dump() for r in job["results"]]
    counts = job["counts"]

    st.subheader(f"Results · {len(results)} emails")

    cols = st.columns(len(STATUS_LABELS))
    for col, (key, label) in zip(cols, STATUS_LABELS.items()):
        col.metric(label, counts.get(key, 0))

    promoted = counts.get("promoted_to_valid", 0)
    demoted = counts.get("demoted_to_invalid", 0)
    if promoted or demoted:
        st.caption(f"Promotions: {promoted} promoted to valid · {demoted} demoted to invalid")

    df = _to_dataframe(results)

    fcol1, fcol2 = st.columns(2)
    status_opts = ["(all)"] + sorted(df["status"].dropna().unique().tolist()) if "status" in df else ["(all)"]
    sub_opts = ["(all)"] + sorted(df["sub_status"].dropna().unique().tolist()) if "sub_status" in df else ["(all)"]
    sel_status = fcol1.selectbox("Filter by status", status_opts, key=f"st_{job_id}")
    sel_sub = fcol2.selectbox("Filter by sub_status", sub_opts, key=f"sub_{job_id}")

    view = df
    if sel_status != "(all)":
        view = view[view["status"] == sel_status]
    if sel_sub != "(all)":
        view = view[view["sub_status"] == sel_sub]

    st.dataframe(view, use_container_width=True, hide_index=True)

    # Build the download. For file uploads, keep the user's ORIGINAL columns and
    # just add/update a single `status` column; for a single-email check, fall
    # back to the rich table. Either way filter to match the on-screen view.
    in_df = st.session_state.get("input_df")
    row_emails = st.session_state.get("input_row_emails")
    if in_df is not None and row_emails is not None:
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
    dcol2.caption("")
    dcol1.download_button(
        "⬇ Download CSV", data=download_df.to_csv(index=False).encode("utf-8"),
        file_name=f"{fname}.csv", mime="text/csv", key=f"csv_{job_id}",
    )
    dcol2.download_button(
        "⬇ Download XLSX", data=df_to_xlsx(download_df),
        file_name=f"{fname}.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key=f"xlsx_{job_id}",
    )


# ── Progress + results renderer ────────────────────────────────────────────
# Pure render — no polling here. The 1s refresh loop lives at the call site and
# only runs while the job is active, so no status reads happen when idle.
def progress_view(job_id: str) -> None:
    job = job_store.get(job_id)
    if job is None:
        st.error("Job not found.")
        return

    status = job.get("status", "pending")
    counts = job.get("counts", {}) or {}
    progress = job.get("progress") or {}

    if status == "failed":
        st.error(f"Validation failed: {job.get('error') or 'unknown error'}")
        return

    is_complete = status == "complete"
    total = counts.get("total", 0)
    processed = counts.get("processed", 0)

    if is_complete:
        st.success(f"Complete · {processed}/{total} processed")
    else:
        st.info(f"Status: {status} · {processed}/{total} processed")
        st.progress(processed / total if total else 0.0)

    for key, label, desc in STAGES:
        sp = progress.get(key) or {}
        done, st_total = sp.get("done", 0), sp.get("total", 0)
        if st_total:
            pct = done / st_total
            bar_label = f"{label} — {done}/{st_total}"
            if key == "stage1":
                bar_label += f" ({sp.get('passed', 0)} passed, {sp.get('filtered', 0)} filtered)"
        elif is_complete:
            # Nothing reached this stage (e.g. no reserved addresses for scoring) —
            # show an empty bar rather than a misleading full one.
            pct = 0.0
            bar_label = f"{label} — none to process"
        else:
            pct = 0.0
            bar_label = f"{label} — 0/0"
        st.caption(f"{bar_label}  ·  {desc}")
        st.progress(min(max(pct, 0.0), 1.0))

    if is_complete:
        render_results(job_id)


# ── Page ───────────────────────────────────────────────────────────────────
st.title("✉️ EmailVerify")
st.caption("Validate email lists in minutes. No guessing.")

with st.expander("🔌 SMTP port-25 self-test", expanded=False):
    test_email = st.text_input(
        "Probe a real address to confirm port 25 egress",
        value="postmaster@gmail.com", key="selftest_email",
    )
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
            st.error("Port 25 NOT reachable / no SMTP banner — "
                     f"{out.get('detail') or out.get('sub_status')}. "
                     "Mailbox verification will not work here.")

tab_single, tab_csv = st.tabs(["Single email", "CSV / Excel upload"])

with tab_single:
    email = st.text_input("Email address", placeholder="someone@example.com")
    if st.button("Validate email", type="primary", disabled=not email.strip()):
        jid = start_job([email.strip()], "single")
        st.session_state["job_id"] = jid
        st.session_state["input_df"] = None         # single email → rich download
        st.session_state["input_row_emails"] = None
        st.toast(f"Job {jid[:8]} started (1 email)")

with tab_csv:
    st.write("Upload a CSV/XLSX. The result file keeps your original columns and "
             "adds (or updates) a single `status` column.")
    upload = st.file_uploader("Choose file", type=["csv", "xlsx", "xls"])
    if st.button("Validate file", type="primary", disabled=upload is None):
        in_df, row_emails = parse_upload(upload.name, upload.getvalue())
        emails = [e for e in row_emails if e]
        if not emails:
            st.error("No email-like cells found in that file.")
        else:
            jid = start_job(emails, upload.name)
            st.session_state["job_id"] = jid
            st.session_state["input_df"] = in_df
            st.session_state["input_row_emails"] = row_emails
            st.toast(f"Job {jid[:8]} started ({len(emails)} emails)")

job_id = st.session_state.get("job_id")
if job_id:
    st.divider()
    st.subheader(f"Job {job_id}")
    progress_view(job_id)

    # Refresh once per second ONLY while the job is still running. Each rerun
    # re-checks the status; when it reaches complete/failed no rerun is
    # scheduled, so status reads stop the moment results are ready.
    _job = job_store.get(job_id)
    _running = bool(_job) and _job.get("status") not in ("complete", "failed")

    # Visible proof: this stamp ticks every second while polling, then freezes
    # once the job is done — even though Streamlit's own /api/v2/app/status
    # health pings keep going (those are the platform's, not ours).
    if _running:
        st.caption(f"↻ refreshing — {time.strftime('%H:%M:%S')}")
        time.sleep(1)
        st.rerun()
    else:
        st.caption(f"■ idle — our polling stopped (last update {time.strftime('%H:%M:%S')})")
