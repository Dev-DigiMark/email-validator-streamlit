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
    "reserved": "Reserved",
    "do_not_use": "Do not use",
    "duplicate": "Duplicate",
}

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


def extract_emails(name: str, data: bytes) -> list[str]:
    """Pull every email-like cell out of a CSV/XLSX (header-agnostic)."""
    name = name.lower()
    if name.endswith((".xlsx", ".xls")):
        df = pd.read_excel(io.BytesIO(data), header=None, dtype=str)
    else:
        df = pd.read_csv(io.BytesIO(data), header=None, dtype=str)
    emails: list[str] = []
    for val in df.values.ravel():
        if isinstance(val, str):
            emails.extend(EMAIL_RE.findall(val))
    return emails


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
            "status": r.get("status", ""),
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

    dcol1, dcol2 = st.columns(2)
    dcol1.download_button(
        "⬇ Download CSV", data=df.to_csv(index=False).encode("utf-8"),
        file_name="results_all.csv", mime="text/csv", key=f"csv_{job_id}",
    )
    dcol2.download_button(
        "⬇ Download XLSX", data=df_to_xlsx(df),
        file_name="results_all.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        key=f"xlsx_{job_id}",
    )


# ── Progress fragment (polls the in-process store every 1s) ────────────────
@st.fragment(run_every=1)
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
        pct = (done / st_total) if st_total else (1.0 if is_complete else 0.0)
        bar_label = f"{label} — {done}/{st_total}"
        if key == "stage1" and sp:
            bar_label += f" ({sp.get('passed', 0)} passed, {sp.get('filtered', 0)} filtered)"
        st.caption(f"{bar_label}  ·  {desc}")
        st.progress(min(max(pct, 0.0), 1.0))

    if is_complete:
        render_results(job_id)


# ── Page ───────────────────────────────────────────────────────────────────
st.title("✉️ EmailVerify")
st.caption("Validate email lists in minutes. No guessing.")

st.info(
    "Runs entirely in this Streamlit process — no separate backend. Mailbox "
    "(SMTP) checks egress on **port 25** from wherever this app runs. If port 25 "
    "is blocked, those addresses land in `reserved / smtp_connection_failed`. "
    "Use the self-test below to confirm port 25 is open.",
    icon="ℹ️",
)

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
        st.toast(f"Job {jid[:8]} started (1 email)")

with tab_csv:
    st.write("Upload a CSV/XLSX. Any email-like cell is extracted (matches `sample_test.csv`).")
    upload = st.file_uploader("Choose file", type=["csv", "xlsx", "xls"])
    if st.button("Validate file", type="primary", disabled=upload is None):
        emails = extract_emails(upload.name, upload.getvalue())
        if not emails:
            st.error("No email-like cells found in that file.")
        else:
            jid = start_job(emails, upload.name)
            st.session_state["job_id"] = jid
            st.toast(f"Job {jid[:8]} started ({len(emails)} emails)")

job_id = st.session_state.get("job_id")
if job_id:
    st.divider()
    st.subheader(f"Job {job_id}")
    progress_view(job_id)
