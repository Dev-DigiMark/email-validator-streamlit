"""Streamlit front end for the FastAPI email-validation backend.

Repo-root entrypoint for Streamlit Cloud. Talks to FastAPI over HTTP and polls
GET /jobs/{id} for live progress (no websockets).

Run locally:
    uvicorn app.main:app --port 8000      # backend
    streamlit run streamlit_app.py        # this UI

Set BACKEND_URL to point at a non-local backend.
"""
from __future__ import annotations

import io
import os

import httpx
import pandas as pd
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")

# Mirror config/index.ts -> stages (frontend feature parity).
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

# Column order matching the backend export.
DISPLAY_COLUMNS = [
    "email", "status", "sub_status", "score", "confidence", "flags",
    "did_you_mean", "mx_record", "smtp_provider", "smtp_response",
    "smtp_response_code", "is_free_provider", "is_role_address", "is_disposable",
    "promoted_from_reserved", "demoted_from_reserved", "score_breakdown",
]

st.set_page_config(page_title="EmailVerify", page_icon="✉️", layout="wide")


# ── HTTP helpers ──────────────────────────────────────────────────────────
def _client() -> httpx.Client:
    return httpx.Client(base_url=BACKEND_URL, timeout=30.0)


def submit_emails(emails: list[str]) -> dict:
    with _client() as c:
        r = c.post("/validate", json={"emails": emails})
    if r.status_code != 202:
        raise RuntimeError(_err_text(r))
    return r.json()


def submit_file(name: str, data: bytes) -> dict:
    with _client() as c:
        r = c.post("/validate", files={"file": (name, data, "application/octet-stream")})
    if r.status_code != 202:
        raise RuntimeError(_err_text(r))
    return r.json()


def get_job(job_id: str) -> dict | None:
    with _client() as c:
        r = c.get(f"/jobs/{job_id}")
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()


def get_results(job_id: str) -> dict:
    with _client() as c:
        r = c.get(f"/results/{job_id}")
    r.raise_for_status()
    return r.json()


def df_to_xlsx(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    return buf.getvalue()


def _err_text(r: httpx.Response) -> str:
    try:
        body = r.json()
        return body.get("error") or body.get("detail") or r.text
    except Exception:
        return r.text or f"HTTP {r.status_code}"


def backend_ok() -> bool:
    try:
        with _client() as c:
            c.get("/jobs/__healthcheck__")
        return True
    except Exception:
        return False


# ── Result rendering ──────────────────────────────────────────────────────
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


def render_results(job_id: str, counts: dict) -> None:
    payload = get_results(job_id)
    results = payload.get("results", [])
    counts = payload.get("counts", counts) or counts

    st.subheader(f"Results · {len(results)} emails")

    # Bucket summary (mirrors BucketGrid).
    cols = st.columns(len(STATUS_LABELS))
    for col, (key, label) in zip(cols, STATUS_LABELS.items()):
        col.metric(label, counts.get(key, 0))

    promoted = counts.get("promoted_to_valid", 0)
    demoted = counts.get("demoted_to_invalid", 0)
    if promoted or demoted:
        st.caption(f"Promotions: {promoted} promoted to valid · {demoted} demoted to invalid")

    df = _to_dataframe(results)

    # Sub-status filter (mirrors SubStatusFilter).
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

    # Download buttons — built client-side from the full results df (same
    # columns/flattening as the backend export).
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


# ── Progress fragment (polls every 1s) ────────────────────────────────────
@st.fragment(run_every=1)
def progress_view(job_id: str) -> None:
    job = get_job(job_id)
    if job is None:
        st.error("Job not found.")
        return

    status = job.get("status", "pending")
    counts = job.get("counts", {}) or {}
    progress = job.get("progress") or {}

    if status == "failed":
        st.error("Validation failed. Check the backend logs.")
        return

    is_complete = status == "complete"
    total = counts.get("total", 0)
    processed = counts.get("processed", 0)

    if is_complete:
        st.success(f"Complete · {processed}/{total} processed")
    else:
        st.info(f"Status: {status} · {processed}/{total} processed")
        st.progress(processed / total if total else 0.0)

    # Per-stage progress bars.
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
        st.session_state["done_job"] = job_id
        render_results(job_id, counts)


# ── Page ──────────────────────────────────────────────────────────────────
st.title("✉️ EmailVerify")
st.caption("Validate email lists in minutes. No guessing.")

st.warning(
    "⚠️ **Port 25 caveat:** mailbox (SMTP) verification needs outbound port 25 "
    "on the host running FastAPI. Cloud hosts often block it — affected addresses "
    "land in `reserved / temp_error`. This is an infra limit, not a bug.",
    icon="⚠️",
)

with st.expander("Backend connection", expanded=False):
    st.code(BACKEND_URL, language="text")
    if not backend_ok():
        st.error("Cannot reach the FastAPI backend. Start it with "
                 "`uvicorn app.main:app --port 8000` or set BACKEND_URL.")

tab_single, tab_csv = st.tabs(["Single email", "CSV / Excel upload"])

with tab_single:
    email = st.text_input("Email address", placeholder="someone@example.com")
    if st.button("Validate email", type="primary", disabled=not email.strip()):
        try:
            resp = submit_emails([email.strip()])
            st.session_state["job_id"] = resp["jobId"]
            st.session_state.pop("done_job", None)
            st.toast(f"Job {resp['jobId'][:8]} created ({resp['total']} email)")
        except Exception as err:
            st.error(f"Submit failed: {err}")

with tab_csv:
    st.write("Upload a CSV/XLSX. Any email-like cell is extracted (matches `sample_test.csv`).")
    upload = st.file_uploader("Choose file", type=["csv", "xlsx", "xls"])
    if st.button("Validate file", type="primary", disabled=upload is None):
        try:
            resp = submit_file(upload.name, upload.getvalue())
            st.session_state["job_id"] = resp["jobId"]
            st.session_state.pop("done_job", None)
            st.toast(f"Job {resp['jobId'][:8]} created ({resp['total']} emails)")
        except Exception as err:
            st.error(f"Submit failed: {err}")

job_id = st.session_state.get("job_id")
if job_id:
    st.divider()
    st.subheader(f"Job {job_id}")
    progress_view(job_id)
