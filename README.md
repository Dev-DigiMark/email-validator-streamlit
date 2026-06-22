# email-validation-streamlit

Python port of the TypeScript email-validation backend.

## Architecture

- **Backend**: FastAPI (Python 3.11+), single uvicorn process, in-memory job store.
- **Concurrency**: pure asyncio. `asyncio.gather` replaces Node `worker_threads`;
  an `asyncio.Semaphore` replaces the `AsyncQueue`; a per-domain semaphore map
  replaces `DomainQueue`, honouring the same limits (strict=1, moderate=2,
  default=5) from `app.config.CONFIG`.
- **Progress**: no websockets. A job runs as an asyncio background task; the
  client polls `GET /jobs/{id}` for `{status, counts, progress}`.
- **UI**: Streamlit, calling FastAPI over HTTP and polling for progress.
- **SMTP**: requires outbound port 25 on the host running FastAPI.

## Layout

```
app/
  config.py          # ported from config/index.ts (frozen CONFIG)
  models.py          # ported from pipeline/types.ts (pydantic / Literal)
  checks/lists.py    # disposable / free / role / spam-trap / duplicate checks
  checks/syntax.py   # ported from checks/syntax.ts (normalisation, did_you_mean)
  checks/dns.py      # ported from checks/dns.ts (MX/SPF/DMARC/DKIM/DNSBL, 24h cache)
  checks/smtp.py     # ported from checks/smtp.ts (port-ladder state machine)
  data/              # list files copied verbatim from backend/data/
  pipeline/          # validation pipeline (later phases)
  store/             # in-memory job store (later phases)
scripts/
  smtp_live_check.py # guarded live mailbox check (SMTP_LIVE=1)
tests/
```

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit as needed
```

## Run locally

Two processes — the FastAPI backend and the Streamlit UI.

```bash
# Terminal 1 — backend (FastAPI on :8000)
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2 — UI (Streamlit on :8501)
export BACKEND_URL=http://localhost:8000
streamlit run streamlit_app.py
```

Open http://localhost:8501, paste emails or upload a CSV/XLSX (try the bundled
`sample_test.csv`), and watch progress poll until the job is `complete`.

## Environment variables

| Variable                    | Used by   | Default                      | Purpose |
|-----------------------------|-----------|------------------------------|---------|
| `BACKEND_URL`               | Streamlit | `http://localhost:8000`      | FastAPI base URL the UI calls/polls |
| `PORT` / `HOST`             | FastAPI   | `3001` / `localhost`         | CONFIG server bind (uvicorn flags override) |
| `CORS_ORIGIN`               | FastAPI   | `http://localhost:3000`      | Allowed CORS origin (UI also allowed via `*`) |
| `HELO_DOMAIN`               | SMTP      | `mail-checker.local`         | EHLO/HELO name sent during the SMTP probe |
| `SMTP_FROM`                 | SMTP      | `verify@mail-checker.local`  | MAIL FROM envelope address |
| `EXPORT_TMP_DIR`            | FastAPI   | `/tmp`                       | Scratch dir for `/export` |
| `RESULT_CACHE_ENABLED`      | pipeline  | `false`                      | Enable result cache (`true` to turn on) |
| `ALLOW_REPUTATION_PROMOTION`| scoring   | `false`                      | Allow reputation-based promotion |
| `SMTP_LIVE`                 | script    | unset                        | Set `1` to run the live SMTP check script |

See `.env.example`. Never commit a real `.env` (it is git-ignored).

## Test

```bash
pytest
```

The unit tests (`tests/test_syntax.py`, `tests/test_smtp_classify.py`, etc.)
need no network and run fully offline.

## Port 25 requirement (important)

The SMTP probe (`app/checks/smtp.py`) makes **outbound TCP connections on port
25** (plus the STARTTLS/implicit-TLS ladder ports 2525, 587, 465). **Most
residential ISPs and many cloud providers block outbound port 25**, so the SMTP
stage will silently degrade (connections fail → `smtp_connection_failed`) on
those networks. Run FastAPI on a host where port 25 is open.

> **Hetzner note:** outbound port 25 is the planned deployment target. Hetzner
> Cloud blocks port 25 by default on new accounts — you must request an unblock
> via support before SMTP verification will work there.

### Live SMTP check

A guarded script verifies one known-good and one known-bad mailbox; it is
skipped unless `SMTP_LIVE=1`:

```bash
SMTP_LIVE=1 python scripts/smtp_live_check.py
# optionally: GOOD_EMAIL=... BAD_EMAIL=... MX_HOST=...
```

## Deployment

The two processes deploy to **different homes** because of the port-25 constraint:

- **FastAPI backend** must run where outbound port 25 is open (e.g. a Hetzner
  VM, port 25 unblocked). Start it with the bundled `Procfile`:

  ```bash
  uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
  ```

  Put it behind a reverse proxy / firewall and expose it on a public URL.

- **Streamlit UI** can run on **Streamlit Community Cloud**, which serves
  `streamlit_app.py` directly from this repo. In the app's *Settings → Secrets*
  (or environment), set:

  ```toml
  BACKEND_URL = "https://your-fastapi-host.example.com"
  ```

  Streamlit Cloud itself does **not** need port 25 — only the FastAPI host does.

So: Streamlit Cloud hosts the UI; the Hetzner (or equivalent) box hosts FastAPI
with port 25 open; `BACKEND_URL` wires the two together.
