# Showcase runbook — AI Security Analyst

How to run the whole project locally to demo it. No AI/LLM key required, nothing
to pay for. You run three things: the **backend** (API), the **worker** (runs
analyses in the background), and the **frontend** (the web UI).

Login for the demo user: **`demo@example.com`** / **`correct horse battery staple demo`**

---

## 0. Prerequisites (install once)

- **Python 3.12** — check with `python3 --version`
- **Node.js 18+** and npm — check with `node --version`

## 1. One-time setup

All commands run from the project root: `Vulnerability_backend-main/`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

The `.env` file (already created) configures everything, including turning the
LLM **off**. You don't need to edit it.

Create the database tables and a ready-to-use admin user:

```bash
alembic upgrade head
python scripts/create_demo_user.py
```

A sample app to scan already exists at `repositories/sample/` (a tiny program
with an intentional security flaw), so you have something to find.

## 2. Run it (three terminals)

Open three terminal tabs, all in the project root, and in **each** first run
`source .venv/bin/activate`.

**Terminal 1 — backend API:**
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — background worker** (so analysis runs actually process):
```bash
python -m app.worker
```

**Terminal 3 — the web UI:**
```bash
cd frontend
npm install        # first time only
npm run dev
```

## 3. Open the app

Go to **http://127.0.0.1:5173** and sign in with the demo credentials above.

## 4. Demo path (what to click)

1. **Assessments → New assessment → Create** (type: Repository).
2. On the detail page, in **Repository source**, paste this path and click
   **Configure source**:
   ```
   /Users/dakshkumar/Desktop/Vulnerability_backend-main/repositories/sample
   ```
3. Click **Start run**. Watch the run go **Queued → Completed** on its own.
4. Click **View findings** → expand the finding → see the detail, the evidence,
   and the (advisory, off) AI panel.
5. Open **Report** → executive summary + a rendered report you can download.
6. **Audit Logs** and **Administration** (admin-only) show the recorded trail and
   security monitoring.

## 5. Stopping

Press `Ctrl+C` in each of the three terminals.

---

## Notes / troubleshooting

- **No AI key needed.** The deterministic core does all the scanning. The "AI
  explanation" button is optional and left off in `.env`
  (`LLM_EXPLANATIONS_ENABLED=false`). The code only supports Anthropic (Claude);
  DeepSeek would require new backend code, so a DeepSeek key will not work here.
- **"Repository path not allowed"** when configuring a source: the path must be
  inside `REPOSITORY_ALLOWED_ROOTS` in `.env`. It is set to the project's
  `repositories/` folder — put any code you want to scan under there.
- **A run stays "Queued" forever:** the background worker (Terminal 2) isn't
  running. Start it.
- **Login bounces back to the sign-in page after a refresh:** make sure the
  backend is running with `.env` loaded (`AUTH_COOKIE_SECURE=false` is required
  for local http); this is already set.
- **The access token lives in memory only** and the refresh token is an
  HttpOnly cookie — a page reload silently re-authenticates; a full sign-out
  clears it. This is the intended, secure behaviour.
