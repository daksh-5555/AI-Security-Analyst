# Running a DVWA lab for authenticated assessment (M15, ADR-0018)

The scanner can authenticate into a **local** deliberately-vulnerable web lab
(DVWA) with known credentials and then crawl and probe its authenticated
surface. This is a development/lab feature: it is off by default, restricted to
authorized local addresses, and refused when `APP_ENV` is staging or production.
It performs a single login with the credentials you supply and never attempts
credential guessing.

## 1. Start DVWA locally, bound to loopback

Use the official image, published only on 127.0.0.1 so nothing is exposed:

```bash
docker run --rm -it -p 127.0.0.1:8080:80 ghcr.io/digininja/dvwa:latest
```

Open http://127.0.0.1:8080, click **Create / Reset Database**, and set
**DVWA Security** to **Low** (DVWA → Security). Default credentials are
`admin` / `password`.

Docker is not required by this project; a native PHP/MySQL DVWA install bound to
loopback works the same way. Only loopback/local addresses are accepted.

## 2. Enable the feature (development only)

```bash
WEB_AUTH_LAB_ENABLED=true
WEB_TARGET_ALLOWED_HOSTS=127.0.0.1
WEB_TARGET_ALLOWED_LOCAL_NETWORKS=127.0.0.0/8
RUNTIME_PROBES_ENABLED=true           # opt-in; probes are off by default
```

The login form fields default to DVWA (`/login.php`, `user_token`, `username`,
`password`, `Login=Login`) and are configurable via `WEB_AUTH_LAB_*` settings.

## 3. Assess it through the API

```bash
# Register the local target (owner-confirmed authorization)
POST /api/v1/assessments/{id}/web-target
  {"base_url":"http://127.0.0.1:8080/","authorization_statement":"...","confirm_authorized":true}

# Establish the lab session (one login; the password is used once, never stored)
POST /api/v1/assessments/{id}/web-target/lab-credentials
  {"username":"admin","password":"password"}

# Run the assessment (or a workflow); the crawler and probes now see the
# authenticated surface
POST /api/v1/assessments/{id}/analysis-runs
```

Only the resulting session cookie is persisted, and it is never returned by the
API, logged, or placed in evidence or reports. Clear it with
`DELETE /api/v1/assessments/{id}/web-target/lab-credentials`.

## 4. Automated integration test (opt-in)

With a lab running, `tests/test_dvwa_integration.py` runs end-to-end:

```bash
DVWA_URL=http://127.0.0.1:8080/ pytest tests/test_dvwa_integration.py
```

Without `DVWA_URL` it skips, so the regular suite needs no lab.

## Safety boundaries

- Local addresses only; the feature is forbidden outside development.
- All requests go through the guarded (SSRF-safe, host-bound) HTTP client.
- Probes stay read-only and non-destructive (inert XSS markers, boolean-only
  SQLi); no destructive requests, no credential guessing, no data extraction,
  no denial-of-service testing.
- Inside a workflow, runtime probes still require the human approval gate.
