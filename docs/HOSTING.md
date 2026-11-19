# Hosting

MailShield runs the same way as ShieldNet: backend on Render, dashboard on Vercel, code on GitHub. There is no database in the MVP — analysis is stateless.

## Backend — Render

1. Render → New → Blueprint → connect the `MailShield-AI` repo. The `render.yaml` at the repo root creates one free web service, `mailshield-backend`, from `backend/` (health check `/health`).
2. After the first deploy, note the service URL, e.g. `https://mailshield-backend-xxxx.onrender.com`.
3. Once the Vercel URL is known, set the service env var `CORS_ORIGINS` to the dashboard origin (plus `http://localhost:5173` for local dev) and redeploy.

Notes:
- Free tier sleeps after inactivity; the first request after sleep takes ~30–60 s (hosting cold start, not analysis time).
- The trained model binary is not committed (binaries are not pushed), so the Render build trains it instead: the build command runs `ml/train_build.py` after installing requirements, which downloads the same public corpora, trains the TF-IDF + Logistic Regression pipeline and saves the artefact where the backend loads it. The step is guarded — if training fails (for example a corpus host is unreachable) the deploy still succeeds and the backend runs without the ML component, renormalising the hybrid score over rules + anomaly, with the dashboard saying so. `GET /health` reports `"ml_model": "loaded"` or `"absent"` so the state is checkable at any time.

## Frontend — Vercel

1. Vercel → Add New Project → import `MailShield-AI`.
2. **Root Directory: `frontend`** (important — the repo root has no app; ShieldNet's first deploy failed for exactly this).
3. Environment variable: `VITE_API_URL` = the Render backend URL from step 2 above.
4. Deploy. For a public demo link, turn off Deployment Protection (Settings → Deployment Protection) if it is enabled.

## Verify

- `GET <render-url>/health` → `{"status":"ok", ...}`
- Open the Vercel URL: the pill should read **LIVE**, loading the PayPal sample and analysing it should return a phishing verdict (score computed from rules + anomaly on the hosted backend).
