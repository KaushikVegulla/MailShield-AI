# Hosting

MailShield runs the same way as ShieldNet: backend on Render, dashboard on Vercel, code on GitHub. There is no database in the MVP — analysis is stateless.

## Backend — Render

1. Render → New → Blueprint → connect the `MailShield-AI` repo. The `render.yaml` at the repo root creates one free web service, `mailshield-backend`, from `backend/` (health check `/health`).
2. After the first deploy, note the service URL, e.g. `https://mailshield-backend-xxxx.onrender.com`.
3. Once the Vercel URL is known, set the service env var `CORS_ORIGINS` to the dashboard origin (plus `http://localhost:5173` for local dev) and redeploy.

Notes:
- Free tier sleeps after inactivity; the first request after sleep takes ~30–60 s (hosting cold start, not analysis time).
- The hosted backend has no ML model file (the trained joblib is not committed — binaries are not pushed), so `ml_prediction.model_available` is false there and the hybrid score renormalises over rules + anomaly. The dashboard shows this honestly. To ship the model later, train it during the Render build (`ml/download_data.py` + `ml/train.py` as a pre-build step) — not done yet because the corpus hosts can be slow from datacenter IPs.

## Frontend — Vercel

1. Vercel → Add New Project → import `MailShield-AI`.
2. **Root Directory: `frontend`** (important — the repo root has no app; ShieldNet's first deploy failed for exactly this).
3. Environment variable: `VITE_API_URL` = the Render backend URL from step 2 above.
4. Deploy. For a public demo link, turn off Deployment Protection (Settings → Deployment Protection) if it is enabled.

## Verify

- `GET <render-url>/health` → `{"status":"ok", ...}`
- Open the Vercel URL: the pill should read **LIVE**, loading the PayPal sample and analysing it should return a phishing verdict (score computed from rules + anomaly on the hosted backend).
