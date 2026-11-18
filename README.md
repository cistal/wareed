# WAREED prototype (simulated data)
FastAPI backend (`api/index.py`) + static dashboard (`public/`). JWT login, role-based access, rule-based correlation with explainable alerts.
Demo accounts: admin, doctor, security, nurse. Password: Wareed@2026 (set DEMO_PASSWORD).

## Deploy on Vercel
Set env var SECRET_KEY to a long random string, then import the folder (Framework Preset: Other). Vercel serves `public/` and runs `api/index.py` as a Python function.
Note: serverless functions keep state in memory only, so simulated scenarios reset when the function restarts. For real persistence, add PostgreSQL (e.g. Neon) and set DATABASE_URL.

## Run locally
pip install -r requirements.txt uvicorn
uvicorn api.index:app --reload   # http://localhost:8000
Or: docker build -t wareed . && docker run -p 8000:8000 -e SECRET_KEY=change-me wareed

## Roles
admin and security_analyst: view, review, simulate. doctor: view, review. nurse: view only.
