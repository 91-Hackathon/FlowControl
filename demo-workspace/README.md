# greeter

A tiny HTTP service that returns a greeting. Deployed to production by the
GitHub Actions workflow in `.github/workflows/deploy.yml`.

## Layout
- `app.py` — the service (one endpoint)
- `.env` — runtime secrets (API key, signing secret, deploy-hook account)
- `.github/workflows/deploy.yml` — CI/CD: lint, then deploy on push to `main`

## Dev
    python3 app.py        # serves on :8000
