# Safe AI Mailroom Agent

Public HTTPS endpoint implementing `propose` and `commit` for the
`ga5-mailroom-action-gate/v2` profile.

## What it does

- Validates the entire request before calling the model.
- Computes the required canonical `inputDigest`.
- Uses OpenRouter once per unique dossier content, then caches stable decisions.
- Returns one schema-valid proposal per dossier.
- Persists proposals, evaluation verifier keys, receipts, and outcomes in SQLite.
- Verifies every Ed25519 receipt signature before returning terminal outcomes.
- Rejects malformed requests, duplicate dossier IDs, unknown evaluations, changed
  content for an evaluation ID, invalid/moved/duplicate receipts, and proposal mismatches.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and add OPENROUTER_API_KEY
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Health check: `GET /health`

## Deploy on Render

1. Put this folder in a GitHub repository.
2. In Render, choose **New + > Blueprint** and select the repository.
3. Render reads `render.yaml`.
4. Add the environment variable `OPENROUTER_API_KEY`.
5. Deploy. Use the generated `https://...onrender.com/` URL as the submitted endpoint.

The submitted URL must have no query string, credentials, or fragment.

## Important

- Keep `OPENROUTER_API_KEY` only in the hosting provider secret settings.
- SQLite is persisted on Render using the configured 1 GB disk.
- Do not put raw customer mail, secrets, or canary text into tool arguments.
