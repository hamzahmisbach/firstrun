# acme-app

Customer portal API for Acme. Express + Postgres.

## Setup

```sh
cp .env.example .env   # then fill in the keys from 1Password
npm install
docker compose up -d postgres redis
npm run migrate
npm run dev
```

The API listens on http://localhost:3000. Health check: `GET /healthz`.

## Deploy

Merges to `main` deploy to staging through GitHub Actions; production is promoted by hand
with `gh workflow run promote.yml`.
