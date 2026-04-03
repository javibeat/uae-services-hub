# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

UAE Community Services Hub — a free directory for UAE licensed professionals. Users register, log in (JWT auth), and list/browse/manage professional services. All providers must confirm they hold a valid UAE trade license. Single-page app with Express backend and monolithic `index.html` frontend (HTML + CSS + vanilla JS, no build step).

## Commands

```bash
npm install          # install dependencies
npm start            # start server (node server.js), default port 3000
npm run dev          # same as start (no hot-reload)
```

No test runner, linter, or build pipeline is configured.

## Architecture

- **`server.js`** — Express server with all API routes, JWT auth middleware, rate limiting, input sanitization, and file-based JSON persistence (`data/*.json`).
- **`index.html`** — Entire frontend in one file. Auth flow (register/login/logout), service CRUD, search/filter, reporting. Communicates via `fetch` to `/api/*` with Bearer tokens.
- **`data/`** — Auto-created directory with `users.json`, `services.json`, `reports.json` (flat JSON arrays). Also stores `.jwt_secret` for persistent JWT signing key.

### API Routes

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/register` | No | Create account (PDPL consent tracked) |
| POST | `/api/auth/login` | No | Log in, get JWT |
| GET | `/api/auth/me` | Yes | Current user profile |
| GET | `/api/services` | No | List all services (public, userId stripped) |
| GET | `/api/services/mine` | Yes | Current user's services |
| GET | `/api/services/:id` | No | Single service detail |
| POST | `/api/services` | Yes | Create listing (license type required) |
| PUT | `/api/services/:id` | Yes | Update own listing |
| DELETE | `/api/services/:id` | Yes | Delete own listing |
| POST | `/api/services/:id/report` | Yes | Report listing (one per user per service) |

### Key Details

- JWT secret: reads `JWT_SECRET` env var, or generates and persists a random 64-byte hex in `data/.jwt_secret`.
- Bcrypt cost factor: 12 rounds.
- Password minimum: 8 characters.
- Rate limiting: in-memory per IP+action (resets on restart).
- PDPL compliance: consent timestamp + version stored on user record and on each service listing.
- Service validation: category and license type checked against fixed arrays (`VALID_CATEGORIES`, `LICENSE_TYPES`). At least one contact method required.
- Reports: deduplicated per user per service.
- Route order matters: `/services/mine` must be declared before `/services/:id`.

### Legal Context (UAE)

The platform references these UAE laws in its Terms:
- Federal Decree-Law No. 32/2021 (Commercial Companies) — trade license requirement
- Federal Decree-Law No. 45/2021 (PDPL) — personal data protection
- Federal Decree-Law No. 34/2021 (Cybercrime Law) — prohibited content
