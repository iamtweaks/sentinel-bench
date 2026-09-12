# Sentinel-Bench

Personal **Cyber Threat Intelligence** lab. Collects vulnerabilities from public sources (CISA KEV, NVD, EPSS, GitHub Security Advisories, MSRC, and 11 OT/ICS vendor feeds), prioritizes them by **real evidence of exploitation** (not just CVSS), delivers a daily briefing via Telegram, and exposes a public dashboard + REST API.

> 🔒 100% public intelligence. Isolated from any corporate SOC. No private IoCs, no internal infra scraping. Suitable as a Blue Team portfolio.

## Architecture

```
CISA KEV ─┐
NVD ───────┼─→ ingest.py ─→ Supabase ─┬─→ diff.py ─→ Telegram (briefing)
EPSS ──────┤    (normalize/dedupe/score)│              ↑
GHSA ──────┤                           ├─→ Astro dashboard → Vercel
MSRC ──────┘                           │
                                      └─→ cron (orchestration, agentless)
11 OT sources (ABB, Rockwell, Siemens, Moxa, …) ──→
```

* **Ingest**: stdlib-only Python scripts (`urllib`, `json`, `hashlib`). No LLM.
* **Scoring**: SQL-side, explainable v1 formula, no LLM.
* **Briefing**: LLM (Hermes) is only invoked when the top-5 changes.
* **Persistence**: Supabase Postgres with RLS (anon read-only).
* **Delivery**: existing Telegram bot, Astro static dashboard on Vercel.
* **Coverage**: 5 IT sources + 11 OT/ICS sources = 16 total.

## Structure

```
sentinel-bench/
├── README.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── RUNBOOK.md
│   ├── SCORING.md
│   └── ROLLBACK.md
├── supabase/
│   └── migrations/
│       ├── 0001_init.sql      — schema + source seed
│       ├── 0002_rls.sql       — RLS: anon read-only
│       └── 0003_latest_risk_scores_view.sql — dashboard view
├── ingest/
│   ├── ingest.py              — CLI: --source=KEV|EPSS|GHSA|NVD|MSRC|<OT>|all
│   ├── score.py               — recompute risk_scores
│   ├── diff.py                — generate Telegram briefing
│   └── lib/
│       ├── config.py          — 16 sources (5 IT + 11 OT) + env loader
│       ├── http.py            — GET with retry/backoff
│       ├── hash.py            — canonical sha256 for idempotency
│       ├── supabase.py        — PostgREST client
│       ├── normalize.py       — KEV/EPSS/GHSA/NVD/MSRC/OT → common shape
│       └── score.py           — 0..100 formula
├── cron/
│   ├── sentinel_bench_hourly.sh
│   ├── sentinel_bench_every8h.sh   — full --source=all pull
│   ├── sentinel_bench_daily.sh
│   └── sentinel_bench_weekly.sh
└── dashboard/                 — Astro static on Vercel
    ├── src/pages/
    │   ├── index.astro            — landing
    │   ├── dashboard.astro        — vuln table + filters
    │   ├── sources.astro          — source catalog
    │   ├── status.astro           — operational status
    │   ├── about.astro
    │   ├── api-docs.astro         — public API docs
    │   └── api/v1/                — public REST API
    │       ├── index.json.ts
    │       ├── vulnerabilities.json.ts
    │       ├── advisories.json.ts
    │       ├── sources.json.ts
    │       └── status.json.ts
    ├── src/lib/{sb,render}.ts
    └── public/styles.css
```

## Sources (all validated)

### IT vulnerabilities (5 sources)

| Source | Coverage |
|---|---|
| CISA KEV | Vulnerabilities with active exploitation |
| NVD CVE 2.0 | CVEs + CVSS |
| FIRST EPSS | Exploit probability |
| GitHub Security Advisories | CVEs + PoC + vendor |
| MSRC CVRF | Microsoft security updates |

### OT / ICS vulnerabilities (11 sources)

| Source | Vendor focus |
|---|---|
| ABB | Industrial automation |
| Rockwell Automation | Allen-Bradley / Logix |
| CERT@VDE | Industrial + IoT |
| Fortinet | Network + OT appliances |
| Siemens | Industrial + ICS |
| Cisco | Networking + IoT |
| NVD ICS | ICS-tagged CVEs |
| Palo Alto Networks | Firewalls + OT |
| CISA ICS | ICS advisories |
| Moxa | Industrial networking |

Run any single source or the full set:

```bash
python -m ingest.ingest --source=KEV
python -m ingest.ingest --source=all       # all 16 IT + OT sources
```

## Quickstart

```bash
# 1. Apply migrations (already applied for this repo; the script generates the SQL)
psql $SUPABASE_DB_URL -f supabase/migrations/0001_init.sql
psql $SUPABASE_DB_URL -f supabase/migrations/0002_rls.sql
psql $SUPABASE_DB_URL -f supabase/migrations/0003_latest_risk_scores_view.sql

# 2. Ingest everything
python -m ingest.ingest --source=KEV
python -m ingest.ingest --source=EPSS --limit=2000
python -m ingest.ingest --source=GHSA --limit=100
python -m ingest.ingest --source=NVD --limit=200   # requires known CVEs
python -m ingest.ingest --source=MSRC --limit=200
python -m ingest.ingest --source=all               # all 16 IT + OT sources

# 3. Recompute scores
python -m ingest.score --limit=2000

# 4. Briefing (sends to Telegram only when the top-5 changes)
python -m ingest.diff

# 5. Dashboard local
cd dashboard && npm install && npm run dev
```

## Configuration

Variables in `/root/.hermes/.env`:

```bash
SUPABASE_SERVICE_ROLE_KEY=...    # server-side writes (ingest)
SUPABASE_ANON_KEY=...            # anon read-only (dashboard)
NVD_API_KEY=...                  # optional; bumps throttle 5→50 req/30s
TELEGRAM_BOT_TOKEN=...
TELEGRAM_HOME_CHANNEL=...
```

Dashboard Astro env vars are configured as `PUBLIC_SUPABASE_URL` and
`PUBLIC_SUPABASE_ANON_KEY` in Vercel.

## REST API

Read-only public API at `https://sentinel-bench.vercel.app/api/v1/`:

- `index.json` — manifest with all endpoints
- `vulnerabilities.json[?cve=]` — vulnerabilities with risk scores and remediation
- `advisories.json` — official vendor advisories
- `sources.json` — source catalog + health
- `status.json` — operational status

CORS: `https://sentinel-bench.vercel.app`. Full docs at `/api-docs/`.

## Contributing

Issues and PRs are welcome at [github.com/iamtweaks/sentinel-bench/issues](https://github.com/iamtweaks/sentinel-bench/issues).

**Best ways to contribute:**

- **Report a bug** — open an issue with steps to reproduce, expected vs actual behavior, and the dashboard URL.
- **Request a new OT source** — open an issue with the vendor advisory URL format and a recent sample. If it's a public feed that returns JSON/XML/CSV, we'll wire it.
- **Improve scoring** — the formula is in `ingest/lib/score.py`. Open an issue with the rationale (which signals you want weighted higher and why) before sending a PR.
- **Triage false positives** — open an issue with the CVE ID and the field that's wrong (severity, KEV flag, vendor). We re-ingest from source.
- **Docs** — `docs/` folder. Spelling, missing context, broken links: send a PR.

**Don't open issues for:** deployment problems on your own fork (use Vercel/Supabase support), generic CVE questions (use NVD/CISA directly), or anything that requires access to private infrastructure.

Labels we use: `bug`, `enhancement`, `new-source`, `scoring`, `docs`, `good-first-issue`.

## Cron

| Frequency | Command |
|---|---|
| Every 30 min | `python -m ingest.ingest --source=KEV,EPSS,GHSA` |
| Every 8h | `python -m ingest.ingest --source=all` (full IT+OT pull) |
| 7am ARG (0 11 UTC) | `python -m ingest.score --limit=2000 && python -m ingest.diff` |
| Sun 10am ARG | `python -m ingest.diff --force` (weekly summary) |

See `docs/RUNBOOK.md` for details and troubleshooting.

## Costs

* Vercel Hobby: **$0**
* Supabase Free tier (500MB + 2GB egress): **$0**
* Public sources: **$0**
* LLM (only when something changes): **<$1/month**

## License

MIT. Made for the Blue Team portfolio. If you find something that could be
sensitive (corporate infra, private IoCs, work data), open an issue or
contact me directly.

## Donations / Sponsors

If Sentinel-Bench saved you time on a triage or a Tuesday patch, you can
chip in via Solana (mainnet):

```
8ZNN5bomP4SVfDthfcFgXBSoZAgtngZAcKscddhoPrGA
```

That's a personal Phantom wallet address (non-custodial — I hold the keys).
Verify the address matches exactly before sending; on-chain transactions
are irreversible. SPL tokens accepted (SOL, USDC, etc.).
