# Sentinel-Bench

Laboratorio personal de **Cyber Threat Intelligence**. Recolecta vulnerabilidades
de fuentes públicas (CISA KEV, NVD, EPSS, GitHub Security Advisories, MSRC),
las prioriza por **evidencia real de explotación** (no solo CVSS), entrega un
briefing diario por Telegram y expone un dashboard público.

> 🔒 100% inteligencia pública. Aislado de cualquier SOC corporativo. Sin IoCs
> privados, sin scraping de infra interna. Apto como portfolio Blue Team.

## Arquitectura

```
CISA KEV ─┐
NVD ───────┼─→ ingest.py ─→ Supabase ─┬─→ diff.py ─→ Telegram (briefing)
EPSS ──────┤    (normalize/dedupe/score)│              ↑
GHSA ──────┤                           ├─→ Astro dashboard → Vercel
MSRC ──────┘                           │
                                      └─→ cron (orquestación, no-agent)
```

* **Ingesta**: scripts Python stdlib-only (`urllib`, `json`, `hashlib`). Sin LLM.
* **Scoring**: SQL-side, fórmula v1 explicable, sin LLM.
* **Briefing**: LLM (Hermes) solo se invoca cuando el top-5 cambió.
* **Persistencia**: Supabase Postgres con RLS (anon read-only).
* **Entrega**: Telegram bot existente, dashboard Astro static en Vercel.

## Estructura

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
│       ├── 0001_init.sql      — schema + seed de fuentes
│       └── 0002_rls.sql       — RLS: anon read-only
├── ingest/
│   ├── ingest.py              — CLI: --source=KEV|EPSS|GHSA|NVD|MSRC|all
│   ├── score.py               — recompute risk_scores
│   ├── diff.py                — generate Telegram briefing
│   └── lib/
│       ├── config.py          — source catalog + env loader
│       ├── http.py            — GET con retry/backoff
│       ├── hash.py            — sha256 canónico para idempotencia
│       ├── supabase.py        — PostgREST client
│       ├── normalize.py       — KEV/EPSS/GHSA/NVD/MSRC → shape común
│       └── score.py           — fórmula 0..100
├── cron/
│   └── (shims para `hermes cron`)
└── dashboard/                 — Astro static
    ├── src/pages/{index,sources,about}.astro
    ├── src/lib/{sb,render}.ts
    └── public/styles.css
```

## Fuentes (todas validadas con `curl`)

| Fuente | URL | Auth | Cobertura |
|---|---|---|---|
| CISA KEV | `feeds/known_exploited_vulnerabilities.json` | No | Vulns explotadas |
| NVD CVE 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | No (con API key sube throttle) | CVEs + CVSS |
| FIRST EPSS | `api.first.org/data/v1/epss` | No | Probabilidad de exploit |
| GitHub Advisories | `api.github.com/advisories` | No | CVEs + PoC + vendor |
| MSRC CVRF | `api.msrc.microsoft.com/cvrf/v2.0/updates` | No | Microsoft security updates |

## Quickstart

```bash
# 1. Aplicar migraciones (ya aplicado en este repo; el script genera el SQL)
psql $SUPABASE_DB_URL -f supabase/migrations/0001_init.sql
psql $SUPABASE_DB_URL -f supabase/migrations/0002_rls.sql

# 2. Ingerestar todo
python -m ingest.ingest --source=KEV
python -m ingest.ingest --source=EPSS --limit=2000
python -m ingest.ingest --source=GHSA --limit=100
python -m ingest.ingest --source=NVD --limit=200   # requiere CVEs conocidos
python -m ingest.ingest --source=MSRC --limit=200

# 3. Recomputar scores
python -m ingest.score --limit=2000

# 4. Briefing (envía Telegram solo si el top-5 cambió)
python -m ingest.diff

# 5. Dashboard local
cd dashboard && npm install && npm run dev
```

## Configuración

Variables en `/root/.hermes/.env`:

```bash
SUPABASE_SERVICE_ROLE_KEY=...    # server-side writes (ingest)
SUPABASE_ANON_KEY=...            # anon read-only (dashboard)
NVD_API_KEY=...                  # opcional; sube throttle 5→50 req/30s
TELEGRAM_BOT_TOKEN=...
TELEGRAM_HOME_CHANNEL=...
```

Las env vars del dashboard Astro se configuran como `PUBLIC_SUPABASE_URL`
y `PUBLIC_SUPABASE_ANON_KEY` en Vercel.

## Cron

| Frecuencia | Comando |
|---|---|
| Cada 30 min | `python -m ingest.ingest --source=KEV,EPSS,GHSA` |
| Cada 6h | `python -m ingest.ingest --source=NVD` |
| 7am ARG (0 11 UTC) | `python -m ingest.score --limit=2000 && python -m ingest.diff` |
| Dom 10am ARG | `python -m ingest.diff --force` (resumen semanal) |

Ver `docs/RUNBOOK.md` para detalles y troubleshooting.

## Costos

* Vercel Hobby: **$0**
* Supabase Free tier (500MB + 2GB egress): **$0**
* Fuentes públicas: **$0**
* LLM (solo cuando hay cambios): **<$1/mes**

## Licencia

MIT. Hecho para portfolio Blue Team. Si encontrás algo que pueda ser sensible
(infra corporativa, IoCs privados, datos laborales), abrí un issue o contactame
directamente.

## Donations / Sponsors

If Sentinel-Bench saved you time on a triage or a Tuesday patch, you can
chip in via Bitcoin (segwit, mainnet):

```
bc1q d2rpqfv glkzzce5 j7ryey4k 9c9sfefd wf9juax
```

Full address: `bc1qd2rpqfvglkzzce5j7ryey4k9c9sfefdwf9juax`

⚠️ The address above is a BloFin exchange deposit address (custodial),
**not** a personal non-custodial wallet. Funds land in a BloFin pooled
account under my user account. Verify the address matches exactly
before sending — on-chain transactions are irreversible.
<!-- branch: feat/sentinel-bench-mvp | last commit on this branch differs from main -->
