# Sentinel-Bench — Runbook

## Comandos rápidos

```bash
cd /root/projects/sentinel-bench

# Ingesta completa (todas las fuentes)
python -m ingest.ingest --source=all

# Solo KEV (rápido, 1 GET)
python -m ingest.ingest --source=KEV

# Solo EPSS incremental
python -m ingest.ingest --source=EPSS --limit=2000

# Recomputar todos los scores
python -m ingest.score --limit=2000

# Briefing diario (envía Telegram si hay cambio)
python -m ingest.diff

# Briefing forzado (ignora diff)
python -m ingest.diff --force

# Dry-run del briefing
python -m ingest.diff --dry-run
```

## Troubleshooting

### "Faltan PUBLIC_SUPABASE_URL / PUBLIC_SUPABASE_ANON_KEY"

El dashboard Astro necesita esas env vars en build time. En local:
```bash
cd dashboard
PUBLIC_SUPABASE_URL=https://<ref>.supabase.co \
PUBLIC_SUPABASE_ANON_KEY=<anon> \
npm run dev
```
En Vercel: Project → Settings → Environment Variables.

### "NVD rate limit 5/30s"

Sin API key NVD throttle = 5 req cada 30s. Con key = 50. Generala en
<https://nvd.nist.gov/request-products> (gratis) y agregala a `.env` como `NVD_API_KEY`.

### "404 en /vulnerabilities?published_at=..."

El campo correcto es `first_seen_at`. La query ya está corregida en `ingest/score.py`.

### "is_kev se borra al re-correr ingest"

El merge preserva flags previos via `_fetch_existing_vulns()` (en `ingest.py`).
Si volvés a tener el problema, verificá que `upsert_vulnerabilities` esté
llamando esa función antes de generar el hash.

### "Briefing no se envía"

Revisar `delivery_runs`:
```sql
select started_at, briefing_sent, briefing_reason, errors
from delivery_runs
order by started_at desc
limit 5;
```

### "Score no cambia al re-correr"

`risk_scores` es append-only. Cada ejecución agrega filas nuevas. El dashboard
lee la **última** por `cve_id`. Para "limpiar" el histórico: `delete from risk_scores;` y
re-correr `python -m ingest.score`.

## Health check

```bash
# ¿Hay datos?
psql $DB_URL -c "select count(*) from advisories; select count(*) from vulnerabilities; select count(*) from risk_scores;"

# ¿Las fuentes respondieron OK?
psql $DB_URL -c "select started_at, sources_ok, sources_attempted, briefing_sent, briefing_reason from delivery_runs order by started_at desc limit 5;"

# ¿Alguna fuente caída?
psql $DB_URL -c "select http_statuses, errors from delivery_runs order by started_at desc limit 1;"
```

## Datos de contacto

- Repo: github.com/iamtweaks/sentinel-bench
- Dashboard: <https://sentinel-bench.vercel.app>
- Privacidad: <https://github.com/iamtweaks/sentinel-bench/issues>