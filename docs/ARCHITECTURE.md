# Arquitectura

## Componentes

```
┌─────────────────┐
│   Fuentes       │  ← CISA KEV, NVD, EPSS, GHSA, MSRC
└────────┬────────┘
         │ HTTP GET
┌────────▼──────────────────────────┐
│  ingest/ingest.py                 │  urllib stdlib + retry/backoff
│  • normalize() per source         │
│  • content_hash = sha256(raw)     │  ← idempotencia
│  • upsert advisories (PostgREST)  │
│  • upsert vulnerabilities (merge) │
└────────┬──────────────────────────┘
         │ HTTPS
┌────────▼──────────────────────────┐
│   Supabase Postgres               │
│   • sources, advisories, vulns    │
│   • risk_scores (append-only)     │
│   • delivery_runs (audit)         │
└────────┬──────────────────────────┘
         │
   ┌─────┴──────────────┐
   │                   │
┌──▼───────────┐  ┌─────▼──────────────┐
│  diff.py     │  │  Dashboard (Astro) │
│  • top-5     │  │  • anon read-only  │
│  • Hermes    │  │  • static build    │
│  • Telegram  │  │  • Vercel CDN      │
└──────────────┘  └────────────────────┘
```

## Patrón "Unix + cheap fetch + LLM only on change"

Inspirado en `brief_7am.py` (existente en el host).

1. **Cron barato**: cada 30 min un script GET+parsea, sin LLM.
2. **Hash canónico**: cada advisory/vuln tiene `content_hash`. Si el contenido
   no cambió, el upsert no hace nada útil.
3. **Diff hash**: el briefing computa un hash del top-5. Si es igual al último
   enviado, NO llama a Hermes y NO manda Telegram.
4. **LLM solo cuando hay cambio**: la síntesis de "Por qué importa" + "Acción
   defensiva" usa Hermes (`minimax/MiniMax-M3`). El prompt se construye desde
   facts públicos — el LLM no inventa IoCs ni claims de explotación.

## Idempotencia

- `advisories`: UNIQUE(`source_id`, `external_id`) + merge-duplicates en upsert.
- `vulnerabilities`: PK `cve_id` + merge-duplicates. `_fetch_existing_vulns()`
  preserva flags booleanos (KEV) cuando una fuente posterior no los trae.
- `risk_scores`: append-only. Idempotencia = "el último gana" en el dashboard
  (dedup por `cve_id`, ordenado por `computed_at desc`).

## Cron pattern

```
*/30 * * * *   ingest --source=KEV,EPSS,GHSA         # ~10s, cada 30min
0 */6 * * *    ingest --source=NVD                    # ~1m por batch
0 11 * * *     score + diff                          # briefing diario 7am ARG
0 13 * * 0     diff --force                          # semanal dom 10am ARG
```

Todos en modo `no-agent` (script-only stdout, sin LLM). Diff es la única
excepción — usa LLM solo si hay cambio.

## Privacidad

- 100% feeds públicos.
- Sin conexión a infra corporativa.
- Sin scraping de redes sociales ni sitios sensibles.
- RLS en Supabase: anon solo puede SELECT.
- service_role key solo en `/root/.hermes/.env` (mode 600).