# Rollback

## Migraciones

Las migraciones son forward-only por convención. Para "rollback":

### Rollback total (eliminar todo el schema)

```sql
-- ⚠️ DESTRUCTIVO — borra todas las tablas y datos
drop table if exists observations cascade;
drop table if exists risk_scores cascade;
drop table if exists vulnerabilities cascade;
drop table if exists advisories cascade;
drop table if exists delivery_runs cascade;
drop table if exists sources cascade;
drop function if exists pgcrypto gen_random_uuid;
```

(El proyecto Supabase tiene backups automáticos en plan free — revisar
<https://supabase.com/dashboard/project/_/database/backups>.)

### Rollback selectivo

| Quiero sacar | Acción |
|---|---|
| Una fuente | `update sources set enabled=false where slug='epss';` |
| RLS | `drop policy "anon read X" on X;` por tabla (no desactiva RLS, solo quita policy) |
| Datos de un run | `delete from delivery_runs where started_at < '...';` |
| Scores viejos | `delete from risk_scores where computed_at < now() - interval '7 days';` |

## Cambios al scoring

El scoring es append-only (`risk_scores`). Para resetear:

```sql
truncate risk_scores;
-- y después re-correr:
python -m ingest.score --limit=2000
```

## Cambios al normalizador

Si cambia `lib/normalize.py`, los datos viejos pueden tener shape incorrecto.
Solución: `delete from advisories where source_id = (select id from sources where slug='X');`
y re-ingestar.

## Cambios al dashboard

Vercel mantiene historial de deploys. Para revertir:
1. Project → Deployments
2. Seleccionar el deploy anterior que funcionaba
3. "Promote to Production"

## Cambios a las migraciones

**Nunca** editar una migración ya aplicada. Crear una nueva:
`supabase/migrations/0003_<description>.sql`.