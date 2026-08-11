-- 0003_latest_risk_scores_view.sql — Optimización de consulta para el Threat Feed
-- De-duplica el histórico de risk_scores directamente en PostgreSQL usando DISTINCT ON.

create or replace view latest_risk_scores as
select distinct on (cve_id)
  id,
  cve_id,
  computed_at,
  score,
  factors,
  rationale,
  model_version
from risk_scores
order by cve_id, computed_at desc;

-- Otorgar permiso de lectura al rol anonimo para la API de Supabase Dashboard
grant select on latest_risk_scores to anon, authenticated, service_role;
