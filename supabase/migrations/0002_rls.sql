-- 0002_rls.sql — Sentinel-Bench RLS for public dashboard
-- The dashboard uses the anon key; RLS is on; only SELECT is allowed (no public writes).
-- Writes are restricted to the service_role key (used by ingest scripts).

-- Enable RLS on all public tables
alter table sources enable row level security;
alter table advisories enable row level security;
alter table vulnerabilities enable row level security;
alter table risk_scores enable row level security;
alter table observations enable row level security;
alter table delivery_runs enable row level security;

-- Public read-only policies for anon role
create policy "anon read sources" on sources for select to anon using (true);
create policy "anon read advisories" on advisories for select to anon using (true);
create policy "anon read vulnerabilities" on vulnerabilities for select to anon using (true);
create policy "anon read risk_scores" on risk_scores for select to anon using (true);
create policy "anon read observations" on observations for select to anon using (true);
create policy "anon read delivery_runs" on delivery_runs for select to anon using (true);

-- Service role bypasses RLS automatically; no explicit policy needed for ingest.