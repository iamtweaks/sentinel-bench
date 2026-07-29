-- 0001_init.sql — Sentinel-Bench MVP schema
-- Sources + advisories + vulnerabilities + risk_scores + observations + delivery_runs
-- Run via: supabase db push OR psql $DATABASE_URL -f this.sql

-- Sources: catalog of feeds we ingest from
create table if not exists sources (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,           -- 'cisa_kev', 'nvd', 'epss', 'ghsa', 'msrc'
  name text not null,
  kind text not null,                  -- 'json_feed' | 'rest_api' | 'rss'
  url text,
  enabled boolean not null default true,
  last_seen_at timestamptz,
  last_status text,                    -- 'ok' | 'http_403' | 'timeout' | etc.
  config jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Advisories: one row per advisory fetched from one source. Dedup by (source_id, external_id).
create table if not exists advisories (
  id uuid primary key default gen_random_uuid(),
  source_id uuid not null references sources(id) on delete cascade,
  external_id text not null,           -- GHSA-xxxx, MSRC doc id, etc.
  url text,
  title text,
  summary text,
  severity text,                       -- 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'unknown'
  published_at timestamptz,
  observed_at timestamptz not null default now(),
  raw jsonb not null default '{}'::jsonb,
  content_hash text not null,          -- sha256(canonical_json(raw)) for idempotency
  cve_ids text[] not null default '{}',
  vendors text[] not null default '{}',
  products text[] not null default '{}',
  is_kev boolean not null default false,
  exploitation_status text not null default 'unknown',  -- confirmed|probable|poc|none|unknown
  unique (source_id, external_id)
);
create index if not exists advisories_cve_idx on advisories using gin (cve_ids);
create index if not exists advisories_published_idx on advisories (published_at desc);
create index if not exists advisories_hash_idx on advisories (content_hash);

-- Vulnerabilities: canonical CVE row, merge from all sources.
create table if not exists vulnerabilities (
  cve_id text primary key,             -- 'CVE-2024-3400'
  cvss_v3_score numeric,
  cvss_v3_vector text,
  cvss_v4_score numeric,
  epss_score numeric,                  -- 0..1
  epss_percentile numeric,             -- 0..1
  description text,
  vendors text[] not null default '{}',
  products text[] not null default '{}',
  kev_date_added date,
  kev_due_date date,
  is_kev boolean not null default false,
  exploited_in_wild boolean not null default false,
  poc_public boolean not null default false,
  poc_urls text[] not null default '{}',
  refs jsonb not null default '[]'::jsonb,  -- [{source,url,kind}]
  first_seen_at timestamptz not null default now(),
  last_updated_at timestamptz not null default now(),
  content_hash text not null
);
create index if not exists vulns_kev_idx on vulnerabilities (is_kev) where is_kev;
create index if not exists vulns_epss_idx on vulnerabilities (epss_score desc);
create index if not exists vulns_updated_idx on vulnerabilities (last_updated_at desc);
create index if not exists vulns_vendors_idx on vulnerabilities using gin (vendors);

-- Risk scores: append-only history (every recompute is a row)
create table if not exists risk_scores (
  id uuid primary key default gen_random_uuid(),
  cve_id text not null references vulnerabilities(cve_id) on delete cascade,
  computed_at timestamptz not null default now(),
  score numeric not null check (score between 0 and 100),
  factors jsonb not null default '{}'::jsonb,  -- per-factor breakdown + nulls for unknowns
  rationale text,
  model_version text not null default 'v1'
);
create index if not exists risk_scores_cve_idx on risk_scores (cve_id, computed_at desc);
create index if not exists risk_scores_score_idx on risk_scores (score desc, computed_at desc);

-- Observations: LLM-generated notes (campaigns/exploits/defensive actions). Facts only.
create table if not exists observations (
  id uuid primary key default gen_random_uuid(),
  kind text not null,                  -- 'campaign' | 'exploit' | 'advisory'
  cve_ids text[] not null default '{}',
  vendors text[] not null default '{}',
  title text,
  summary text,
  action_defensive text,
  source_urls text[] not null default '{}',
  observed_at timestamptz not null default now(),
  llm_model text,
  prompt_version text,
  content_hash text,
  raw jsonb not null default '{}'::jsonb
);
create index if not exists obs_cve_idx on observations using gin (cve_ids);
create index if not exists obs_kind_idx on observations (kind, observed_at desc);

-- Delivery runs: per-execution audit. CRITICAL: lets us prove "second run was silent".
create table if not exists delivery_runs (
  id uuid primary key default gen_random_uuid(),
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  sources_attempted int not null default 0,
  sources_ok int not null default 0,
  advisories_new int not null default 0,
  advisories_updated int not null default 0,
  cves_new int not null default 0,
  scores_recomputed int not null default 0,
  briefing_sent boolean not null default false,
  briefing_reason text,                -- 'silent_no_change' | 'sent_significant' | 'sent_weekly'
  http_statuses jsonb not null default '{}'::jsonb,
  errors jsonb not null default '[]'::jsonb
);
create index if not exists runs_started_idx on delivery_runs (started_at desc);

-- Seed sources (MVP)
insert into sources (slug, name, kind, url, config) values
  ('cisa_kev', 'CISA Known Exploited Vulnerabilities', 'json_feed',
   'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
   '{}'::jsonb),
  ('nvd', 'NIST National Vulnerability Database', 'rest_api',
   'https://services.nvd.nist.gov/rest/json/cves/2.0',
   '{"requires_api_key": true, "rate_no_key": "5/30s", "rate_with_key": "50/30s"}'::jsonb),
  ('epss', 'FIRST EPSS', 'rest_api',
   'https://api.first.org/data/v1/epss',
   '{}'::jsonb),
  ('ghsa', 'GitHub Security Advisories', 'rest_api',
   'https://api.github.com/advisories',
   '{"rate": "60/h no-auth"}'::jsonb),
  ('msrc', 'Microsoft Security Response Center', 'rest_api',
   'https://api.msrc.microsoft.com/cvrf/v2.0/updates',
   '{}'::jsonb)
on conflict (slug) do nothing;