-- Retention: track last time a vendor republished each advisory and prune
-- anything that hasn't been seen in N days (default 90). The column is
-- nullable so existing rows can be seeded with `observed_at` for free.

alter table advisories
  add column if not exists last_seen_at timestamptz not null default now();

update advisories set last_seen_at = coalesce(last_seen_at, observed_at);

create index if not exists advisories_last_seen_idx on advisories (last_seen_at);

comment on column advisories.last_seen_at is
  'Refreshed every time the source republishes the advisory. Prune target for retention.';