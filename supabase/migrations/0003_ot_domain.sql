-- 0003_ot_domain.sql — Add domain column to advisories for IT/OT split
-- Idempotent. Safe to run multiple times.
--
-- All existing advisories are IT (Kev, EPSS, GHSA, MSRC, NVD are IT-only).
-- New OT advisories will set domain='OT'.

alter table advisories
  add column if not exists domain text not null default 'IT'
    check (domain in ('IT','OT'));

create index if not exists advisories_domain_idx
  on advisories (domain, published_at desc);

-- Ensure every source row has a domain in its config jsonb.
-- Existing sources stay IT. New OT sources added later via 0004+.
update sources
   set config = coalesce(config, '{}'::jsonb) || jsonb_build_object('domain', 'IT')
 where coalesce(config->>'domain','') = '';

comment on column advisories.domain is 'IT (KEV/EPSS/GHSA/MSRC/NVD) or OT (CISA-ICS/Siemens/Schneider/Rockwell/ABB/Moxa/CERT@VDE/Cisco/Fortinet/PaloAlto)';