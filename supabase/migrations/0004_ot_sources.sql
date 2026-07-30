-- 0004_ot_sources.sql — public OT sources currently verified from the VPS
-- Idempotent: aligns fresh DBs with the live source catalog.

insert into sources (slug, name, kind, url, enabled, config) values
  ('abb_psirt', 'ABB PSIRT (RSS)', 'rss', 'https://psirt.abb.com/rss/abbrssfeed.xml', true, '{"domain":"OT"}'),
  ('abb_csaf', 'ABB PSIRT (CSAF)', 'csaf', 'https://psirt.abb.com/csaf/abb-csaf-feed-tlp-white.json', true, '{"domain":"OT"}'),
  ('siemens', 'Siemens ProductCERT', 'csaf', 'https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json', true, '{"domain":"OT"}'),
  ('rockwell', 'Rockwell Automation Security Advisories', 'rss', 'https://www.rockwellautomation.com/bin/rss/security-advisories.xml', true, '{"domain":"OT"}'),
  ('cert_vde', 'CERT@VDE Advisories', 'rss', 'https://certvde.com/en/advisories/feeds/rss/', true, '{"domain":"OT"}'),
  ('fortinet', 'Fortinet PSIRT', 'rss', 'https://filestore.fortinet.com/fortiguard/rss/ir.xml', true, '{"domain":"OT"}'),
  ('cisco_psirt', 'Cisco PSIRT', 'json_feed', 'https://sec.cloudapps.cisco.com/security/center/publicationService.x?publicationTypeIDs=1&offset=0&limit=200&sort=-last_published&criteria=exact', true, '{"domain":"OT"}'),
  ('paloalto', 'Palo Alto Networks Security Advisories', 'json_feed', 'https://security.paloaltonetworks.com/json', true, '{"domain":"OT"}'),
  ('cisa_ics', 'CISA ICS Advisories (official CSAF mirror)', 'csaf_tree', 'https://api.github.com/repos/cisagov/CSAF/git/trees/develop?recursive=1', true, '{"domain":"OT"}'),
  ('moxa', 'Moxa Security Advisories', 'html', 'https://www.moxa.com/en/support/product-support/security-advisory/security-advisories-all', true, '{"domain":"OT"}'),
  ('nvd_ics', 'NIST NVD (ICS-filtered)', 'rest_api', 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=ics', true, '{"domain":"OT"}')
on conflict (slug) do update set
  name = excluded.name,
  kind = excluded.kind,
  url = excluded.url,
  config = excluded.config;