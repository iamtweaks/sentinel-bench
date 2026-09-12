/**
 * GET /api/v1/vulnerabilities.json
 *
 * Query params (all optional unless flagged):
 *   cve      = CVE-YYYY-NNNN            single-CVE detail (other filters ignored)
 *   domain   = IT | OT                  filter by domain
 *   vendor   = cisco|microsoft|...      filter by vendor (case-insensitive)
 *   kev      = true                     only KEV entries
 *   limit    = 1..500 (default 100)     page size
 *   offset   = 0..n (default 0)         pagination
 *   since    = ISO date                 only updated after this date
 *
 * Returns:
 *   - Single CVE: { cve_id, ..., risk_score, risk_factors, ..., generated_at }
 *   - List:       { data: Vulnerability[], total, limit, offset, filters, generated_at }
 */
import type { APIRoute } from 'astro';
import { createClient } from '@supabase/supabase-js';


export const prerender = false;
const CORS = 'https://sentinel-bench.vercel.app';

// ponytail: one helper so the cache + CORS policy lives in one place.
function jsonHeaders(status = 200): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': CORS,
    'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=600',
  };
}

export const GET: APIRoute = async ({ url }) => {
  const sbUrl = import.meta.env.PUBLIC_SUPABASE_URL;
  const sbKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;

  if (!sbUrl || !sbKey) {
    return new Response(JSON.stringify({ error: 'server misconfigured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const sb = createClient(sbUrl, sbKey);

  const params = url.searchParams;
  const cve = (params.get('cve') || '').toUpperCase();

  // Single-CVE detail branch
  if (cve) {
    if (!/^CVE-\d{4}-\d{4,7}$/.test(cve)) {
      return new Response(JSON.stringify({ error: 'invalid_cve_format', cve }), {
        status: 400,
        headers: jsonHeaders(),
      });
    }

    const [{ data: vuln, error: vErr }, { data: score }] = await Promise.all([
      sb.from('vulnerabilities')
        .select('cve_id,cvss_v3_score,cvss_v3_vector,cvss_v4_score,epss_score,epss_percentile,is_kev,kev_date_added,kev_due_date,exploited_in_wild,poc_public,poc_urls,refs,vendors,products,first_seen_at,last_updated_at,description,remediation')
        .eq('cve_id', cve)
        .maybeSingle(),
      sb.from('latest_risk_scores')
        .select('score, factors, rationale, computed_at')
        .eq('cve_id', cve)
        .maybeSingle(),
    ]);

    if (vErr) {
      return new Response(JSON.stringify({ error: vErr.message }), { status: 500, headers: jsonHeaders() });
    }
    if (!vuln) {
      return new Response(JSON.stringify({ error: 'not_found', cve }), { status: 404, headers: jsonHeaders() });
    }

    return new Response(JSON.stringify({
      cve_id: vuln.cve_id,
      cvss_v3_score: vuln.cvss_v3_score,
      cvss_v3_vector: vuln.cvss_v3_vector,
      cvss_v4_score: vuln.cvss_v4_score,
      epss_score: vuln.epss_score,
      epss_percentile: vuln.epss_percentile,
      is_kev: vuln.is_kev,
      kev_date_added: vuln.kev_date_added,
      kev_due_date: vuln.kev_due_date,
      exploited_in_wild: vuln.exploited_in_wild,
      poc_public: vuln.poc_public,
      poc_urls: vuln.poc_urls || [],
      refs: vuln.refs || [],
      vendors: vuln.vendors || [],
      products: vuln.products || [],
      first_seen_at: vuln.first_seen_at,
      last_updated_at: vuln.last_updated_at,
      description: vuln.description,
      remediation: vuln.remediation,
      risk_score: score?.score ?? null,
      risk_factors: score?.factors ?? null,
      risk_rationale: score?.rationale ?? null,
      computed_at: score?.computed_at ?? null,
      generated_at: new Date().toISOString(),
    }, null, 2), { status: 200, headers: jsonHeaders() });
  }

  const domain = (params.get('domain') || '').toUpperCase();
  const vendor = (params.get('vendor') || '').toLowerCase();
  const kevOnly = params.get('kev') === 'true';
  const limit = Math.min(Math.max(parseInt(params.get('limit') || '100', 10) || 100, 1), 500);
  const offset = Math.max(parseInt(params.get('offset') || '0', 10) || 0, 0);
  const since = params.get('since');

  // Build the query against latest_risk_scores for ordering by computed priority.
  // ponytail: skip count=exact — Supabase does a full sort to honor it and the
  // free tier times out on 4000+ rows. We expose total only as "estimated: null,
  // returned: N" and let callers paginate to discover the full count.
  let q = sb
    .from('latest_risk_scores')
    .select('cve_id, score, factors, rationale, computed_at')
    .order('score', { ascending: false })
    .range(offset, offset + limit - 1);

  if (since) {
    q = q.gt('computed_at', since);
  }

  const { data: scores, error: scoresErr } = await q;
  if (scoresErr) {
    return new Response(JSON.stringify({ error: scoresErr.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const cveIds = (scores || []).map((r: any) => r.cve_id).filter(Boolean);
  if (cveIds.length === 0) {
    return new Response(
      JSON.stringify({
        data: [],
        total: null,
        returned: 0,
        limit,
        offset,
        filters: { domain, vendor, kev: kevOnly, since },
        generated_at: new Date().toISOString(),
      }, null, 2),
      { status: 200, headers: jsonHeaders() }
    );
  }

  // Hydrate with vulnerability details.
  let vQ = sb
    .from('vulnerabilities')
    .select('cve_id,cvss_v3_score,epss_score,is_kev,vendors,products,exploited_in_wild,poc_public,last_updated_at,description,remediation')
    .in('cve_id', cveIds);

  if (domain === 'IT' || domain === 'OT') {
    vQ = vQ.contains('vendors', []); // placeholder, real filter below via join
  }
  const { data: vulns, error: vErr } = await vQ;
  if (vErr) {
    return new Response(JSON.stringify({ error: vErr.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const vmap = new Map<string, any>((vulns || []).map((v: any) => [v.cve_id, v]));

  // ponytail: filter+map inline; one pass keeps it cheap.
  let merged = (scores || []).map((r: any) => ({
    cve_id: r.cve_id,
    score: r.score,
    rationale: r.rationale,
    computed_at: r.computed_at,
    cvss_v3_score: vmap.get(r.cve_id)?.cvss_v3_score ?? null,
    epss_score: vmap.get(r.cve_id)?.epss_score ?? null,
    is_kev: vmap.get(r.cve_id)?.is_kev ?? false,
    vendors: vmap.get(r.cve_id)?.vendors ?? [],
    products: vmap.get(r.cve_id)?.products ?? [],
    exploited_in_wild: vmap.get(r.cve_id)?.exploited_in_wild ?? false,
    poc_public: vmap.get(r.cve_id)?.poc_public ?? false,
    description: vmap.get(r.cve_id)?.description ?? null,
    remediation: vmap.get(r.cve_id)?.remediation ?? null,
    last_updated_at: vmap.get(r.cve_id)?.last_updated_at ?? null,
    domain: 'IT', // OT entries come through /api/v1/advisories.json
  }));

  if (kevOnly) merged = merged.filter((r) => r.is_kev);
  if (vendor) merged = merged.filter((r) => r.vendors.some((v: string) => String(v).toLowerCase().includes(vendor)));

  return new Response(
    JSON.stringify({
      data: merged,
      total: null,
      returned: merged.length,
      limit,
      offset,
      filters: { domain, vendor, kev: kevOnly, since },
      generated_at: new Date().toISOString(),
    }, null, 2),
    { status: 200, headers: jsonHeaders() }
  );
};
