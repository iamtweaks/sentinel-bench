/**
 * GET /api/v1/sources.json
 *
 * Returns the source catalog (CISA KEV, NVD, EPSS, GHSA, MSRC, ABB, Siemens, ...)
 * with last successful fetch and recent HTTP health from the latest delivery_run.
 *
 * Cached 60s browser / 5min edge.
 */
import type { APIRoute } from 'astro';
import { createClient } from '@supabase/supabase-js';

const CORS = 'https://sentinel-bench.vercel.app';

export const GET: APIRoute = async () => {
  const sbUrl = import.meta.env.PUBLIC_SUPABASE_URL;
  const sbKey = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;
  if (!sbUrl || !sbKey) {
    return new Response(JSON.stringify({ error: 'server misconfigured' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const sb = createClient(sbUrl, sbKey);
  const [{ data: sources, error: sErr }, { data: runs }] = await Promise.all([
    // ponytail: column is last_seen_at (when ingest saw it), not last_successful_fetch.
    sb.from('sources').select('id, slug, name, kind, url, enabled, last_seen_at, last_status').order('slug'),
    sb.from('delivery_runs').select('http_statuses, started_at').order('started_at', { ascending: false }).limit(1),
  ]);

  if (sErr) {
    return new Response(JSON.stringify({ error: sErr.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  const latestRun = runs?.[0] || null;
  const httpStatuses: Record<string, number> = latestRun?.http_statuses || {};

  const out = (sources || []).map((s: any) => {
    const code = httpStatuses[s.slug] ?? null;
    let health = 'unknown';
    if (!s.enabled) health = 'disabled';
    else if (code === null) health = 'no_data';
    else if (code >= 500) health = 'down';
    else if (code >= 400) health = 'degraded';
    else if (code >= 200 && code < 400) health = 'healthy';

    return {
      slug: s.slug,
      name: s.name,
      kind: s.kind,
      url: s.url,
      enabled: s.enabled,
      last_seen_at: s.last_seen_at,
      last_status: s.last_status,
      last_http_status: code,
      health,
    };
  });

  return new Response(
    JSON.stringify({
      data: out,
      total: out.length,
      last_delivery_run_started_at: latestRun?.started_at ?? null,
      generated_at: new Date().toISOString(),
    }, null, 2),
    {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': CORS,
        'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=600',
      },
    }
  );
};
