/**
 * GET /api/v1/advisories.json
 *
 * Query params (all optional):
 *   domain = IT | OT
 *   vendor = cisco|microsoft|...   (case-insensitive substring match)
 *   limit  = 1..500 (default 100)
 *   offset = 0..n (default 0)
 *   since  = ISO date (filter advisories published_at > since)
 *
 * Returns: { data: Advisory[], total, limit, offset, filters, generated_at }
 */
import type { APIRoute } from 'astro';
import { createClient } from '@supabase/supabase-js';

const CORS = 'https://sentinel-bench.vercel.app';

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
  const domain = (params.get('domain') || '').toUpperCase();
  const vendor = (params.get('vendor') || '').toLowerCase();
  const limit = Math.min(Math.max(parseInt(params.get('limit') || '100', 10) || 100, 1), 500);
  const offset = Math.max(parseInt(params.get('offset') || '0', 10) || 0, 0);
  const since = params.get('since');

  let q = sb
    .from('advisories')
    .select('id, source_id, title, summary, url, severity, published_at, vendors, products, cve_ids, domain', { count: 'exact' })
    .order('published_at', { ascending: false, nullsFirst: false })
    .range(offset, offset + limit - 1);

  if (domain === 'IT' || domain === 'OT') q = q.eq('domain', domain);
  if (since) q = q.gt('published_at', since);

  const { data, error, count } = await q;
  if (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': CORS },
    });
  }

  let rows = data || [];
  if (vendor) rows = rows.filter((r: any) => Array.isArray(r.vendors) && r.vendors.some((v: string) => String(v).toLowerCase().includes(vendor)));

  return new Response(
    JSON.stringify({
      data: rows,
      total: count ?? rows.length,
      limit,
      offset,
      filters: { domain, vendor, since },
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
