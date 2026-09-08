import type { APIRoute } from 'astro';
import { createClient } from '@supabase/supabase-js';

export const GET: APIRoute = async () => {
  const url = import.meta.env.PUBLIC_SUPABASE_URL;
  const key = import.meta.env.PUBLIC_SUPABASE_ANON_KEY;

  if (!url || !key) {
    return new Response(
      JSON.stringify({ status: 'error', message: 'Missing Supabase environment variables' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }

  const supabase = createClient(url, key);

  try {
    const [srcRes, runsRes] = await Promise.all([
      supabase.from('sources').select('id, slug, name, kind, url, enabled, last_successful_fetch').order('slug'),
      supabase.from('delivery_runs').select('*').order('started_at', { ascending: false }).limit(1),
    ]);

    const sources = srcRes.data || [];
    const latestRun = runsRes.data?.[0] || null;
    const httpStatuses: Record<string, number> = latestRun?.http_statuses || {};

    let healthyCount = 0;
    let degradedCount = 0;

    const sourceHealth = sources.map(s => {
      const httpCode = httpStatuses[s.slug] ?? null;
      let state = 'healthy';

      if (!s.enabled) {
        state = 'disabled';
      } else if (httpCode && httpCode >= 400) {
        state = 'degraded';
        degradedCount++;
      } else {
        healthyCount++;
      }

      return {
        slug: s.slug,
        name: s.name,
        kind: s.kind,
        enabled: s.enabled,
        url: s.url,
        last_http_status: httpCode,
        health: state,
        last_successful_fetch: s.last_successful_fetch,
      };
    });

    const systemStatus = degradedCount > 0 ? 'degraded' : 'operational';

    return new Response(
      JSON.stringify({
        status: systemStatus,
        timestamp: new Date().toISOString(),
        sources_total: sources.length,
        sources_healthy: healthyCount,
        sources_degraded: degradedCount,
        last_delivery_run: latestRun ? {
          id: latestRun.id,
          started_at: latestRun.started_at,
          finished_at: latestRun.finished_at,
          sources_ok: latestRun.sources_ok,
          sources_attempted: latestRun.sources_attempted,
          advisories_new: latestRun.advisories_new,
          briefing_reason: latestRun.briefing_reason,
        } : null,
        sources: sourceHealth,
      }, null, 2),
      {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': 'https://sentinel-bench.vercel.app',
          'Cache-Control': 'public, max-age=60, s-maxage=60',
        },
      }
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({ status: 'error', message: err?.message || 'Failed to fetch status' }),
      { status: 500, headers: { 'Content-Type': 'application/json' } }
    );
  }
};
