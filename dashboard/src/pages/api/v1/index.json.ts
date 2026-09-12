/**
 * GET /api/v1/index.json
 *
 * API discovery document — points clients at the available endpoints and
 * shows a short version banner. See /api-docs for full documentation.
 */
import type { APIRoute } from 'astro';

export const prerender = false;

const CORS = 'https://sentinel-bench.vercel.app';

export const GET: APIRoute = async () => {
  const body = {
    name: 'Sentinel-Bench Public API',
    version: 'v1',
    description: 'Read-only access to Sentinel-Bench vulnerability intelligence.',
    docs: 'https://sentinel-bench.vercel.app/api-docs/',
    endpoints: {
      vulnerabilities: '/api/v1/vulnerabilities.json',
      vulnerability_by_cve: '/api/v1/vulnerabilities.json?cve=CVE-YYYY-NNNN',
      advisories: '/api/v1/advisories.json',
      sources: '/api/v1/sources.json',
      status: '/api/v1/status.json',
    },
    query_params: {
      vulnerabilities: ['domain', 'vendor', 'kev', 'limit', 'offset', 'since'],
      advisories: ['domain', 'vendor', 'limit', 'offset', 'since'],
      sources: [],
      status: [],
    },
    rate_limit: 'No explicit rate limit; CDN-cached, please be reasonable.',
    cors_origin: CORS,
    generated_at: new Date().toISOString(),
  };

  return new Response(JSON.stringify(body, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': CORS,
      'Cache-Control': 'public, max-age=300, s-maxage=3600',
    },
  });
};
