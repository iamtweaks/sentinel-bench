import { createClient } from '@supabase/supabase-js';

// Read from window.__ENV (injected at build time by Vercel env vars) OR fallback to runtime config.
// The dashboard uses the anon key — RLS is not enabled in MVP; if added later, restrict to public-readable views.
const SUPABASE_URL = (import.meta as any).env?.PUBLIC_SUPABASE_URL
  ?? (typeof window !== 'undefined' ? (window as any).__SB_URL : null);
const SUPABASE_ANON = (import.meta as any).env?.PUBLIC_SUPABASE_ANON_KEY
  ?? (typeof window !== 'undefined' ? (window as any).__SB_ANON : null);

export const sb = (SUPABASE_URL && SUPABASE_ANON)
  ? createClient(SUPABASE_URL, SUPABASE_ANON)
  : null;