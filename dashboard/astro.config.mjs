import { defineConfig } from 'astro/config';

export default defineConfig({
  output: 'static',
  site: 'https://sentinel-bench.vercel.app',
  build: { format: 'directory' },
  vite: {
    server: { allowedHosts: true }
  }
});