import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import vercel from "@astrojs/vercel";

// ponytail: pages stay prerendered (CDN-cached HTML), API endpoints opt into
// server rendering so query params actually run at request time.
// Each /api/v1/*.json.ts file has `export const prerender = false`.
export default defineConfig({
  output: "server",
  site: "https://sentinel-bench.vercel.app",
  build: { format: "directory" },
  vite: {
    server: { allowedHosts: true },
    plugins: [tailwindcss()],
  },
  adapter: vercel({
    imageService: false,
  }),
});
