import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import vercel from "@astrojs/vercel";

export default defineConfig({
  output: "static",
  adapter: vercel(),
  site: "https://sentinel-bench.vercel.app",
  build: { format: "directory" },
  vite: {
    server: { allowedHosts: true },
    plugins: [tailwindcss()],
  },
});
