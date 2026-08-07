import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  output: "static",
  site: "https://sentinel-bench.vercel.app",
  build: { format: "directory" },
  vite: {
    server: { allowedHosts: true },
    plugins: [tailwindcss()],
  },
});
