import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

// Vite resolves /package to package.json unless we force the SPA entry.
function spaPackageRoute(): Plugin {
  return {
    name: "spa-package-route",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const pathOnly = (req.url ?? "").split("?", 1)[0];
        if (pathOnly === "/package" || pathOnly === "/package/") {
          req.url = "/";
        }
        next();
      });
    },
  };
}

export default defineConfig({
  appType: "spa",
  plugins: [
    spaPackageRoute(),
    tanstackRouter({
      target: "react",
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 8080,
  },
  preview: {
    host: "0.0.0.0",
    port: 8080,
  },
});
