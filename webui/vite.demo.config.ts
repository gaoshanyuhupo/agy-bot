import path from "node:path";
import { defineConfig, type Plugin, type PluginOption } from "vite";
import baseConfig from "./vite.config";

const SRC_API_PATH = path.resolve(__dirname, "src/api.ts");
const MOCK_API_PATH = path.resolve(__dirname, "src/demo/mockApi.ts");
const SRC_AUTH_PATH = path.resolve(__dirname, "src/bootstrapAuth.ts");
const MOCK_AUTH_PATH = path.resolve(__dirname, "src/demo/mockBootstrapAuth.ts");

function demoAliasPlugin(): Plugin {
  return {
    name: "agy-demo-module-alias",
    enforce: "pre",
    async resolveId(source, importer, options) {
      if (!importer) return null;
      const normImporter = importer.replace(/\\/g, "/");
      if (normImporter.includes("/src/demo/")) return null;
      const resolved = await this.resolve(source, importer, {
        ...options,
        skipSelf: true,
      });
      if (!resolved?.id) return null;
      const cleanId = resolved.id.split("?", 1)[0];
      if (cleanId === SRC_API_PATH) return MOCK_API_PATH;
      if (cleanId === SRC_AUTH_PATH) return MOCK_AUTH_PATH;
      return null;
    },
  };
}

function inlineDemoSingleFilePlugin(): Plugin {
  return {
    name: "agy-demo-inline-singlefile",
    enforce: "post",
    generateBundle(_options, bundle) {
      let htmlKey = "";
      let jsKey = "";
      let cssKey = "";
      let jsCode = "";
      let cssCode = "";

      for (const [fileName, item] of Object.entries(bundle)) {
        if (item.type === "asset" && fileName.endsWith(".html")) {
          htmlKey = fileName;
        } else if (item.type === "chunk" && item.isEntry && fileName.endsWith(".js")) {
          jsKey = fileName;
          jsCode = item.code;
        } else if (item.type === "asset" && fileName.endsWith(".css")) {
          cssKey = fileName;
          cssCode = typeof item.source === "string" ? item.source : String(item.source);
        }
      }

      if (!htmlKey) return;
      const htmlAsset = bundle[htmlKey];
      if (htmlAsset.type !== "asset") return;
      let html = typeof htmlAsset.source === "string" ? htmlAsset.source : String(htmlAsset.source);

      // Remove external module/nomodule script tags & stylesheet link tags emitted by Vite
      html = html.replace(/<script\b[^>]*\bsrc=[^>]*><\/script>\s*/gi, "");
      html = html.replace(/<link\b[^>]*rel=["'](?:stylesheet|modulepreload)["'][^>]*>\s*/gi, "");

      if (cssCode) {
        const safeCss = cssCode.replace(/<\/style/gi, "<\\/style");
        html = html.replace("</head>", () => `  <style>${safeCss}</style>\n  </head>`);
      }
      if (jsCode) {
        const safeJs = jsCode.replace(/<\/script/gi, "<\\/script");
        html = html.replace("</body>", () => `  <script>${safeJs}</script>\n  </body>`);
      }

      delete bundle[htmlKey];
      if (jsKey) delete bundle[jsKey];
      if (cssKey) delete bundle[cssKey];

      this.emitFile({
        type: "asset",
        fileName: "index.html",
        source: html,
      });
    },
  };
}

const basePlugins: PluginOption[] = Array.isArray(baseConfig.plugins) ? baseConfig.plugins : [];

export default defineConfig({
  base: "./",
  plugins: [demoAliasPlugin(), ...basePlugins, inlineDemoSingleFilePlugin()],
  resolve: {
    alias: [
      { find: SRC_API_PATH, replacement: MOCK_API_PATH },
      { find: SRC_AUTH_PATH, replacement: MOCK_AUTH_PATH },
    ],
  },
  build: {
    outDir: "dist-demo",
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    assetsInlineLimit: 100 * 1024 * 1024,
    rollupOptions: {
      input: path.resolve(__dirname, "demo.html"),
      output: {
        format: "iife",
        inlineDynamicImports: true,
      },
    },
  },
});
