/**
 * build-site.ts — bundle the landing-page demo (which runs the real ../src
 * client code) and assemble dist/ for GitHub Pages. esbuild produces one
 * self-contained demo.js; index.html is copied verbatim.
 *
 *   bun run scripts/build-site.ts   ->   dist/{index.html, demo.js}
 */
import * as esbuild from "esbuild";

const root = `${import.meta.dir}/..`;
const outdir = `${root}/dist`;

await esbuild.build({
  entryPoints: [`${root}/site/demo.ts`],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2020",
  minify: true,
  sourcemap: false,
  outfile: `${outdir}/demo.js`,
  logLevel: "info",
});

await Bun.write(`${outdir}/index.html`, await Bun.file(`${root}/site/index.html`).text());
console.log("site built -> dist/{index.html, demo.js}");
