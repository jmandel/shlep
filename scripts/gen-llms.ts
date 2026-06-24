/**
 * gen-llms.ts — emit a static llms.txt (e.g. to host on a CDN or commit). The
 * running server serves the same thing dynamically at GET /llms.txt; use this
 * when you want a file. Reads the same env the server does.
 *
 *   BASE_URL=https://shl.example.com bun run scripts/gen-llms.ts > llms.txt
 */
import { renderLlmsTxt } from "../src/llms";

const env = (k: string, d?: string) => process.env[k] ?? d;

process.stdout.write(
  renderLlmsTxt({
    baseUrl: env("BASE_URL", "https://shl.example.com")!,
    createRequiresToken: !!env("CREATE_TOKEN"),
    // S3-family backends are CAS-capable unless explicitly disabled.
    useLimitsSupported: env("S3_CONDITIONAL_WRITE", "1") !== "0",
  }),
);
