import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { NextConfig } from "next";

// No fallback, so a build missing the file fails instead of shipping an old name.
const product = JSON.parse(
  readFileSync(join(process.cwd(), "..", "product.json"), "utf8"),
) as { name: string };

const nextConfig: NextConfig = {
  env: { NEXT_PUBLIC_PRODUCT_NAME: product.name },
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
