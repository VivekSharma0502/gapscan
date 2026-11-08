// The product name, set once in product.json at the repo root. next.config.ts reads that
// file and inlines the value here at build time.
export const PRODUCT_NAME = process.env.NEXT_PUBLIC_PRODUCT_NAME as string;
