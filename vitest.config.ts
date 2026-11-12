import { defineConfig } from 'vitest/config';

// Footprint tests perform real DNS/RDAP/crt.sh lookups, which can exceed the 5s default on slow networks.
export default defineConfig({ test: { testTimeout: 30000, hookTimeout: 30000 } });
