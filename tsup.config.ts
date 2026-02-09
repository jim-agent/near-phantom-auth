import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'server/index': 'src/server/index.ts',
    'client/index': 'src/client/index.ts',
  },
  format: ['esm', 'cjs'], // Support both ESM and CJS
  dts: false, // TODO: Fix type errors and re-enable
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  external: ['express', 'react', 'pg'],
});
