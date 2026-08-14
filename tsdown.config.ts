import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: {
    index: 'lib/types/index.js',
    invariant: 'lib/types/invariant.js',
  },
  outDir: 'lib',
  format: ['esm'],
  platform: 'node',
  target: 'es2024',
  fixedExtension: false,
  dts: false,
  // The entries live inside outDir (tsc emits lib/types first), so a blanket
  // clean would wipe the inputs; clean only the bundles this config writes.
  clean: ['index.js', 'invariant.js'],
})
