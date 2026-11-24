# Vendored browser libraries

These files are copied verbatim from the npm packages below and served from the
binary (`go:embed`). The panel never loads code from a CDN at runtime.

| File | Package | Version | License |
|---|---|---|---|
| `preact.module.js` | [preact](https://www.npmjs.com/package/preact) `dist/preact.module.js` (ESM build, not the UMD minified file) | 10.27.2 | MIT (`LICENSE.preact`) |
| `hooks.module.js` | preact `hooks/dist/hooks.module.js` (ESM build) | 10.27.2 | MIT |
| `htm.module.js` | [htm](https://www.npmjs.com/package/htm) `dist/htm.mjs` | 3.1.1 | Apache-2.0 (`LICENSE.htm`) |

The ESM builds are required: the longer-named `*.min.module.js` files are UMD
bundles in this release and provide no named exports, so `import { h }` fails.
The served copies are the official npm artifacts with these SHA-256 digests:

| File | SHA-256 |
|---|---|
| `preact.module.js` | `a1cefabf06ec626adcb92731537e1e04fd09a7908e22551bab50540106dc950d` |
| `hooks.module.js` | `59197e80cf93d09fc08a84183aa250c3fbb20ae5d24f7f2beef1ae0538ca30bf` (after the import edit below) |
| `htm.module.js` | `ab33dd3f38059b9be4d5f5350128eefb2356639c4e0bbe9d9e8b3ba75847e9e4` |

One edit was made to `hooks.module.js`: its bare import specifier `"preact"` was
changed to `"./preact.module.js"` so browsers can resolve it without an import
map (an inline import map would violate the panel's CSP).

To refresh: `npm pack preact@<version> htm@<version>`, extract, copy the files
above, re-apply the import-specifier edit, and update this table.
