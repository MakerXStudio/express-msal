// Post-processes dist/ to give the ESM condition its own declaration file.
// Remove once @makerx/ts-toolkit emits per-condition types natively.
import { readFileSync, writeFileSync, copyFileSync } from 'node:fs'
import { join } from 'node:path'

const dist = 'dist'
const pkgPath = join(dist, 'package.json')
const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'))

// Order matters: `import` before `require`, `types` before `default`.
pkg.exports = {
  '.': {
    import: { types: './index.d.mts', default: './index.mjs' },
    require: { types: './index.d.ts', default: './index.js' },
  },
}

writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n')

// Content-identical copy — declarations here are pure type imports, so the
// only thing that changes is the resolution mode TypeScript applies.
copyFileSync(join(dist, 'index.d.ts'), join(dist, 'index.d.mts'))
