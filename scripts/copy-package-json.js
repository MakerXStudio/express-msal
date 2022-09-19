const fs = require('fs')
const path = require('path')

const readJson = (relPath) => JSON.parse(fs.readFileSync(path.join(__dirname, relPath), 'utf-8'))
const writeJson = (relPath, value) => fs.writeFileSync(path.join(__dirname, relPath), JSON.stringify(value, undefined, 2), 'utf-8')

const packageJson = readJson('../package.json')

const { scripts, devDependencies, ...distPackageJson } = packageJson

writeJson('../dist/package.json', { ...distPackageJson })
