#!/usr/bin/env node
// Release acceptance for consumers that pin this package by commit: after `npm run build`, every export in
// package.json must be packed (`npm pack --dry-run`) and must load from the compiled output by its public name.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packed = JSON.parse(execFileSync(npm, ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: new URL('..', import.meta.url), encoding: 'utf8' }));
const files = new Set(packed[0].files.map((f) => f.path));
const problems = [];
for (const forbidden of [...files].filter((f) => /^(src|tests|integration|registry)\/|\.env|\.pem$|\.key$/.test(f))) problems.push(`unexpected file in package: ${forbidden}`);
for (const [subpath, target] of Object.entries(pkg.exports)) {
  for (const kind of ['types', 'default']) if (!files.has(target[kind].replace(/^\.\//, ''))) problems.push(`${subpath} ${kind} target ${target[kind]} is not packed`);
  const name = subpath === '.' ? pkg.name : `${pkg.name}/${subpath.slice(2)}`;
  try {
    const mod = await import(name);
    if (Object.keys(mod).length === 0) problems.push(`${name} exports nothing`);
  } catch (error) { problems.push(`${name} does not load: ${error instanceof Error ? error.message : String(error)}`); }
}
const engine = await import(`${pkg.name}/engine`);
if (engine.manifest?.id !== 'E01' || typeof engine.createEngine !== 'function' || typeof engine.migrate !== 'function') problems.push('engine export is incomplete');
const serve = await import(`${pkg.name}/serve`);
if (typeof serve.start !== 'function' || typeof serve.configFromEnv !== 'function' || typeof serve.portsFromEnv !== 'function') problems.push('serve export is incomplete');
if (problems.length > 0) { console.error(problems.join('\n')); process.exit(1); }
console.log(`Package ${pkg.name}@${pkg.version}: ${Object.keys(pkg.exports).length} exports packed and loadable from the build (${files.size} files).`);
