import { promises as fs } from 'fs';
import * as path from 'path';
import { Dependency } from './types';

const SOURCE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue']);
const SKIP_DIRS = new Set(['node_modules', 'dist', 'build', '.git', '.next', 'coverage', 'out']);

// import x from 'pkg' | import 'pkg' | export * from 'pkg' | require('pkg') | import('pkg')
const SPECIFIER_RE =
  /(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"\n]+)['"]/g;

/** Turn 'lodash/fp' -> 'lodash', '@nestjs/core/x' -> '@nestjs/core', './a' -> null */
export function packageFromSpecifier(spec: string): string | null {
  if (spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  if (spec.startsWith('@')) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  return parts[0];
}

export function importsInSource(code: string): Set<string> {
  const found = new Set<string>();
  for (const m of code.matchAll(SPECIFIER_RE)) {
    const pkg = packageFromSpecifier(m[1]);
    if (pkg) found.add(pkg);
  }
  return found;
}

async function* walk(dir: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) yield* walk(path.join(dir, e.name));
    } else if (SOURCE_EXT.has(path.extname(e.name))) {
      yield path.join(dir, e.name);
    }
  }
}

/** Every source file of the project (minus node_modules, build output), read once. */
export interface SourceIndex {
  files: { file: string; code: string }[]; // file is relative to the repo
}

const MAX_FILE_BYTES = 1_000_000; // skip bundles / generated files

export async function indexSources(repoPath: string): Promise<SourceIndex> {
  const files: SourceIndex['files'] = [];
  for await (const abs of walk(repoPath)) {
    const stat = await fs.stat(abs);
    if (stat.size > MAX_FILE_BYTES) continue;
    files.push({ file: path.relative(repoPath, abs), code: await fs.readFile(abs, 'utf8') });
  }
  return { files };
}

export function countImports(index: SourceIndex): Map<string, number> {
  const counts = new Map<string, number>();
  for (const { code } of index.files)
    for (const pkg of importsInSource(code)) counts.set(pkg, (counts.get(pkg) ?? 0) + 1);
  return counts;
}

/** Count, per package, how many source files import it. */
export async function scanImports(repoPath: string): Promise<Map<string, number>> {
  return countImports(await indexSources(repoPath));
}

/**
 * Packages that only run while building (CSS processing, bundling, compiling).
 * Anything reachable *only* through them never runs in production.
 */
export const BUILD_TIME = new Set([
  'postcss',
  'autoprefixer',
  'tailwindcss',
  '@tailwindcss/postcss',
  'sass',
  'less',
  'stylus',
  'webpack',
  'terser',
  'esbuild',
  'rollup',
  'vite',
  '@babel/core',
  'typescript',
  'eslint',
  'prettier',
]);

/**
 * Import-level reachability.
 * - Direct deps: reachable if any source file imports them.
 * - Transitive deps: reachable if an imported production dependency pulls
 *   them in (walks the lockfile graph by package name). Otherwise unknown.
 */
export function applyReachability(deps: Dependency[], imports: Map<string, number>): Dependency[] {
  const out = deps.map((d) => {
    if (!d.direct) return { ...d };
    const count = imports.get(d.name) ?? 0;
    return { ...d, reachable: count > 0, importCount: count };
  });

  const childrenOf = new Map<string, Set<string>>();
  const peersOf = new Map<string, Set<string>>();
  for (const d of out) {
    const c = childrenOf.get(d.name) ?? new Set<string>();
    d.children.forEach((x) => c.add(x));
    childrenOf.set(d.name, c);
    const p = peersOf.get(d.name) ?? new Set<string>();
    d.peers.forEach((x) => p.add(x));
    peersOf.set(d.name, p);
  }
  const directProd = new Map(out.filter((d) => d.direct && !d.dev).map((d) => [d.name, d]));

  // BFS from every reachable production direct dependency. Then promote
  // installed direct deps that a reachable package lists as a peer (loaded at
  // runtime, never imported by you) and repeat until nothing changes.
  // pathOf records the first chain we found from your code to each package.
  const via = new Map<string, string>();
  const pathOf = new Map<string, string[]>();
  for (const d of directProd.values()) if (d.reachable) pathOf.set(d.name, [d.name]);
  const walked = new Set<string>();
  for (let changed = true; changed; ) {
    changed = false;
    for (const root of directProd.values()) {
      if (!root.reachable || walked.has(root.name)) continue;
      walked.add(root.name);
      const rootPath = pathOf.get(root.name) ?? [root.name];
      const queue = [...(childrenOf.get(root.name) ?? [])].map((name) => ({ name, parent: rootPath }));
      while (queue.length) {
        const { name, parent } = queue.shift()!;
        if (via.has(name)) continue;
        const asDirect = directProd.get(name);
        if (asDirect) {
          // a direct dep that a reachable package requires is reachable too
          if (!asDirect.reachable) {
            asDirect.reachable = true;
            asDirect.loadedBy = parent[parent.length - 1];
            pathOf.set(name, [...parent, name]);
            changed = true;
          }
          continue;
        }
        via.set(name, root.name);
        const path = [...parent, name];
        pathOf.set(name, path);
        queue.push(...[...(childrenOf.get(name) ?? [])].map((c) => ({ name: c, parent: path })));
      }
    }
    for (const name of [...pathOf.keys()]) {
      for (const peer of peersOf.get(name) ?? []) {
        const d = directProd.get(peer);
        if (d && !d.reachable) {
          d.reachable = true;
          d.loadedBy = name;
          pathOf.set(peer, [...pathOf.get(name)!, peer]);
          changed = true;
        }
      }
    }
  }

  for (const d of out) {
    if (!d.direct && !d.dev) {
      const root = via.get(d.name);
      if (root) {
        d.reachable = true;
        d.via = root;
      }
    }
    if (d.reachable && !d.dev) d.path = pathOf.get(d.name) ?? [d.name];
  }

  // Runtime reachability: the same walk, but never stepping *into* a build tool.
  // (A build tool you import yourself still counts as runtime.)
  const runtime = new Set<string>();
  const rq = [
    ...[...directProd.values()].filter((d) => d.reachable).map((d) => d.name),
    ...[...imports.keys()].filter((n) => childrenOf.has(n)), // anything your code imports runs
  ];
  rq.forEach((n) => runtime.add(n));
  while (rq.length) {
    const name = rq.shift()!;
    for (const child of [...(childrenOf.get(name) ?? []), ...(peersOf.get(name) ?? [])]) {
      if (runtime.has(child) || BUILD_TIME.has(child)) continue;
      if (!childrenOf.has(child)) continue; // peer not installed
      runtime.add(child);
      rq.push(child);
    }
  }
  for (const d of out) {
    if (d.reachable && !d.dev && !runtime.has(d.name)) {
      d.buildTimeOnly = true;
      d.buildTool = d.path?.find((p) => BUILD_TIME.has(p)) ?? [...BUILD_TIME].find((b) => childrenOf.get(b)?.has(d.name));
    }
  }
  return out;
}
