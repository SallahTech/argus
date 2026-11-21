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

/** Count, per package, how many source files import it. */
export async function scanImports(repoPath: string): Promise<Map<string, number>> {
  const counts = new Map<string, number>();
  for await (const file of walk(repoPath)) {
    const code = await fs.readFile(file, 'utf8');
    for (const pkg of importsInSource(code)) counts.set(pkg, (counts.get(pkg) ?? 0) + 1);
  }
  return counts;
}

/**
 * Import-level reachability: a direct dependency nobody imports is far less
 * dangerous. Transitive deps stay `null` (unknown) in this MVP.
 */
export function applyReachability(deps: Dependency[], imports: Map<string, number>): Dependency[] {
  return deps.map((d) => {
    if (!d.direct) return d;
    const count = imports.get(d.name) ?? 0;
    return { ...d, reachable: count > 0, importCount: count };
  });
}
