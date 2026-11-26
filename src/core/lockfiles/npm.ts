import { Dependency } from '../types';

interface LockEntry {
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

interface Lockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
}

/**
 * Parse an npm package-lock.json (lockfileVersion 2 or 3) into a flat,
 * de-duplicated dependency list. Reachability is filled in later.
 */
export function parseNpmLockfile(raw: string | Lockfile): Dependency[] {
  const lock: Lockfile = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!lock.packages) {
    throw new Error(
      `Unsupported lockfile (lockfileVersion ${lock.lockfileVersion ?? '?'}). ` +
        'Regenerate it with npm 7+ to get lockfileVersion 2 or 3.',
    );
  }

  // the root project plus any npm workspaces (entries outside node_modules)
  const directNames = new Set<string>();
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path.includes('node_modules/')) continue;
    for (const deps of [entry.dependencies, entry.devDependencies, entry.optionalDependencies])
      Object.keys(deps ?? {}).forEach((n) => directNames.add(n));
  }

  const seen = new Map<string, Dependency>();
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || entry.link || !entry.version) continue;
    const idx = path.lastIndexOf('node_modules/');
    if (idx === -1) continue; // workspace package, not a dependency
    const name = path.slice(idx + 'node_modules/'.length);
    // hoisted to the root, or installed directly under a workspace
    const topLevel = path.split('node_modules/').length === 2;
    const direct = topLevel && directNames.has(name);
    const key = `${name}@${entry.version}`;
    const children = [
      ...Object.keys(entry.dependencies ?? {}),
      ...Object.keys(entry.optionalDependencies ?? {}),
    ];
    const peers = Object.keys(entry.peerDependencies ?? {});

    const existing = seen.get(key);
    if (existing) {
      // same package@version in several places: keep the most exposed view
      existing.direct ||= direct;
      existing.dev &&= !!entry.dev;
      existing.children = [...new Set([...existing.children, ...children])];
      existing.peers = [...new Set([...existing.peers, ...peers])];
      continue;
    }
    seen.set(key, {
      name,
      version: entry.version,
      direct,
      dev: !!entry.dev,
      reachable: null,
      importCount: 0,
      children,
      peers,
    });
  }
  return [...seen.values()];
}
