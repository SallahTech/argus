import { Dependency } from './types';

interface LockEntry {
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

interface Lockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
}

/**
 * Parse an npm package-lock.json (lockfileVersion 2 or 3) into a flat,
 * de-duplicated dependency list. Reachability is filled in later.
 */
export function parseLockfile(raw: string | Lockfile): Dependency[] {
  const lock: Lockfile = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!lock.packages) {
    throw new Error(
      `Unsupported lockfile (lockfileVersion ${lock.lockfileVersion ?? '?'}). ` +
        'Regenerate it with npm 7+ to get lockfileVersion 2 or 3.',
    );
  }

  const root = lock.packages[''] ?? {};
  const directNames = new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
  ]);

  const seen = new Map<string, Dependency>();
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || entry.link || !entry.version) continue;
    const idx = path.lastIndexOf('node_modules/');
    if (idx === -1) continue; // workspace package, not a dependency
    const name = path.slice(idx + 'node_modules/'.length);
    const topLevel = path === `node_modules/${name}`;
    const direct = topLevel && directNames.has(name);
    const key = `${name}@${entry.version}`;

    const existing = seen.get(key);
    if (existing) {
      // same package@version in several places: keep the most exposed view
      existing.direct ||= direct;
      existing.dev &&= !!entry.dev;
      continue;
    }
    seen.set(key, {
      name,
      version: entry.version,
      direct,
      dev: !!entry.dev,
      reachable: null,
      importCount: 0,
    });
  }
  return [...seen.values()];
}
