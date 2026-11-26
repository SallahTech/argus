import YAML from 'yaml';
import { Dependency } from '../types';
import { addNode, LockGraph, LockNode, LockRoot, nodeId, toDependencies } from './graph';

export interface Manifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  workspaces?: string[] | { packages?: string[] };
}

/** Reads package.json files relative to the repo, and expands workspace globs. */
export interface ProjectContext {
  readManifest(relDir: string): Manifest | null;
  /** expand a workspace pattern like "packages/*" into relative directories */
  expandWorkspaces(patterns: string[]): string[];
}

const unquote = (s: string) => s.trim().replace(/^"(.*)"$/, '$1');
const nameOfDescriptor = (d: string) => d.slice(0, d.indexOf('@', 1));

function rootsFromManifest(m: Manifest | null): LockRoot[] {
  if (!m) return [];
  return [
    ...Object.entries(m.dependencies ?? {}).map(([name, ref]) => ({ name, ref, dev: false })),
    ...Object.entries(m.optionalDependencies ?? {}).map(([name, ref]) => ({ name, ref, dev: false })),
    ...Object.entries(m.devDependencies ?? {}).map(([name, ref]) => ({ name, ref, dev: true })),
  ];
}

export const isBerry = (text: string) => /^__metadata:/m.test(text);

// ---------------------------------------------------------------- Yarn Berry

interface BerryEntry {
  version: string;
  resolution: string;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/**
 * Yarn 2+ (Berry) yarn.lock: YAML. Keys are comma-separated descriptors
 * ("lodash@npm:^4.17.20, lodash@npm:^4.17.21"). Workspaces are listed as
 * `name@workspace:path` entries, but their dev and prod dependencies are merged,
 * so the split comes from each workspace's package.json.
 */
export function parseYarnBerryLockfile(text: string, ctx: ProjectContext): Dependency[] {
  const doc = YAML.parse(text) as Record<string, BerryEntry>;
  const nodes = new Map<string, LockNode>();
  const byDescriptor = new Map<string, string>();
  const workspaces: { dir: string; entry: BerryEntry }[] = [];

  for (const [key, e] of Object.entries(doc)) {
    if (key === '__metadata' || !e?.resolution) continue;
    const res = e.resolution;
    const name = nameOfDescriptor(res);
    const protocol = res.slice(name.length + 1);
    if (protocol.startsWith('workspace:')) {
      workspaces.push({ dir: protocol.slice('workspace:'.length), entry: e });
      continue;
    }
    // npm packages, including patched ones (patch:name@npm%3A1.0.0#...)
    if (!protocol.startsWith('npm:') && !(protocol.startsWith('patch:') && protocol.includes('npm%3A'))) continue;
    const n = addNode(nodes, name, String(e.version));
    for (const [dn, dr] of Object.entries(e.dependencies ?? {})) n.deps.set(dn, String(dr));
    Object.keys(e.peerDependencies ?? {}).forEach((p) => n.peers.add(p));
    for (const d of key.split(',')) byDescriptor.set(unquote(d), nodeId(name, String(e.version)));
  }

  const resolve = (name: string, ref: string) =>
    byDescriptor.get(`${name}@${ref}`) ?? byDescriptor.get(`${name}@npm:${ref}`);

  const roots: LockRoot[] = [];
  for (const ws of workspaces) {
    const manifest = ctx.readManifest(ws.dir);
    if (manifest) roots.push(...rootsFromManifest(manifest));
    else for (const [name, ref] of Object.entries(ws.entry.dependencies ?? {})) roots.push({ name, ref, dev: false });
  }
  return toDependencies({ nodes, roots, resolve } satisfies LockGraph);
}

// --------------------------------------------------------------- Yarn Classic

interface ClassicEntry {
  descriptors: string[];
  version: string;
  dependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
}

/** Yarn 1 lockfile: its own indentation-based format, not YAML. */
export function parseYarnClassicText(text: string): ClassicEntry[] {
  const entries: ClassicEntry[] = [];
  let current: ClassicEntry | null = null;
  let section: 'dependencies' | 'optionalDependencies' | null = null;
  const kv = /^("[^"]+"|\S+)\s+(.*)$/;

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      current = {
        descriptors: line.replace(/:$/, '').split(',').map(unquote).filter(Boolean),
        version: '',
        dependencies: {},
        optionalDependencies: {},
      };
      entries.push(current);
      section = null;
    } else if (!current) {
      continue;
    } else if (indent === 2) {
      if (line.endsWith(':')) {
        const s = line.slice(0, -1);
        section = s === 'dependencies' || s === 'optionalDependencies' ? s : null;
      } else {
        section = null;
        const m = line.match(kv);
        if (m && m[1] === 'version') current.version = unquote(m[2]);
      }
    } else if (indent >= 4 && section) {
      const m = line.match(kv);
      if (m) current[section][unquote(m[1])] = unquote(m[2]);
    }
  }
  return entries.filter((e) => e.version && e.descriptors.length);
}

/**
 * Yarn 1 does not record workspaces or peer dependencies in the lockfile, so
 * roots come from package.json (+ workspace globs). Peers are filled in later
 * from node_modules when it exists (see inventory).
 */
export function parseYarnClassicLockfile(text: string, ctx: ProjectContext): Dependency[] {
  const nodes = new Map<string, LockNode>();
  const byDescriptor = new Map<string, string>();
  for (const e of parseYarnClassicText(text)) {
    const name = nameOfDescriptor(e.descriptors[0]);
    if (!name) continue;
    const n = addNode(nodes, name, e.version);
    for (const deps of [e.dependencies, e.optionalDependencies])
      for (const [dn, dr] of Object.entries(deps)) n.deps.set(dn, dr);
    for (const d of e.descriptors) byDescriptor.set(d, nodeId(name, e.version));
  }
  const resolve = (name: string, ref: string) => byDescriptor.get(`${name}@${ref}`);

  const rootManifest = ctx.readManifest('.');
  const ws = rootManifest?.workspaces;
  const patterns = Array.isArray(ws) ? ws : (ws?.packages ?? []);
  const roots = [
    ...rootsFromManifest(rootManifest),
    ...ctx.expandWorkspaces(patterns).flatMap((dir) => rootsFromManifest(ctx.readManifest(dir))),
  ];
  return toDependencies({ nodes, roots, resolve } satisfies LockGraph);
}
