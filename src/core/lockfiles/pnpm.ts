import YAML from 'yaml';
import { Dependency } from '../types';
import { addNode, LockGraph, LockNode, LockRoot, nodeId, toDependencies } from './graph';

type DepMap = Record<string, string | { specifier?: string; version: string }>;
interface Importer {
  dependencies?: DepMap;
  devDependencies?: DepMap;
  optionalDependencies?: DepMap;
}
interface PkgEntry {
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}
interface PnpmLock extends Importer {
  lockfileVersion: string | number;
  importers?: Record<string, Importer>;
  packages?: Record<string, PkgEntry>;
  snapshots?: Record<string, PkgEntry>; // v9
}

/**
 * pnpm-lock.yaml, lockfile versions 5.x (pnpm 7), 6.x (pnpm 8) and 9.x (pnpm 9+).
 *   v5  key: /@scope/name/1.2.3_peerhash       ref: 1.2.3_peerhash
 *   v6  key: /@scope/name@1.2.3(peer@1.0.0)    ref: 1.2.3(peer@1.0.0)
 *   v9  key: @scope/name@1.2.3(peer@1.0.0)     ref: 1.2.3(peer@1.0.0)   (graph in `snapshots`)
 * Aliases (`npm:other@1.0.0`) appear as refs of the form `other@1.0.0` or `/other@1.0.0`.
 */
export function parsePnpmLockfile(text: string): Dependency[] {
  const lock = YAML.parse(text) as PnpmLock;
  const version = parseFloat(String(lock.lockfileVersion));
  const legacy = version < 6; // slash-separated keys

  // peer suffixes live on the version only: names can contain '_' (string_decoder)
  const stripPeers = (version: string) => (legacy ? version.split('_')[0] : version.split('(')[0]);

  /** '/a/1.0.0_x' | '/a@1.0.0(x)' | 'a@1.0.0(x)' -> [name, version] */
  const parseKey = (key: string): [string, string] | null => {
    const k = key.replace(/^\//, '');
    if (legacy && key.startsWith('/')) {
      const i = k.lastIndexOf('/');
      return i > 0 ? [k.slice(0, i), stripPeers(k.slice(i + 1))] : null;
    }
    const plain = k.split('(')[0];
    const i = plain.indexOf('@', 1);
    return i > 0 ? [plain.slice(0, i), plain.slice(i + 1)] : null;
  };

  const resolve = (name: string, ref: string): string | undefined => {
    if (/^(link|file|workspace|portal):/.test(ref)) return undefined;
    if (ref.startsWith('/')) {
      const p = parseKey(ref);
      return p ? nodeId(p[0], p[1]) : undefined;
    }
    const r = stripPeers(ref);
    const at = r.indexOf('@', 1);
    if (at > 0) return nodeId(r.slice(0, at), r.slice(at + 1)); // alias: other@1.0.0
    return nodeId(name, r);
  };

  const nodes = new Map<string, LockNode>();
  const absorb = (entries: Record<string, PkgEntry> | undefined, withGraph: boolean, withPeers: boolean) => {
    for (const [key, e] of Object.entries(entries ?? {})) {
      const p = parseKey(key);
      if (!p) continue;
      const n = addNode(nodes, p[0], p[1]);
      if (withGraph)
        for (const deps of [e?.dependencies, e?.optionalDependencies])
          for (const [dn, dr] of Object.entries(deps ?? {})) n.deps.set(dn, String(dr));
      if (withPeers) Object.keys(e?.peerDependencies ?? {}).forEach((x) => n.peers.add(x));
    }
  };
  if (lock.snapshots) {
    absorb(lock.packages, false, true); // v9: metadata (peers) in packages
    absorb(lock.snapshots, true, false); // ... dependency graph in snapshots
  } else {
    absorb(lock.packages, true, true);
  }

  const importers: Importer[] = lock.importers
    ? Object.values(lock.importers)
    : [{ dependencies: lock.dependencies, devDependencies: lock.devDependencies, optionalDependencies: lock.optionalDependencies }];
  const roots: LockRoot[] = [];
  const refOf = (v: DepMap[string]) => (typeof v === 'string' ? v : v.version);
  for (const imp of importers) {
    for (const [n, v] of Object.entries(imp.dependencies ?? {})) roots.push({ name: n, ref: refOf(v), dev: false });
    for (const [n, v] of Object.entries(imp.optionalDependencies ?? {})) roots.push({ name: n, ref: refOf(v), dev: false });
    for (const [n, v] of Object.entries(imp.devDependencies ?? {})) roots.push({ name: n, ref: refOf(v), dev: true });
  }

  const graph: LockGraph = { nodes, roots, resolve };
  return toDependencies(graph);
}
