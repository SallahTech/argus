import { Dependency } from '../types';

/** One resolved package in a lockfile. id is always `name@version`. */
export interface LockNode {
  name: string;
  version: string;
  /** dependency name -> lockfile reference, resolved with LockGraph.resolve */
  deps: Map<string, string>;
  peers: Set<string>;
}

export interface LockRoot {
  name: string;
  ref: string;
  dev: boolean;
}

/**
 * A format-neutral view of a lockfile. Parsers for pnpm and Yarn fill this in;
 * toDependencies turns it into what the rest of Argus works with.
 */
export interface LockGraph {
  nodes: Map<string, LockNode>;
  /** what the project (and every workspace in it) asks for directly */
  roots: LockRoot[];
  /** resolve a reference found in roots or deps to a node id, or undefined (workspace link, git, ...) */
  resolve(name: string, ref: string): string | undefined;
}

export const nodeId = (name: string, version: string) => `${name}@${version}`;

export function addNode(nodes: Map<string, LockNode>, name: string, version: string): LockNode {
  const id = nodeId(name, version);
  let n = nodes.get(id);
  if (!n) {
    n = { name, version, deps: new Map(), peers: new Set() };
    nodes.set(id, n);
  }
  return n;
}

/**
 * Direct = what a root resolves to. Dev-only = not reachable from any production
 * root through the dependency graph (the lockfile flags are not trusted, most
 * formats don't have them).
 */
export function toDependencies(g: LockGraph): Dependency[] {
  const direct = new Set<string>();
  const prod = new Set<string>();
  const queue: string[] = [];
  for (const r of g.roots) {
    const id = g.resolve(r.name, r.ref);
    if (!id || !g.nodes.has(id)) continue;
    direct.add(id);
    if (!r.dev && !prod.has(id)) {
      prod.add(id);
      queue.push(id);
    }
  }
  while (queue.length) {
    const node = g.nodes.get(queue.shift()!)!;
    for (const [name, ref] of node.deps) {
      const id = g.resolve(name, ref);
      if (id && g.nodes.has(id) && !prod.has(id)) {
        prod.add(id);
        queue.push(id);
      }
    }
  }

  const out: Dependency[] = [];
  for (const [id, n] of g.nodes) {
    out.push({
      name: n.name,
      version: n.version,
      direct: direct.has(id),
      dev: !prod.has(id),
      reachable: null,
      importCount: 0,
      children: [...n.deps.keys()],
      peers: [...n.peers],
    });
  }
  return out;
}
