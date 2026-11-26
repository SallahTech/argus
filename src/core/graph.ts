import { ThreatGroup, LEVEL_RANK } from './group';
import { Dependency, ThreatLevel } from './types';

export interface GraphNode {
  id: string;
  version: string | null;
  depth: number;
  direct: boolean;
  level: ThreatLevel | null; // null = observed, no known vulnerability
  score: number;
  vulns: number;
}
export interface GraphEdge {
  from: string;
  to: string;
  level: ThreatLevel | null; // worst threat whose path uses this edge
}
export interface ThreatGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  hidden: number; // reachable packages left out to keep the view readable
}

export const ROOT = 'your code';

/**
 * The Machine view: your code -> every reachable direct dependency, plus every
 * path that leads to a package with a known vulnerability.
 */
export function buildGraph(deps: Dependency[], groups: ThreatGroup[], maxNodes = 80): ThreatGraph {
  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  // A package can be installed in several versions (yarn and pnpm often do).
  // Match by name@version; only versions that actually run count.
  const runs = (d?: Dependency) => !!d && !!d.reachable && !d.dev;
  const byKey = new Map(deps.map((d) => [`${d.name}@${d.version}`, d]));
  const reachableGroups = groups.filter((g) => runs(byKey.get(g.key)));

  // per box (package name): the worst running version with findings, else any running version
  const groupOf = new Map<string, ThreatGroup>();
  for (const g of reachableGroups) {
    const cur = groupOf.get(g.name);
    if (!cur || g.score > cur.score) groupOf.set(g.name, g);
  }
  const runningVersion = new Map<string, Dependency>();
  for (const d of deps) if (runs(d) && !runningVersion.has(d.name)) runningVersion.set(d.name, d);

  const addNode = (name: string, depth: number) => {
    const existing = nodes.get(name);
    if (existing) {
      existing.depth = Math.min(existing.depth, depth);
      return;
    }
    const g = groupOf.get(name);
    const d = g ? byKey.get(g.key) : runningVersion.get(name);
    nodes.set(name, {
      id: name,
      version: d?.version ?? null,
      depth,
      direct: !!d?.direct,
      level: g?.level ?? null,
      score: g?.score ?? 0,
      vulns: g?.findings.length ?? 0,
    });
  };
  const addEdge = (from: string, to: string, level: ThreatLevel | null) => {
    const k = `${from}>${to}`;
    const e = edges.get(k);
    if (!e) edges.set(k, { from, to, level });
    else if (level && (!e.level || LEVEL_RANK[level] > LEVEL_RANK[e.level])) e.level = level;
  };

  nodes.set(ROOT, { id: ROOT, version: null, depth: 0, direct: false, level: null, score: 0, vulns: 0 });

  // threat paths first, worst first, so they survive the node cap
  for (const g of reachableGroups) {
    if (nodes.size + g.path.length > maxNodes && g.level === 'IRRELEVANT') continue;
    const chain = [ROOT, ...g.path];
    chain.forEach((n, i) => i > 0 && addNode(n, i));
    for (let i = 1; i < chain.length; i++) addEdge(chain[i - 1], chain[i], g.level);
  }

  // then the rest of your direct, running production deps (observed, quiet)
  const quiet = deps.filter((d) => d.direct && runs(d) && !nodes.has(d.name));
  for (const d of quiet) {
    if (nodes.size >= maxNodes) break;
    const parent = d.path && d.path.length > 1 ? d.path[d.path.length - 2] : ROOT;
    addNode(d.name, nodes.has(parent) ? nodes.get(parent)!.depth + 1 : 1);
    addEdge(nodes.has(parent) ? parent : ROOT, d.name, null);
  }
  const hidden = new Set(deps.filter((d) => runs(d) && !nodes.has(d.name)).map((d) => d.name)).size;
  return { nodes: [...nodes.values()], edges: [...edges.values()], hidden };
}
