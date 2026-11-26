export type Level = 'CRITICAL' | 'RELEVANT' | 'IRRELEVANT';

export interface RepoSummary {
  id: string;
  name: string;
  internetFacing: boolean;
  packageCount: number;
  reachableCount: number;
  lastScannedAt: string | null;
  critical: number;
  relevant: number;
  irrelevant: number;
}

export interface Overview {
  scanning: boolean;
  watch: { intervalSec: number; lastSweepAt: string | null; nextSweepAt: string | null };
  totals: {
    packages: number;
    reachable: number;
    vulnerabilities: number;
    critical: number;
    relevant: number;
    irrelevant: number;
  };
  repos: RepoSummary[];
}

export interface GraphNode {
  id: string;
  version: string | null;
  depth: number;
  direct: boolean;
  level: Level | null;
  score: number;
  vulns: number;
}
export interface GraphEdge {
  from: string;
  to: string;
  level: Level | null;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  hidden: number;
}

export interface Finding {
  vulnId: string;
  cveId: string | null;
  summary: string;
  severity: string;
  score: number;
  level: Level;
  reasons: string[];
  fixVersion: string | null;
  epss: number | null;
  epssPercentile: number | null;
  kevDateAdded: string | null;
  published: string | null;
  malicious: boolean;
  scoreHistory: { at: string; score: number }[];
}

export interface ThreatNumber {
  id: string;
  caseNo: string;
  repo: string;
  repoId: string;
  name: string;
  version: string;
  score: number;
  level: Level;
  path: string[];
  fixVersion: string | null;
  unfixed: number;
  firstSeenAt: string;
  findings: Finding[];
}

export interface CaseFile extends ThreatNumber {
  timeline: { at: string; kind: string; text: string; level?: Level | null }[];
}

export interface ArgusEvent {
  id: number;
  at: string;
  type: string;
  level: Level | null;
  repoName: string | null;
  packageKey: string | null;
  vulnId: string | null;
  message: string;
}

async function get<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

export const api = {
  overview: () => get<Overview>('/api/overview'),
  graph: (repoId: string) => get<Graph>(`/api/repos/${repoId}/graph`),
  numbers: (repoId?: string) => get<ThreatNumber[]>(`/api/numbers?level=all${repoId ? `&repo=${repoId}` : ''}`),
  caseFile: (id: string) => get<CaseFile>(`/api/numbers/${id}`),
  events: () => get<ArgusEvent[]>('/api/events?limit=80'),
  scan: () => fetch('/api/scan', { method: 'POST' }),
  sweep: () => fetch('/api/sweep', { method: 'POST' }),
};
