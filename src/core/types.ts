export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'UNKNOWN';
export type ThreatLevel = 'CRITICAL' | 'RELEVANT' | 'IRRELEVANT';

export interface Dependency {
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
  /** true = imported in source, false = direct but never imported, null = unknown (transitive) */
  reachable: boolean | null;
  /** number of source files that import it (direct deps only) */
  importCount: number;
  /** names of packages this one depends on (from the lockfile) */
  children: string[];
  /** peer dependencies: packages this one may load at runtime (e.g. @nestjs/core -> @nestjs/platform-express) */
  peers: string[];
  /** for transitive deps: the imported direct dependency that pulls it in */
  via?: string;
  /** for direct deps never imported in source but loaded at runtime by a reachable package */
  loadedBy?: string;
  /** chain from your code to this package, e.g. ['@nestjs/core','@nestjs/platform-express','multer'] */
  path?: string[];
}

export interface Vulnerability {
  id: string; // OSV id: GHSA-..., MAL-..., etc
  aliases: string[];
  cveIds: string[];
  summary: string;
  severity: Severity;
  malicious: boolean;
  /** fixed versions per npm package name */
  fixedVersions: Record<string, string[]>;
  published?: string;
  modified?: string;
  // enrichment
  kev?: { dateAdded: string; ransomware: boolean };
  epss?: { score: number; percentile: number };
}

export interface RepoContext {
  name: string;
  internetFacing: boolean;
}

export interface Assessment {
  score: number; // 0-100
  level: ThreatLevel;
  reasons: string[];
  fixVersion: string | null;
}

export type FetchFn = typeof fetch;
