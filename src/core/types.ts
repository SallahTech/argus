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
  /** reachable only through a build tool (postcss, webpack...), so it never runs in production */
  buildTimeOnly?: boolean;
  buildTool?: string;
}

/**
 * Does this project use the part of the package the vulnerability lives in?
 * - unused: not exploitable here (feature never used, or build time only)
 * - used:   the vulnerable feature is in use, evidence points at the code
 */
export interface FeatureCheck {
  status: 'used' | 'unused';
  kind: 'feature' | 'build-time';
  /** e.g. "file uploads (multer)" */
  feature: string;
  /** one line a human can read in an alert */
  detail: string;
  /** file:line references */
  evidence: string[];
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
