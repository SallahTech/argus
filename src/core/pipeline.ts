import { enrich, fetchEpss, fetchKev, osvGetVulns, osvQueryBatch } from './feeds';
import { DetectedLockfile, readLockfile } from './lockfiles';
import { checkFeature } from './features';
import { applyReachability, countImports, indexSources } from './reachability';
import { assess } from './scoring';
import { Assessment, Dependency, FeatureCheck, FetchFn, RepoContext, Vulnerability } from './types';

export interface Finding extends Assessment {
  dependency: Dependency;
  vulnerability: Vulnerability;
  check?: FeatureCheck;
}

export interface ScanResult {
  repo: RepoContext;
  lockfile: DetectedLockfile;
  dependencies: Dependency[];
  findings: Finding[]; // sorted, worst first
}

export async function inventoryWithLockfile(repoPath: string) {
  const { lockfile, dependencies } = await readLockfile(repoPath);
  const sources = await indexSources(repoPath);
  return { lockfile, sources, dependencies: applyReachability(dependencies, countImports(sources)) };
}

export async function inventory(repoPath: string): Promise<Dependency[]> {
  return (await inventoryWithLockfile(repoPath)).dependencies;
}

/** inventory -> OSV -> KEV + EPSS -> score. */
export type ProgressFn = (step: string, detail: string) => void;

export async function scanRepo(
  repoPath: string,
  repo: RepoContext,
  f: FetchFn = fetch,
  onProgress: ProgressFn = () => {},
): Promise<ScanResult> {
  const { lockfile, sources, dependencies } = await inventoryWithLockfile(repoPath);
  const direct = dependencies.filter((d) => d.direct).length;
  const reachable = dependencies.filter((d) => d.reachable).length;
  onProgress('inventory', `${lockfile.name} (${lockfile.format}) · ${dependencies.length} packages, ${direct} direct, ${reachable} reachable from code`);

  const hits = await osvQueryBatch(dependencies, f);
  const vulns = await osvGetVulns([...hits.values()].flat(), f);
  onProgress('osv', `${vulns.size} advisories match installed versions`);

  const cves = [...vulns.values()].flatMap((v) => v.cveIds);
  const [kev, epss] = await Promise.all([fetchKev(f), cves.length ? fetchEpss(cves, f) : new Map()]);
  enrich(vulns.values(), kev, epss);
  const inKev = [...vulns.values()].filter((v) => v.kev).length;
  onProgress('intel', `CISA KEV: ${kev.size} exploited CVEs, ${inKev} here · EPSS: ${epss.size} scored`);

  const findings: Finding[] = [];
  for (const dep of dependencies) {
    for (const id of hits.get(`${dep.name}@${dep.version}`) ?? []) {
      const vulnerability = vulns.get(id)!;
      const check = checkFeature(dep, vulnerability, sources, repo);
      findings.push({ ...assess(dep, vulnerability, repo, check), dependency: dep, vulnerability, check });
    }
  }
  findings.sort((a, b) => b.score - a.score);
  const ruledOut = findings.filter((f) => f.check?.status === 'unused').length;
  if (ruledOut) onProgress('features', `${ruledOut} findings not exploitable here (feature unused or build time only)`);
  return { repo, lockfile, dependencies, findings };
}
