import { enrich, fetchEpss, fetchKev, osvGetVulns, osvQueryBatch } from './feeds';
import { DetectedLockfile, readLockfile } from './lockfiles';
import { applyReachability, scanImports } from './reachability';
import { assess } from './scoring';
import { Assessment, Dependency, FetchFn, RepoContext, Vulnerability } from './types';

export interface Finding extends Assessment {
  dependency: Dependency;
  vulnerability: Vulnerability;
}

export interface ScanResult {
  repo: RepoContext;
  lockfile: DetectedLockfile;
  dependencies: Dependency[];
  findings: Finding[]; // sorted, worst first
}

export async function inventoryWithLockfile(repoPath: string) {
  const { lockfile, dependencies } = await readLockfile(repoPath);
  return { lockfile, dependencies: applyReachability(dependencies, await scanImports(repoPath)) };
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
  const { lockfile, dependencies } = await inventoryWithLockfile(repoPath);
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
      findings.push({ ...assess(dep, vulnerability, repo), dependency: dep, vulnerability });
    }
  }
  findings.sort((a, b) => b.score - a.score);
  return { repo, lockfile, dependencies, findings };
}
