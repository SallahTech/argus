import { promises as fs } from 'fs';
import * as path from 'path';
import { enrich, fetchEpss, fetchKev, osvGetVulns, osvQueryBatch } from './feeds';
import { parseLockfile } from './lockfile';
import { applyReachability, scanImports } from './reachability';
import { assess } from './scoring';
import { Assessment, Dependency, FetchFn, RepoContext, Vulnerability } from './types';

export interface Finding extends Assessment {
  dependency: Dependency;
  vulnerability: Vulnerability;
}

export interface ScanResult {
  repo: RepoContext;
  dependencies: Dependency[];
  findings: Finding[]; // sorted, worst first
}

export async function inventory(repoPath: string): Promise<Dependency[]> {
  const lock = await fs.readFile(path.join(repoPath, 'package-lock.json'), 'utf8');
  const deps = parseLockfile(lock);
  return applyReachability(deps, await scanImports(repoPath));
}

/** inventory -> OSV -> KEV + EPSS -> score. */
export async function scanRepo(
  repoPath: string,
  repo: RepoContext,
  f: FetchFn = fetch,
): Promise<ScanResult> {
  const dependencies = await inventory(repoPath);
  const hits = await osvQueryBatch(dependencies, f);
  const vulns = await osvGetVulns([...hits.values()].flat(), f);

  const cves = [...vulns.values()].flatMap((v) => v.cveIds);
  const [kev, epss] = await Promise.all([fetchKev(f), cves.length ? fetchEpss(cves, f) : new Map()]);
  enrich(vulns.values(), kev, epss);

  const findings: Finding[] = [];
  for (const dep of dependencies) {
    for (const id of hits.get(`${dep.name}@${dep.version}`) ?? []) {
      const vulnerability = vulns.get(id)!;
      findings.push({ ...assess(dep, vulnerability, repo), dependency: dep, vulnerability });
    }
  }
  findings.sort((a, b) => b.score - a.score);
  return { repo, dependencies, findings };
}
