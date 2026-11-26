import * as semver from 'semver';
import { Finding } from './pipeline';
import { ThreatLevel } from './types';

export const LEVEL_RANK: Record<ThreatLevel, number> = { IRRELEVANT: 0, RELEVANT: 1, CRITICAL: 2 };

/** One "number": every vulnerability affecting one package@version, with one action. */
export interface ThreatGroup {
  key: string; // name@version
  name: string;
  version: string;
  score: number; // worst finding
  level: ThreatLevel;
  findings: Finding[]; // worst first
  /** one upgrade that fixes every finding that has a fix */
  fixVersion: string | null;
  /** some findings have no fix yet */
  unfixed: number;
  path: string[];
}

export function groupFindings(findings: Finding[]): ThreatGroup[] {
  const groups = new Map<string, ThreatGroup>();
  for (const f of findings) {
    const key = `${f.dependency.name}@${f.dependency.version}`;
    let g = groups.get(key);
    if (!g) {
      g = {
        key,
        name: f.dependency.name,
        version: f.dependency.version,
        score: 0,
        level: 'IRRELEVANT',
        findings: [],
        fixVersion: null,
        unfixed: 0,
        path: f.dependency.path ?? [f.dependency.name],
      };
      groups.set(key, g);
    }
    g.findings.push(f);
    if (f.score > g.score) g.score = f.score;
    if (LEVEL_RANK[f.level] > LEVEL_RANK[g.level]) g.level = f.level;
    if (f.fixVersion) {
      if (!g.fixVersion || semver.gt(f.fixVersion, g.fixVersion)) g.fixVersion = f.fixVersion;
    } else if (!f.vulnerability.malicious) g.unfixed++;
  }
  const out = [...groups.values()];
  for (const g of out) g.findings.sort((a, b) => b.score - a.score);
  return out.sort((a, b) => b.score - a.score || b.findings.length - a.findings.length);
}
