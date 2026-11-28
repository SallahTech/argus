import * as semver from 'semver';
import { Assessment, Dependency, FeatureCheck, RepoContext, Severity, ThreatLevel, Vulnerability } from './types';

export const THRESHOLDS = { critical: 70, relevant: 40 };

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 1.0,
  HIGH: 0.75,
  MODERATE: 0.45,
  LOW: 0.2,
  UNKNOWN: 0.4,
};

/** Smallest fixed version above the installed one. */
export function pickFixVersion(current: string, fixed: string[] = []): string | null {
  const valid = fixed.filter((v) => semver.valid(v) && semver.gt(v, current));
  return valid.sort(semver.compare)[0] ?? null;
}

export function levelFor(score: number): ThreatLevel {
  if (score >= THRESHOLDS.critical) return 'CRITICAL';
  if (score >= THRESHOLDS.relevant) return 'RELEVANT';
  return 'IRRELEVANT';
}

/**
 * score = 100 x severity x exploitability x exposure
 * Every factor that moves the score is recorded as a human-readable reason,
 * so each alert explains itself.
 */
export function assess(dep: Dependency, vuln: Vulnerability, repo: RepoContext, check?: FeatureCheck): Assessment {
  const reasons: string[] = [];
  const fixVersion = pickFixVersion(dep.version, vuln.fixedVersions[dep.name]);

  // Supply-chain malware skips the maths: it is always an emergency.
  if (vuln.malicious) {
    return {
      score: 100,
      level: 'CRITICAL',
      reasons: ['MALICIOUS PACKAGE (supply-chain attack)', dep.direct ? 'direct dependency' : 'pulled in transitively'],
      fixVersion: null,
    };
  }

  // 1. Severity
  const sev = SEVERITY_WEIGHT[vuln.severity];
  reasons.push(`${vuln.severity.toLowerCase()} severity`);

  // 2. Exploitability
  let exploit: number;
  if (vuln.kev) {
    exploit = 1;
    reasons.push(`exploited in the wild (CISA KEV since ${vuln.kev.dateAdded})`);
    if (vuln.kev.ransomware) reasons.push('used in ransomware campaigns');
  } else if (vuln.epss) {
    // floor of 0.35: fresh CVEs start with low EPSS, and "nobody exploits it yet" is not "safe"
    exploit = 0.35 + 0.65 * vuln.epss.percentile;
    reasons.push(
      `EPSS ${(vuln.epss.score * 100).toFixed(1)}% (top ${Math.max(1, Math.round((1 - vuln.epss.percentile) * 100))}%)`,
    );
  } else {
    exploit = 0.5;
    reasons.push('no exploit data yet');
  }

  // 3. Exposure
  let exposure: number;
  if (dep.direct) {
    exposure = 1;
    reasons.push('direct dependency');
  } else if (dep.via) {
    exposure = 0.85;
    reasons.push(`pulled in by ${dep.via} (which you import)`);
  } else {
    exposure = 0.6;
    reasons.push('transitive dependency');
  }
  if (dep.dev) {
    exposure *= 0.3;
    reasons.push('dev-only');
  } else {
    reasons.push('ships to production');
  }
  if (dep.reachable === true) {
    if (dep.direct && dep.loadedBy) reasons.push(`loaded at runtime by ${dep.loadedBy}`);
    else if (dep.direct) reasons.push(`imported in ${dep.importCount} file${dep.importCount === 1 ? '' : 's'}`);
  } else if (dep.reachable === false) {
    exposure *= 0.4;
    reasons.push('never imported in source');
  } else exposure *= 0.8;
  if (repo.internetFacing && !dep.dev && check?.status !== 'unused') {
    exposure = Math.min(1, exposure * 1.15);
    reasons.push('internet-facing app');
  }

  // 4. Feature-level reachability: is the vulnerable part actually used?
  if (check?.status === 'unused') {
    if (vuln.kev && check.kind !== 'build-time') {
      // never fully silence an actively exploited CVE on a code heuristic
      exposure *= 0.55;
      reasons.push(`${check.detail} (exploited in the wild, so kept visible: verify)`);
    } else {
      exposure *= check.kind === 'build-time' ? 0.3 : check.kind === 'platform' ? 0.15 : 0.25;
      reasons.push(check.detail);
    }
  } else if (check?.status === 'used') {
    reasons.push(check.detail);
  }

  const score = Math.round(100 * sev * exploit * exposure);
  return { score, level: levelFor(score), reasons, fixVersion };
}
