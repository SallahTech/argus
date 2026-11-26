import { fetchEpss, fetchKev, osvGetVulns, osvQueryBatch } from '../feeds';
import { checkFeature } from '../features';
import { applyReachability, countImports, indexSources } from '../reachability';
import { assess, THRESHOLDS } from '../scoring';
import { Dependency, FetchFn, RepoContext, ThreatLevel, Vulnerability } from '../types';
import { LockSnapshot, lockfileHistory } from './git';

/** One vulnerability in one installed version, followed through time. */
export interface HistoryFinding {
  name: string;
  version: string;
  vulnId: string;
  cveId: string | null;
  summary: string;
  severity: string;
  /** when the advisory was published */
  published: string | null;
  /** when CISA confirmed exploitation in the wild */
  kevDate: string | null;
  /** when this version was first / last in your lockfile */
  installedFrom: string;
  /** first day it was gone again (you upgraded), null = still installed */
  removedOn: string | null;
  firstRelevant: string | null;
  firstCritical: string | null;
  maxScore: number;
  /** days between Argus flagging it RELEVANT and CISA's KEV listing (positive = Argus was earlier) */
  leadDays: number | null;
  /** days from first RELEVANT to the upgrade (or until today, if still open) */
  daysOpen: number | null;
  /** score changes only */
  timeline: { date: string; score: number; level: ThreatLevel; why: string }[];
}

export interface HistoryReport {
  repo: RepoContext;
  from: string;
  to: string;
  snapshots: { date: string; sha: string; packages: number }[];
  findings: HistoryFinding[];
  summary: {
    affected: number;
    everRelevant: number;
    exploited: number;
    flaggedBeforeKev: number;
    medianLeadDays: number | null;
    fixed: number;
    medianDaysToFix: number | null;
    stillOpen: number;
  };
}

const DAY = 86_400_000;
const day = (d: Date | string) => new Date(d).toISOString().slice(0, 10);
const addDays = (d: string, n: number) => day(new Date(new Date(d).getTime() + n * DAY));
const diffDays = (a: string, b: string) => Math.round((new Date(b).getTime() - new Date(a).getTime()) / DAY);
const median = (xs: number[]) => {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : Math.round((s[s.length / 2 - 1] + s[s.length / 2]) / 2);
};

export interface ReplayOptions {
  since?: string;
  until?: string;
  /** EPSS is sampled once per this many days (default 7) */
  epssEveryDays?: number;
  fetch?: FetchFn;
  onProgress?: (step: string, detail: string) => void;
}

/**
 * The time machine: replay the project's lockfile history against what was
 * known on each day (advisories published so far, EPSS as it was, KEV as it
 * was) and record when each vulnerability would have been flagged.
 *
 * Reachability and feature checks use the code as it is today.
 */
export async function replayHistory(repoPath: string, repo: RepoContext, opts: ReplayOptions = {}): Promise<HistoryReport> {
  const f = opts.fetch ?? fetch;
  const progress = opts.onProgress ?? (() => {});
  const to = opts.until ?? day(new Date());
  const from = opts.since ?? addDays(to, -365);

  const snapshots = await lockfileHistory(repoPath, { since: from, until: to, maxSnapshots: 400 });
  if (!snapshots.length) throw new Error('No lockfile history found (is this a git repo with a committed lockfile?)');
  progress('history', `${snapshots.length} lockfile versions between ${snapshots[0].date} and ${to}`);

  // today's code decides reachability and feature use for every snapshot
  const sources = await indexSources(repoPath);
  const imports = countImports(sources);
  const states = snapshots.map((s) => ({ ...s, dependencies: applyReachability(s.dependencies, imports) }));

  // every package version that was ever installed, asked to OSV once
  const unique = new Map<string, Dependency>();
  for (const s of states) for (const d of s.dependencies) unique.set(`${d.name}@${d.version}`, d);
  const hits = await osvQueryBatch([...unique.values()], f);
  const vulns = await osvGetVulns([...hits.values()].flat(), f);
  progress('osv', `${unique.size} package versions ever installed · ${vulns.size} advisories`);

  // KEV gives a date per CVE; EPSS is fetched as it was on sampled days
  const kev = await fetchKev(f);
  const cves = [...new Set([...vulns.values()].flatMap((v) => v.cveIds))];
  const step = opts.epssEveryDays ?? 7;
  const samples: string[] = [];
  for (let d = from; d <= to; d = addDays(d, step)) samples.push(d);
  if (samples.at(-1) !== to) samples.push(to);
  const epssAt = new Map<string, Map<string, { score: number; percentile: number }>>();
  if (cves.length) {
    const queue = [...samples];
    const worker = async () => {
      for (let s = queue.shift(); s; s = queue.shift()) {
        try {
          epssAt.set(s, await fetchEpss(cves, f, s));
        } catch {
          epssAt.set(s, new Map()); // missing day: treated as no EPSS data
        }
      }
    };
    await Promise.all(Array.from({ length: 4 }, worker));
  }
  progress('intel', `KEV ${kev.size} entries · EPSS sampled on ${samples.length} days for ${cves.length} CVEs`);

  // days on which anything could have changed
  const events = new Set<string>([from, to, ...samples, ...states.map((s) => s.date)]);
  for (const v of vulns.values()) if (v.published) events.add(day(v.published));
  for (const c of cves) {
    const k = kev.get(c);
    if (k) events.add(k.dateAdded);
  }
  const dates = [...events].filter((d) => d >= from && d <= to).sort();

  const tracked = new Map<string, HistoryFinding>();
  const presentOn = new Map<string, string>(); // key -> last date seen installed
  for (const date of dates) {
    const state = [...states].reverse().find((s) => s.date <= date);
    if (!state) continue;
    const epssSample = [...samples].reverse().find((s) => s <= date);
    const epssToday = epssSample ? epssAt.get(epssSample) : undefined;
    const seenToday = new Set<string>();

    for (const dep of state.dependencies) {
      for (const id of hits.get(`${dep.name}@${dep.version}`) ?? []) {
        const base = vulns.get(id)!;
        if (base.published && day(base.published) > date) continue; // not disclosed yet
        const v: Vulnerability = { ...base, kev: undefined, epss: undefined };
        for (const c of base.cveIds) {
          const k = kev.get(c);
          if (k && k.dateAdded <= date && !v.kev) v.kev = k;
          const e = epssToday?.get(c);
          if (e && (!v.epss || e.percentile > v.epss.percentile)) v.epss = e;
        }
        const check = checkFeature(dep, v, sources);
        const a = assess(dep, v, repo, check);
        const key = `${dep.name}@${dep.version}|${id}`;
        seenToday.add(key);
        presentOn.set(key, date);

        let t = tracked.get(key);
        if (!t) {
          const kevDate =
            base.cveIds
              .map((c) => kev.get(c)?.dateAdded)
              .filter((x): x is string => !!x && x <= to) // not known yet at the end of the replay
              .sort()[0] ?? null;
          t = {
            name: dep.name,
            version: dep.version,
            vulnId: id,
            cveId: base.cveIds[0] ?? null,
            summary: base.summary,
            severity: base.severity,
            published: base.published ? day(base.published) : null,
            kevDate,
            installedFrom: date,
            removedOn: null,
            firstRelevant: null,
            firstCritical: null,
            maxScore: 0,
            leadDays: null,
            daysOpen: null,
            timeline: [],
          };
          tracked.set(key, t);
        }
        t.removedOn = null; // installed again (or still)
        if (a.score >= THRESHOLDS.relevant && !t.firstRelevant) t.firstRelevant = date;
        if (a.score >= THRESHOLDS.critical && !t.firstCritical) t.firstCritical = date;
        t.maxScore = Math.max(t.maxScore, a.score);
        const last = t.timeline.at(-1);
        if (!last || last.score !== a.score) t.timeline.push({ date, score: a.score, level: a.level, why: a.reasons.slice(0, 3).join(' · ') });
      }
    }
    // anything tracked but not installed today was upgraded or removed
    for (const [key, t] of tracked) if (!seenToday.has(key) && !t.removedOn && presentOn.get(key)! < date) t.removedOn = date;
  }

  const findings = [...tracked.values()];
  for (const t of findings) {
    if (t.firstRelevant && t.kevDate && t.kevDate >= t.installedFrom) t.leadDays = diffDays(t.firstRelevant, t.kevDate);
    if (t.firstRelevant) t.daysOpen = diffDays(t.firstRelevant, t.removedOn ?? to);
  }
  findings.sort((a, b) => b.maxScore - a.maxScore || a.name.localeCompare(b.name));

  const relevant = findings.filter((t) => t.firstRelevant);
  const lead = relevant.filter((t) => t.leadDays !== null && t.leadDays > 0).map((t) => t.leadDays!);
  const fixed = relevant.filter((t) => t.removedOn);
  return {
    repo,
    from,
    to,
    snapshots: states.map((s) => ({ date: s.date, sha: s.sha, packages: s.dependencies.length })),
    findings,
    summary: {
      affected: findings.length,
      everRelevant: relevant.length,
      exploited: findings.filter((t) => t.kevDate).length,
      flaggedBeforeKev: lead.length,
      medianLeadDays: median(lead),
      fixed: fixed.length,
      medianDaysToFix: median(fixed.map((t) => t.daysOpen!)),
      stillOpen: relevant.filter((t) => !t.removedOn).length,
    },
  };
}

export type { LockSnapshot };
