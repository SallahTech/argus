import { Dependency, FetchFn, Severity, Vulnerability } from './types';

const OSV = 'https://api.osv.dev/v1';
const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function json<T>(f: FetchFn, url: string, init?: RequestInit): Promise<T> {
  const res = await f(url, init);
  if (!res.ok) throw new Error(`${init?.method ?? 'GET'} ${url} -> ${res.status}`);
  return (await res.json()) as T;
}

// ---------- OSV ----------

/** Returns OSV vuln ids affecting each dependency, keyed by name@version. */
export async function osvQueryBatch(
  deps: Dependency[],
  f: FetchFn = fetch,
): Promise<Map<string, string[]>> {
  const result = new Map<string, string[]>();
  for (const batch of chunk(deps, 1000)) {
    const body = {
      queries: batch.map((d) => ({ package: { name: d.name, ecosystem: 'npm' }, version: d.version })),
    };
    const res = await json<{ results: { vulns?: { id: string }[] }[] }>(f, `${OSV}/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    res.results.forEach((r, i) => {
      const ids = (r.vulns ?? []).map((v) => v.id);
      if (ids.length) result.set(`${batch[i].name}@${batch[i].version}`, ids);
    });
  }
  return result;
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  database_specific?: { severity?: string };
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
  }[];
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW'];

export function normalizeOsv(v: OsvVuln): Vulnerability {
  const aliases = v.aliases ?? [];
  const cveIds = [v.id, ...aliases].filter((a) => a.startsWith('CVE-'));
  const sev = (v.database_specific?.severity ?? '').toUpperCase() as Severity;
  const fixedVersions: Record<string, string[]> = {};
  for (const a of v.affected ?? []) {
    if (a.package?.ecosystem !== 'npm') continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) {
        if (e.fixed) (fixedVersions[a.package.name] ??= []).push(e.fixed);
      }
    }
  }
  return {
    id: v.id,
    aliases,
    cveIds,
    summary: v.summary ?? v.details?.slice(0, 140) ?? '',
    severity: SEVERITIES.includes(sev) ? sev : 'UNKNOWN',
    malicious: v.id.startsWith('MAL-'),
    fixedVersions,
    published: v.published,
    modified: v.modified,
  };
}

export async function osvGetVulns(
  ids: string[],
  f: FetchFn = fetch,
  concurrency = 8,
): Promise<Map<string, Vulnerability>> {
  const out = new Map<string, Vulnerability>();
  const queue = [...new Set(ids)];
  const worker = async () => {
    while (queue.length) {
      const id = queue.shift()!;
      out.set(id, normalizeOsv(await json<OsvVuln>(f, `${OSV}/vulns/${encodeURIComponent(id)}`)));
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return out;
}

// ---------- CISA KEV ----------

export async function fetchKev(
  f: FetchFn = fetch,
): Promise<Map<string, { dateAdded: string; ransomware: boolean }>> {
  const res = await json<{
    vulnerabilities: { cveID: string; dateAdded: string; knownRansomwareCampaignUse?: string }[];
  }>(f, KEV_URL);
  return new Map(
    res.vulnerabilities.map((v) => [
      v.cveID,
      { dateAdded: v.dateAdded, ransomware: v.knownRansomwareCampaignUse === 'Known' },
    ]),
  );
}

// ---------- FIRST EPSS ----------

export async function fetchEpss(
  cves: string[],
  f: FetchFn = fetch,
): Promise<Map<string, { score: number; percentile: number }>> {
  const out = new Map<string, { score: number; percentile: number }>();
  for (const batch of chunk([...new Set(cves)], 50)) {
    const res = await json<{ data: { cve: string; epss: string; percentile: string }[] }>(
      f,
      `${EPSS_URL}?cve=${batch.join(',')}`,
    );
    for (const d of res.data) out.set(d.cve, { score: +d.epss, percentile: +d.percentile });
  }
  return out;
}

/** Attach KEV + EPSS to each vulnerability (uses the worst CVE alias). */
export function enrich(
  vulns: Iterable<Vulnerability>,
  kev: Map<string, { dateAdded: string; ransomware: boolean }>,
  epss: Map<string, { score: number; percentile: number }>,
): void {
  for (const v of vulns) {
    for (const cve of v.cveIds) {
      const k = kev.get(cve);
      if (k && !v.kev) v.kev = k;
      const e = epss.get(cve);
      if (e && (!v.epss || e.percentile > v.epss.percentile)) v.epss = e;
    }
  }
}
