import * as path from 'path';
import { parseLockfile } from '../src/core/lockfile';
import { importsInSource, packageFromSpecifier } from '../src/core/reachability';
import { normalizeOsv } from '../src/core/feeds';
import { assess, pickFixVersion } from '../src/core/scoring';
import { inventory, scanRepo } from '../src/core/pipeline';
import { Dependency, Vulnerability } from '../src/core/types';

const FIXTURE = path.join(__dirname, 'fixtures/demo-app');

const dep = (o: Partial<Dependency> = {}): Dependency => ({
  name: 'pkg', version: '1.0.0', direct: true, dev: false, reachable: true, importCount: 3, ...o,
});
const vuln = (o: Partial<Vulnerability> = {}): Vulnerability => ({
  id: 'GHSA-xxxx', aliases: [], cveIds: ['CVE-2099-0001'], summary: 'bad', severity: 'HIGH',
  malicious: false, fixedVersions: { pkg: ['1.0.5', '2.0.0'] }, ...o,
});
const repo = { name: 'demo', internetFacing: false };

describe('lockfile', () => {
  it('flattens, dedupes and flags direct/dev deps', async () => {
    const deps = await inventory(FIXTURE);
    const by = Object.fromEntries(deps.map((d) => [d.name, d]));
    expect(Object.keys(by).sort()).toEqual(['@acme/http', 'jest-mock-thing', 'lodash', 'minimist', 'moment']);
    expect(deps.filter((d) => d.name === 'minimist')).toHaveLength(1);
    expect(by.lodash).toMatchObject({ direct: true, reachable: true, importCount: 2 });
    expect(by['@acme/http']).toMatchObject({ direct: true, reachable: true });
    expect(by.moment).toMatchObject({ direct: true, reachable: false });
    expect(by.minimist).toMatchObject({ direct: false, reachable: null });
    expect(by['jest-mock-thing'].dev).toBe(true);
  });

  it('rejects lockfile v1 with a helpful message', () => {
    expect(() => parseLockfile({ lockfileVersion: 1 })).toThrow(/npm 7\+/);
  });
});

describe('reachability', () => {
  it('extracts package names from specifiers', () => {
    expect(packageFromSpecifier('lodash/fp')).toBe('lodash');
    expect(packageFromSpecifier('@nestjs/core/injector')).toBe('@nestjs/core');
    expect(packageFromSpecifier('./x')).toBeNull();
    expect(packageFromSpecifier('node:fs')).toBeNull();
  });
  it('finds import, require, dynamic import and re-exports', () => {
    const code = `import a from "a"; import 'b'; const c = require('c'); await import('d'); export * from 'e';`;
    expect([...importsInSource(code)].sort()).toEqual(['a', 'b', 'c', 'd', 'e']);
  });
});

describe('scoring', () => {
  it('KEV + high + direct prod reachable => CRITICAL', () => {
    const a = assess(dep(), vuln({ kev: { dateAdded: '2026-11-01', ransomware: false } }), repo);
    expect(a.score).toBe(75);
    expect(a.level).toBe('CRITICAL');
    expect(a.fixVersion).toBe('1.0.5');
    expect(a.reasons.join()).toMatch(/CISA KEV/);
  });
  it('moderate, transitive, dev-only => IRRELEVANT', () => {
    const a = assess(
      dep({ direct: false, dev: true, reachable: null }),
      vuln({ severity: 'MODERATE', epss: { score: 0.001, percentile: 0.5 } }),
      repo,
    );
    expect(a.level).toBe('IRRELEVANT');
    expect(a.score).toBeLessThan(10);
  });
  it('a direct dep that is never imported is heavily discounted', () => {
    const used = assess(dep(), vuln({ severity: 'CRITICAL' }), repo).score;
    const unused = assess(dep({ reachable: false, importCount: 0 }), vuln({ severity: 'CRITICAL' }), repo).score;
    expect(unused).toBeLessThan(used * 0.5);
  });
  it('internet-facing raises the score', () => {
    const v = vuln({ epss: { score: 0.2, percentile: 0.9 } });
    expect(assess(dep(), v, { ...repo, internetFacing: true }).score).toBeGreaterThan(assess(dep({ reachable: null }), v, repo).score);
  });
  it('malicious packages are always 100', () => {
    const a = assess(dep({ dev: true, direct: false }), vuln({ id: 'MAL-2026-1', malicious: true }), repo);
    expect(a).toMatchObject({ score: 100, level: 'CRITICAL' });
  });
  it('picks the smallest fix above the installed version', () => {
    expect(pickFixVersion('1.2.0', ['1.1.0', '2.0.0', '1.3.1'])).toBe('1.3.1');
    expect(pickFixVersion('3.0.0', ['1.0.0'])).toBeNull();
  });
});

describe('osv normalize', () => {
  it('maps severity, CVE aliases and fixed versions', () => {
    const v = normalizeOsv({
      id: 'GHSA-35jh-r3h4-6jhm',
      aliases: ['CVE-2021-23337'],
      summary: 'Command Injection in lodash',
      database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
    });
    expect(v).toMatchObject({ severity: 'HIGH', cveIds: ['CVE-2021-23337'], fixedVersions: { lodash: ['4.17.21'] }, malicious: false });
  });
});

describe('pipeline (mocked feeds)', () => {
  it('correlates OSV + KEV + EPSS into ranked findings', async () => {
    const fake = (async (url: string, init?: RequestInit) => {
      const ok = (body: unknown) => ({ ok: true, status: 200, json: async () => body }) as Response;
      if (url.endsWith('/querybatch')) {
        const { queries } = JSON.parse(String(init!.body));
        return ok({
          results: queries.map((q: any) =>
            q.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-lodash' }] }
            : q.package.name === 'minimist' ? { vulns: [{ id: 'GHSA-minimist' }] }
            : q.package.name === 'moment' ? { vulns: [{ id: 'GHSA-moment' }] }
            : {}),
        });
      }
      if (url.includes('/vulns/GHSA-lodash'))
        return ok({ id: 'GHSA-lodash', aliases: ['CVE-2021-23337'], summary: 'Command injection', database_specific: { severity: 'HIGH' },
          affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] });
      if (url.includes('/vulns/GHSA-minimist'))
        return ok({ id: 'GHSA-minimist', aliases: ['CVE-2021-44906'], summary: 'Prototype pollution', database_specific: { severity: 'CRITICAL' } });
      if (url.includes('/vulns/GHSA-moment'))
        return ok({ id: 'GHSA-moment', aliases: ['CVE-2022-24785'], summary: 'Path traversal', database_specific: { severity: 'HIGH' } });
      if (url.includes('known_exploited'))
        return ok({ vulnerabilities: [{ cveID: 'CVE-2021-23337', dateAdded: '2026-11-20', knownRansomwareCampaignUse: 'Unknown' }] });
      if (url.includes('epss'))
        return ok({ data: [
          { cve: 'CVE-2021-44906', epss: '0.012', percentile: '0.85' },
          { cve: 'CVE-2022-24785', epss: '0.03', percentile: '0.92' },
        ] });
      throw new Error('unexpected ' + url);
    }) as typeof fetch;

    const r = await scanRepo(FIXTURE, repo, fake);
    expect(r.findings.map((f) => f.dependency.name)).toEqual(['lodash', 'minimist', 'moment']);
    expect(r.findings[0]).toMatchObject({ level: 'CRITICAL', fixVersion: '4.17.21' });
    // moment is high severity with a high EPSS but never imported: pushed down the list
    expect(r.findings[2].reasons).toContain('never imported in source');
  });
});
