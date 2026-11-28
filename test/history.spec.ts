import { execFileSync } from 'child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { lockfileHistory } from '../src/core/history/git';
import { replayHistory } from '../src/core/history/replay';

/** A tiny git repo whose lockfile changes on known dates. */
function makeRepo(): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'argus-history-'));
  const git = (args: string[], date?: string) =>
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', ...args], {
      cwd: dir,
      env: { ...process.env, ...(date ? { GIT_AUTHOR_DATE: `${date}T12:00:00Z`, GIT_COMMITTER_DATE: `${date}T12:00:00Z` } : {}) },
      stdio: 'ignore',
    });
  const lock = (a: string) =>
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { a: '^1', b: '^1' } },
        'node_modules/a': { version: a },
        'node_modules/b': { version: '1.0.0' },
      },
    });
  git(['init', '-q']);
  mkdirSync(path.join(dir, 'src'));
  writeFileSync(path.join(dir, 'src/index.ts'), "import a from 'a';\nimport b from 'b';\n");
  writeFileSync(path.join(dir, 'package-lock.json'), lock('1.0.0'));
  git(['add', '-A']);
  git(['commit', '-qm', 'init'], '2026-01-10');
  writeFileSync(path.join(dir, 'package-lock.json'), lock('1.0.1')); // upgrade a: fixes CVE-A
  git(['commit', '-qam', 'upgrade a'], '2026-06-01');
  return dir;
}

const ok = (b: unknown) => ({ ok: true, status: 200, json: async () => b }) as Response;
const fakeFeeds = (async (url: string, init?: RequestInit) => {
  if (url.endsWith('/querybatch')) {
    const { queries } = JSON.parse(String(init!.body));
    return ok({
      results: queries.map((q: { package: { name: string }; version: string }) =>
        q.package.name === 'a' && q.version === '1.0.0' ? { vulns: [{ id: 'GHSA-A' }] } : q.package.name === 'b' ? { vulns: [{ id: 'GHSA-B' }] } : {},
      ),
    });
  }
  if (url.endsWith('/vulns/GHSA-A'))
    return ok({ id: 'GHSA-A', aliases: ['CVE-2026-0001'], summary: 'bug in a', published: '2026-01-05T00:00:00Z', database_specific: { severity: 'HIGH' } });
  if (url.endsWith('/vulns/GHSA-B'))
    return ok({ id: 'GHSA-B', aliases: ['CVE-2026-0002'], summary: 'bug in b', published: '2026-03-01T00:00:00Z', database_specific: { severity: 'CRITICAL' } });
  if (url.includes('known_exploited')) return ok({ vulnerabilities: [{ cveID: 'CVE-2026-0002', dateAdded: '2026-04-15' }] });
  if (url.includes('epss')) {
    const cves = new URL(url).searchParams.get('cve')!.split(',');
    return ok({ data: cves.map((cve) => ({ cve, epss: '0.01', percentile: '0.5' })) });
  }
  throw new Error('unexpected ' + url);
}) as typeof fetch;

describe('lockfile history', () => {
  it('one snapshot per lockfile change, plus uncommitted changes', async () => {
    const dir = makeRepo();
    let snaps = await lockfileHistory(dir, { until: '2026-11-26' });
    expect(snaps.map((s) => [s.date, s.dependencies.find((d) => d.name === 'a')!.version])).toEqual([
      ['2026-01-10', '1.0.0'],
      ['2026-06-01', '1.0.1'],
    ]);
    // uncommitted downgrade shows up as today's working copy
    writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { '': {}, 'node_modules/a': { version: '0.9.0' } } }));
    snaps = await lockfileHistory(dir, { until: '2026-11-26' });
    expect(snaps.at(-1)).toMatchObject({ date: '2026-11-26', sha: 'working-copy' });
  });

  it('starts from the state in force on --since', async () => {
    const snaps = await lockfileHistory(makeRepo(), { since: '2026-03-01', until: '2026-11-26' });
    expect(snaps.map((s) => s.date)).toEqual(['2026-03-01', '2026-06-01']);
  });
});

describe('time machine', () => {
  it('measures lead time before KEV and time to fix', async () => {
    const r = await replayHistory(makeRepo(), { name: 'demo', internetFacing: false }, { since: '2026-01-01', until: '2026-11-26', fetch: fakeFeeds });
    const a = r.findings.find((t) => t.name === 'a')!;
    const b = r.findings.find((t) => t.name === 'b')!;

    // a: relevant from the first lockfile, fixed by the June upgrade
    expect(a).toMatchObject({ installedFrom: '2026-01-10', firstRelevant: '2026-01-10', removedOn: '2026-06-01', daysOpen: 142, kevDate: null });

    // b: flagged on disclosure, CISA confirmed exploitation 45 days later
    expect(b).toMatchObject({ published: '2026-03-01', firstRelevant: '2026-03-01', firstCritical: '2026-04-15', kevDate: '2026-04-15', leadDays: 45, removedOn: null });
    expect(b.timeline.map((x) => x.level)).toEqual(['RELEVANT', 'CRITICAL']);

    expect(r.summary).toEqual({
      affected: 2,
      everRelevant: 2,
      exploited: 1,
      flaggedBeforeKev: 1,
      medianLeadDays: 45,
      fixed: 1,
      medianDaysToFix: 142,
      stillOpen: 1,
    });
  });

  it('never uses data from the future', async () => {
    // replay only up to before b was disclosed: b must not appear at all
    const r = await replayHistory(makeRepo(), { name: 'demo', internetFacing: false }, { since: '2026-01-01', until: '2026-02-15', fetch: fakeFeeds });
    expect(r.findings.map((t) => t.name)).toEqual(['a']);
    expect(r.findings[0].kevDate).toBeNull();
  });

  it('a KEV listing after the replay window is not known yet', async () => {
    const r = await replayHistory(makeRepo(), { name: 'demo', internetFacing: false }, { since: '2026-01-01', until: '2026-04-01', fetch: fakeFeeds });
    const b = r.findings.find((t) => t.name === 'b')!;
    expect(b).toMatchObject({ firstRelevant: '2026-03-01', kevDate: null, leadDays: null, firstCritical: null });
  });
});

describe('two lockfiles in one commit', () => {
  it('history follows the lockfile Argus scans today', async () => {
    const dir = makeRepo();
    // add a yarn.lock in a later commit, then make package-lock.json the newer file on disk
    writeFileSync(path.join(dir, 'yarn.lock'), '# yarn lockfile v1\n\n"a@^1":\n  version "1.0.1"\n\n"b@^1":\n  version "1.0.0"\n');
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', 'add', '-A'], { cwd: dir });
    execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'yarn', '--date', '2026-06-01T13:00:00Z'], {
      cwd: dir,
      env: { ...process.env, GIT_COMMITTER_DATE: '2026-06-01T13:00:00Z' },
    });
    const { utimesSync } = await import('fs');
    utimesSync(path.join(dir, 'yarn.lock'), new Date('2026-06-01'), new Date('2026-06-01'));
    const snaps = await lockfileHistory(dir, { until: '2026-11-26' });
    expect(snaps.at(-1)!.file).toBe('package-lock.json');
  });
});

describe('time machine frames', () => {
  it('records a Machine view frame at every turning point, with notes', async () => {
    const r = await replayHistory(makeRepo(), { name: 'demo', internetFacing: false }, { since: '2026-01-01', until: '2026-11-26', fetch: fakeFeeds, frames: true });
    const byDate = Object.fromEntries(r.frames!.map((f) => [f.date, f]));
    expect(byDate['2026-01-10'].notes).toContainEqual({ kind: 'relevant', text: 'a@1.0.0 became RELEVANT' });
    expect(byDate['2026-03-01'].notes).toContainEqual({ kind: 'relevant', text: 'b@1.0.0 became RELEVANT' });
    expect(byDate['2026-04-15'].notes).toEqual(
      expect.arrayContaining([
        { kind: 'critical', text: 'b@1.0.0 escalated to CRITICAL' },
        { kind: 'exploited', text: 'CVE-2026-0002 confirmed exploited (CISA KEV)' },
      ]),
    );
    expect(byDate['2026-06-01'].notes).toEqual(
      expect.arrayContaining([expect.objectContaining({ kind: 'lockfile' }), { kind: 'resolved', text: 'a@1.0.0 no longer relevant' }]),
    );
    // the graph in each frame reflects that day: b is red on 2026-04-15, a is gone by 2026-06-01
    expect(byDate['2026-04-15'].graph.nodes.find((n) => n.id === 'b')?.level).toBe('CRITICAL');
    expect(byDate['2026-06-01'].graph.nodes.find((n) => n.id === 'a')?.level).toBeNull();
    // quiet days are skipped: far fewer frames than replayed days
    expect(r.frames!.length).toBeLessThan(15);
    expect(r.frames!.at(-1)!.date).toBe('2026-11-26');
  });
});
