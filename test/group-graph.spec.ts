import { buildGraph, ROOT } from '../src/core/graph';
import { groupFindings } from '../src/core/group';
import { Finding } from '../src/core/pipeline';
import { Dependency, ThreatLevel } from '../src/core/types';

const dep = (name: string, path: string[], o: Partial<Dependency> = {}): Dependency => ({
  name, version: '1.0.0', direct: path.length === 1, dev: false, reachable: true, importCount: 1, children: [], peers: [], path, ...o,
});
const finding = (d: Dependency, id: string, score: number, level: ThreatLevel, fix: string | null): Finding => ({
  score, level, reasons: [], fixVersion: fix, dependency: d,
  vulnerability: { id, aliases: [], cveIds: [], summary: '', severity: 'HIGH', malicious: false, fixedVersions: {} },
});

describe('groupFindings', () => {
  it('one number per package: worst score, highest fix, unfixed count', () => {
    const multer = dep('multer', ['@nestjs/core', '@nestjs/platform-express', 'multer']);
    const g = groupFindings([
      finding(multer, 'a', 45, 'RELEVANT', '2.3.0'),
      finding(multer, 'b', 42, 'RELEVANT', '2.5.0'),
      finding(multer, 'c', 20, 'IRRELEVANT', null),
    ]);
    expect(g).toHaveLength(1);
    expect(g[0]).toMatchObject({ name: 'multer', score: 45, level: 'RELEVANT', fixVersion: '2.5.0', unfixed: 1 });
    expect(g[0].path).toEqual(['@nestjs/core', '@nestjs/platform-express', 'multer']);
  });
});

describe('buildGraph', () => {
  it('draws threat paths from your code and marks edges with the worst level on them', () => {
    const core = dep('@nestjs/core', ['@nestjs/core']);
    const pe = dep('@nestjs/platform-express', ['@nestjs/core', '@nestjs/platform-express'], { direct: true, loadedBy: '@nestjs/core' });
    const multer = dep('multer', ['@nestjs/core', '@nestjs/platform-express', 'multer'], { direct: false });
    const ptr = dep('path-to-regexp', ['@nestjs/core', 'path-to-regexp'], { direct: false });
    const axios = dep('axios', ['axios']);
    const devOnly = dep('handlebars', ['handlebars'], { dev: true, reachable: null, path: undefined });
    const groups = groupFindings([
      finding(multer, 'm', 45, 'RELEVANT', '2.5.0'),
      finding(ptr, 'p', 73, 'CRITICAL', '8.4.0'),
      finding(devOnly, 'h', 13, 'IRRELEVANT', '4.7.9'),
    ]);
    const g = buildGraph([core, pe, multer, ptr, axios, devOnly], groups);
    const ids = g.nodes.map((n) => n.id);
    expect(ids).toEqual(expect.arrayContaining([ROOT, '@nestjs/core', '@nestjs/platform-express', 'multer', 'path-to-regexp', 'axios']));
    expect(ids).not.toContain('handlebars'); // dev-only never appears in the view
    const edge = (a: string, b: string) => g.edges.find((e) => e.from === a && e.to === b);
    expect(edge(ROOT, '@nestjs/core')?.level).toBe('CRITICAL');
    expect(edge('@nestjs/core', '@nestjs/platform-express')?.level).toBe('RELEVANT');
    expect(edge(ROOT, 'axios')?.level).toBeNull();
    expect(g.nodes.find((n) => n.id === 'multer')).toMatchObject({ depth: 3, level: 'RELEVANT', vulns: 1 });
  });
});

describe('buildGraph with several versions of one package', () => {
  it('uses the running version, ignores dev/unreachable versions and their findings', () => {
    const typeorm = dep('typeorm', ['typeorm']);
    const glob = dep('glob', ['typeorm', 'glob'], { direct: false, version: '10.5.0' });
    const globDev = dep('glob', ['glob'], { direct: false, version: '7.2.3', dev: true, reachable: null, path: undefined });
    const mm = dep('minimatch', ['typeorm', 'glob', 'minimatch'], { direct: false, version: '9.0.9' });
    const mmDev = dep('minimatch', ['minimatch'], { direct: false, version: '3.1.5', dev: true, reachable: null, path: undefined });
    const be = dep('brace-expansion', ['typeorm', 'glob', 'minimatch', 'brace-expansion'], { direct: false, version: '2.0.2' });
    const beDev = dep('brace-expansion', ['brace-expansion'], { direct: false, version: '5.0.4', dev: true, reachable: null, path: undefined });
    const uuid = dep('uuid', ['uuid'], { version: '13.0.0' });
    const uuidOld = dep('uuid', ['uuid'], { direct: false, version: '11.1.0', reachable: null, path: undefined });
    // dev / unreachable versions listed last, like a lockfile would
    const deps = [typeorm, glob, mm, be, uuid, globDev, mmDev, beDev, uuidOld];
    const groups = groupFindings([
      finding(be, 'be', 52, 'RELEVANT', '2.1.7'),
      finding(mmDev, 'mm', 20, 'IRRELEVANT', '3.1.6'),
      finding(uuidOld, 'u', 25, 'IRRELEVANT', '11.1.1'),
    ]);
    const g = buildGraph(deps, groups);
    const node = (n: string) => g.nodes.find((x) => x.id === n);
    expect(node('brace-expansion')).toMatchObject({ version: '2.0.2', level: 'RELEVANT', depth: 4 });
    expect(node('glob')).toMatchObject({ version: '10.5.0', depth: 2 });
    expect(node('minimatch')).toMatchObject({ version: '9.0.9', level: null, depth: 3 }); // dev version's finding not drawn
    expect(node('uuid')).toMatchObject({ version: '13.0.0', level: null, depth: 1 }); // old unreachable uuid not drawn
    expect(g.edges.find((e) => e.from === 'minimatch' && e.to === 'brace-expansion')?.level).toBe('RELEVANT');
    expect(g.edges.find((e) => e.from === ROOT && e.to === 'minimatch')).toBeUndefined();
  });
});
