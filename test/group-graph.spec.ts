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
