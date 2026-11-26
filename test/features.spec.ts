import { checkFeature } from '../src/core/features';
import { parseNpmLockfile } from '../src/core/lockfiles';
import { applyReachability, SourceIndex } from '../src/core/reachability';
import { assess } from '../src/core/scoring';
import { Dependency, Vulnerability } from '../src/core/types';

const src = (files: Record<string, string>): SourceIndex => ({ files: Object.entries(files).map(([file, code]) => ({ file, code })) });
const dep = (name: string, o: Partial<Dependency> = {}): Dependency => ({
  name, version: '1.0.0', direct: false, dev: false, reachable: true, importCount: 0, children: [], peers: [], via: 'x', path: ['x', name], ...o,
});
const vuln = (summary: string, o: Partial<Vulnerability> = {}): Vulnerability => ({
  id: 'GHSA-1', aliases: [], cveIds: ['CVE-2026-1'], summary, severity: 'HIGH', malicious: false, fixedVersions: {}, epss: { score: 0.01, percentile: 0.6 }, ...o,
});
const repo = { name: 'app', internetFacing: true };

const NEST = {
  'src/main.ts': "import { NestFactory } from '@nestjs/core';\nconst app = await NestFactory.create(AppModule);\nawait app.listen(3000);",
  'src/endpoints/endpoints.controller.ts': "@Controller('endpoints')\nexport class C {\n  @Get(':id')\n  one() {}\n  @Post()\n  create() {}\n}",
};

describe('multer', () => {
  const v = vuln('Denial of Service via deeply nested field names');
  it('unused when no upload interceptor exists, and the score drops to IRRELEVANT', () => {
    const c = checkFeature(dep('multer'), v, src(NEST))!;
    expect(c).toMatchObject({ status: 'unused', kind: 'feature' });
    const before = assess(dep('multer'), v, repo);
    const after = assess(dep('multer'), v, repo, c);
    expect(before.level).toBe('RELEVANT');
    expect(after.level).toBe('IRRELEVANT');
    expect(after.reasons.join()).toMatch(/not exploitable here/);
  });
  it('used, with file:line evidence, when FileInterceptor is used', () => {
    const s = src({ ...NEST, 'src/upload.controller.ts': "import { FileInterceptor } from '@nestjs/platform-express';\n\n@UseInterceptors(FileInterceptor('file'))\nupload() {}" });
    const c = checkFeature(dep('multer'), v, s)!;
    expect(c).toMatchObject({ status: 'used', evidence: ['src/upload.controller.ts:1'] });
    expect(assess(dep('multer'), v, repo, c).level).toBe('RELEVANT');
  });
});

describe('proxy-addr', () => {
  const v = vuln('IP spoofing via IPv4-mapped IPv6 trust subnet', { severity: 'CRITICAL' });
  it('unused without trust proxy', () => expect(checkFeature(dep('proxy-addr'), v, src(NEST))?.status).toBe('unused'));
  it("used with app.set('trust proxy')", () =>
    expect(checkFeature(dep('proxy-addr'), v, src({ ...NEST, 'src/main.ts': "app.set('trust proxy', 1);" }))?.status).toBe('used'));
  it('makes no claim about other proxy-addr advisories', () =>
    expect(checkFeature(dep('proxy-addr'), vuln('Some unrelated parsing bug'), src(NEST))).toBeUndefined());
});

describe('path-to-regexp', () => {
  const optional = vuln('Denial of Service via sequential optional groups');
  const wildcard = vuln('Regular Expression Denial of Service via multiple wildcards');
  it('plain routes are not affected', () => {
    expect(checkFeature(dep('path-to-regexp'), optional, src(NEST))?.status).toBe('unused');
    expect(checkFeature(dep('path-to-regexp'), wildcard, src(NEST))?.status).toBe('unused');
  });
  it('flags the route that uses the risky syntax', () => {
    const s = src({ ...NEST, 'src/files.controller.ts': "@Controller('files')\nclass F {\n  @Get('*path')\n  any() {}\n  @Get('/a{/:b}{/:c}')\n  opt() {}\n}" });
    expect(checkFeature(dep('path-to-regexp'), wildcard, s)).toMatchObject({ status: 'used', evidence: ["src/files.controller.ts:3 '*path'"] });
    expect(checkFeature(dep('path-to-regexp'), optional, s)).toMatchObject({ status: 'used', evidence: ["src/files.controller.ts:5 '/a{/:b}{/:c}'"] });
  });
  it('no routes found: no claim', () => expect(checkFeature(dep('path-to-regexp'), optional, src({ 'a.ts': 'x' }))).toBeUndefined());
});

describe('next', () => {
  const mw = vuln('Authorization Bypass in Next.js Middleware', { severity: 'CRITICAL' });
  it('middleware bypass needs a middleware or proxy file', () => {
    expect(checkFeature(dep('next'), mw, src({ 'app/page.tsx': 'export default 1' }))?.status).toBe('unused');
    expect(checkFeature(dep('next'), mw, src({ 'src/middleware.ts': 'export function middleware() {}' }))?.status).toBe('used');
    expect(checkFeature(dep('next'), mw, src({ 'proxy.ts': 'export function proxy() {}' }))?.status).toBe('used');
  });
  it('image optimizer needs next/image', () => {
    const v = vuln('Next.js Image Optimization cache poisoning');
    expect(checkFeature(dep('next'), v, src({ 'app/page.tsx': 'x' }))?.status).toBe('unused');
    expect(checkFeature(dep('next'), v, src({ 'app/page.tsx': "import Image from 'next/image';" }))?.status).toBe('used');
  });
  it('server actions need "use server"', () =>
    expect(checkFeature(dep('next'), vuln('Denial of Service in Server Actions'), src({ 'app/a.ts': "'use server';\nexport async function f() {}" }))?.status).toBe('used'));
  it('an exploited-in-the-wild CVE is softened, never silenced', () => {
    const kev = { ...mw, kev: { dateAdded: '2026-11-20', ransomware: false } };
    const d = dep('next', { direct: true, importCount: 3, path: ['next'] });
    const c = checkFeature(d, kev, src({ 'app/page.tsx': 'x' }))!;
    expect(c.status).toBe('unused');
    const a = assess(d, kev, { name: 'ui', internetFacing: true }, c);
    expect(a.level).toBe('RELEVANT');
    expect(a.reasons.join()).toMatch(/exploited in the wild, so kept visible: verify/);
  });
  it('unknown Next.js advisories make no claim', () => expect(checkFeature(dep('next'), vuln('Cache poisoning'), src({}))).toBeUndefined());
});

describe('sharp under next', () => {
  const v = vuln('libvips heap overflow on crafted image');
  const viaNext = dep('sharp', { path: ['next', 'sharp'] });
  it('unused when the app never uses next/image', () => expect(checkFeature(viaNext, v, src({ 'app/page.tsx': '<img src="/a.png" />' }))?.status).toBe('unused'));
  it('used with next/image', () => expect(checkFeature(viaNext, v, src({ 'app/page.tsx': "import Image from 'next/image';" }))?.status).toBe('used'));
  it('no claim when something else pulls sharp in', () => expect(checkFeature(dep('sharp', { path: ['thumbnailer', 'sharp'] }), v, src({}))).toBeUndefined());
});

describe('other rules', () => {
  it('lodash _.template', () => {
    const v = vuln('Code Injection via _.template imports key names');
    expect(checkFeature(dep('lodash'), v, src({ 'a.ts': "import { merge } from 'lodash';" }))?.status).toBe('unused');
    expect(checkFeature(dep('lodash'), v, src({ 'a.ts': '_.template(x)' }))?.status).toBe('used');
  });
  it('qs comma format', () => {
    const v = vuln('qs.stringify with arrayFormat comma throws');
    expect(checkFeature(dep('qs'), v, src(NEST))?.status).toBe('unused');
    expect(checkFeature(dep('qs'), v, src({ 'a.ts': "qs.stringify(x, { arrayFormat: 'comma' })" }))?.status).toBe('used');
  });
  it('malware is never ruled out', () =>
    expect(checkFeature(dep('multer'), vuln('Malicious code', { malicious: true }), src(NEST))).toBeUndefined());
});

describe('build time only', () => {
  // next -> postcss -> nanoid, source-map-js ; next -> @next/env (runtime)
  const lock = {
    lockfileVersion: 3,
    packages: {
      '': { dependencies: { next: '16', react: '19', tailwindcss: '4' } },
      'node_modules/next': { version: '16.2.1', dependencies: { postcss: '8', '@next/env': '16', 'styled-jsx': '5' } },
      'node_modules/postcss': { version: '8.4.31', dependencies: { nanoid: '3', 'source-map-js': '1' } },
      'node_modules/nanoid': { version: '3.3.11' },
      'node_modules/source-map-js': { version: '1.2.1' },
      'node_modules/@next/env': { version: '16.2.1' },
      'node_modules/styled-jsx': { version: '5.1.6', dependencies: { 'client-only': '0' } },
      'node_modules/client-only': { version: '0.0.1' },
      'node_modules/react': { version: '19.0.0' },
      'node_modules/tailwindcss': { version: '4.0.0' },
    },
  };
  const imports = new Map([['next', 4], ['react', 9]]);

  it('marks packages reachable only through a build tool', () => {
    const by = Object.fromEntries(applyReachability(parseNpmLockfile(lock), imports).map((d) => [d.name, d]));
    for (const n of ['postcss', 'nanoid', 'source-map-js']) expect(by[n]).toMatchObject({ reachable: true, buildTimeOnly: true, buildTool: 'postcss' });
    for (const n of ['next', '@next/env', 'styled-jsx', 'client-only', 'react']) expect(by[n].buildTimeOnly).toBeFalsy();
  });

  it('build-time-only findings drop out of RELEVANT', () => {
    const by = Object.fromEntries(applyReachability(parseNpmLockfile(lock), imports).map((d) => [d.name, d]));
    const v = vuln('nanoid predictable results with non-integer values');
    const c = checkFeature(by.nanoid, v, src({}))!;
    expect(c).toMatchObject({ status: 'unused', kind: 'build-time' });
    expect(c.detail).toMatch(/postcss, which runs at build time/);
    expect(assess(by.nanoid, v, repo, c).level).toBe('IRRELEVANT');
  });

  it('a package also used at runtime is not build time only', () => {
    const l = JSON.parse(JSON.stringify(lock));
    l.packages['node_modules/@next/env'].dependencies = { nanoid: '3' }; // runtime path to nanoid
    const by = Object.fromEntries(applyReachability(parseNpmLockfile(l), imports).map((d) => [d.name, d]));
    expect(by.nanoid.buildTimeOnly).toBeFalsy();
    expect(by['source-map-js'].buildTimeOnly).toBe(true);
  });

  it('a build tool you import in your own code counts as runtime', () => {
    const by = Object.fromEntries(applyReachability(parseNpmLockfile(lock), new Map([...imports, ['postcss', 1]])).map((d) => [d.name, d]));
    expect(by.postcss.buildTimeOnly).toBeFalsy();
  });
});
