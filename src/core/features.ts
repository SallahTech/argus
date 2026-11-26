import { SourceIndex } from './reachability';
import { Dependency, FeatureCheck, Vulnerability } from './types';

/**
 * Feature-level reachability.
 *
 * A vulnerability usually lives in one feature of a package: multer's bugs are
 * in multipart upload parsing, proxy-addr's spoofing bug only matters when you
 * trust proxy headers. Each rule says which vulnerabilities it covers (by
 * advisory summary) and how to tell whether this project uses that feature.
 *
 * Rules only exist where the answer is reliable. No rule = no claim, and the
 * finding is scored as before.
 */
export interface FeatureRule {
  /** package the rule is about */
  pkg: string;
  /** human name of the feature, shown in alerts */
  feature: string;
  /** which advisories this applies to; omit = every advisory for the package */
  appliesTo?: RegExp;
  /** how the vulnerable feature gets used in source code */
  detect: Detector;
  /** why "unused" means not exploitable, shown in the case file */
  because: string;
  /** only apply when this package is pulled in directly by `via` (e.g. sharp under next) */
  via?: string;
}

type Detector =
  | { kind: 'code'; pattern: RegExp } // any source line matches
  | { kind: 'file'; pattern: RegExp } // a file with this path exists
  | { kind: 'routes'; risky: RegExp }; // a route string contains a risky token

const ROUTE_RES = [
  /@(?:Get|Post|Put|Patch|Delete|All|Options|Head|Controller)\(\s*(['"`])([^'"`]*)\1/g,
  /\.(?:get|post|put|patch|delete|all|use|route|options|head)\(\s*(['"`])([^'"`]+)\1/g,
];

export const RULES: FeatureRule[] = [
  {
    pkg: 'multer',
    feature: 'file uploads (multipart parsing)',
    detect: {
      kind: 'code',
      pattern: /\b(?:File|Files|FileFields|AnyFiles|NoFiles)Interceptor\b|\bMulterModule\b|\bmulter\s*\(/,
    },
    because: 'multer only parses requests on routes that accept uploads (FileInterceptor, multer())',
  },
  {
    pkg: 'proxy-addr',
    feature: 'trusting proxy headers (trust proxy)',
    appliesTo: /trust|spoof|subnet|x-forwarded/i,
    detect: { kind: 'code', pattern: /['"]trust proxy['"]|\btrustProxy\b/ },
    because: 'proxy headers are ignored unless trust proxy is enabled',
  },
  {
    pkg: 'path-to-regexp',
    feature: 'routes with optional groups { }',
    appliesTo: /optional/i,
    detect: { kind: 'routes', risky: /\{/ },
    because: 'the slow pattern is only built from routes that use optional groups',
  },
  {
    pkg: 'path-to-regexp',
    feature: 'routes with wildcards *',
    appliesTo: /wildcard/i,
    detect: { kind: 'routes', risky: /\*|\(\.\*\)/ },
    because: 'the slow pattern is only built from routes that use wildcards',
  },
  {
    pkg: 'sharp',
    via: 'next',
    feature: 'image optimization (next/image)',
    detect: { kind: 'code', pattern: /from\s+['"]next\/image['"]|\bimages\s*:\s*\{|from\s+['"]sharp['"]|require\(\s*['"]sharp['"]\s*\)/ },
    because: 'Next.js only loads sharp to optimize images for next/image',
  },
  {
    pkg: 'lodash',
    feature: '_.template',
    appliesTo: /template/i,
    detect: { kind: 'code', pattern: /\b_\.template\b|lodash[/.]template|\btemplate\s*\(/ },
    because: 'the injection is in _.template, which this project never calls',
  },
  {
    pkg: 'qs',
    feature: 'comma array format',
    appliesTo: /comma/i,
    detect: { kind: 'code', pattern: /arrayFormat\s*:\s*['"]comma['"]|\bcomma\s*:\s*true/ },
    because: 'the bug needs the comma option, which express and this project do not set',
  },
  {
    pkg: 'qs',
    feature: 'allowDots option',
    appliesTo: /allowDots|dot notation/i,
    detect: { kind: 'code', pattern: /\ballowDots\b/ },
    because: 'the bug needs allowDots, which this project never enables',
  },
  {
    pkg: 'next',
    feature: 'middleware / proxy',
    appliesTo: /middleware/i,
    detect: { kind: 'file', pattern: /^(?:src\/)?(?:middleware|proxy)\.(?:ts|js|mjs)$/ },
    because: 'without a middleware (proxy) file there is no middleware to bypass',
  },
  {
    pkg: 'next',
    feature: 'image optimization',
    appliesTo: /\bimage/i,
    detect: { kind: 'code', pattern: /from\s+['"]next\/image['"]|\bimages\s*:\s*\{/ },
    because: 'the image optimizer only serves requests when next/image or images config is used',
  },
  {
    pkg: 'next',
    feature: 'server actions',
    appliesTo: /server action/i,
    detect: { kind: 'code', pattern: /^\s*['"]use server['"]/m },
    because: 'without "use server" there are no server actions to attack',
  },
];

function lineOf(code: string, index: number) {
  return code.slice(0, index).split('\n').length;
}

function findEvidence(src: SourceIndex, d: Detector, max = 3): string[] {
  const hits: string[] = [];
  for (const { file, code } of src.files) {
    if (hits.length >= max) break;
    const unix = file.split('\\').join('/');
    if (d.kind === 'file') {
      if (d.pattern.test(unix)) hits.push(unix);
    } else if (d.kind === 'code') {
      const re = new RegExp(d.pattern.source, d.pattern.flags.includes('g') ? d.pattern.flags : d.pattern.flags + 'g');
      const m = re.exec(code);
      if (m) hits.push(`${unix}:${lineOf(code, m.index)}`);
    } else {
      for (const re of ROUTE_RES) {
        for (const m of code.matchAll(re)) {
          if (d.risky.test(m[2])) {
            hits.push(`${unix}:${lineOf(code, m.index ?? 0)} '${m[2]}'`);
            if (hits.length >= max) return hits;
          }
        }
      }
    }
  }
  return hits;
}

/** Routes we could read; if there are none, a routes rule can't conclude anything. */
function countRoutes(src: SourceIndex): number {
  let n = 0;
  for (const { code } of src.files) for (const re of ROUTE_RES) n += [...code.matchAll(re)].length;
  return n;
}

/** Feature check for one finding, or undefined when no rule applies. */
export function checkFeature(dep: Dependency, vuln: Vulnerability, src: SourceIndex): FeatureCheck | undefined {
  if (vuln.malicious) return undefined; // malware runs on install, features don't matter

  if (dep.buildTimeOnly) {
    return {
      status: 'unused',
      kind: 'build-time',
      feature: 'production runtime',
      detail:
        dep.buildTool === dep.name
          ? `${dep.name} runs at build time (CSS/bundling), not in production`
          : `only reached through ${dep.buildTool ?? 'a build tool'}, which runs at build time, not in production`,
      evidence: dep.path ?? [],
    };
  }

  const text = `${vuln.summary} ${vuln.id}`;
  const parent = dep.path && dep.path.length > 1 ? dep.path[dep.path.length - 2] : undefined;
  const rule = RULES.find(
    (r) => r.pkg === dep.name && (!r.appliesTo || r.appliesTo.test(text)) && (!r.via || r.via === parent),
  );
  if (!rule) return undefined;
  if (rule.detect.kind === 'routes' && countRoutes(src) === 0) return undefined;

  const evidence = findEvidence(src, rule.detect);
  return evidence.length
    ? { status: 'used', kind: 'feature', feature: rule.feature, detail: `uses ${rule.feature} (${evidence[0]})`, evidence }
    : { status: 'unused', kind: 'feature', feature: rule.feature, detail: `not exploitable here: ${rule.because}`, evidence: [] };
}
