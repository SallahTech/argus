import { ScanResult } from './pipeline';
import { ThreatLevel } from './types';

const c = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  white: '\x1b[37m',
};

const BADGE: Record<ThreatLevel, string> = {
  CRITICAL: `${c.red}${c.bold}[ CRITICAL ]${c.reset}`,
  RELEVANT: `${c.yellow}${c.bold}[ RELEVANT ]${c.reset}`,
  IRRELEVANT: `${c.dim}[ IRRELEVANT ]${c.reset}`,
};

export function renderReport(r: ScanResult, opts: { showAll?: boolean } = {}): string {
  const direct = r.dependencies.filter((d) => d.direct).length;
  const shown = r.findings.filter((f) => opts.showAll || f.level !== 'IRRELEVANT');
  const suppressed = r.findings.length - shown.length;
  const lines: string[] = [];

  lines.push(`${c.yellow}┌──────────────────────────────────────────────────────────┐${c.reset}`);
  lines.push(`${c.yellow}│${c.reset} ${c.bold}ARGUS // THREAT ASSESSMENT${c.reset}`);
  lines.push(`${c.yellow}│${c.reset} target: ${r.repo.name}${r.repo.internetFacing ? '  (internet-facing)' : ''}`);
  lines.push(`${c.yellow}│${c.reset} watching ${r.dependencies.length} packages (${direct} direct)`);
  lines.push(`${c.yellow}│${c.reset} ${r.findings.length} known vulnerabilities, ${shown.length} need attention`);
  lines.push(`${c.yellow}└──────────────────────────────────────────────────────────┘${c.reset}`);

  if (!shown.length) {
    lines.push(`\n${c.white}No relevant threats. ${suppressed} findings assessed as noise.${c.reset}`);
    return lines.join('\n');
  }

  for (const f of shown) {
    const v = f.vulnerability;
    const id = v.cveIds[0] ?? v.id;
    const fix = f.fixVersion ? `upgrade to ${f.fixVersion}` : v.malicious ? 'REMOVE NOW' : 'no fix yet';
    lines.push('');
    lines.push(`${BADGE[f.level]} ${c.bold}${String(f.score).padStart(3)}${c.reset}  ${f.dependency.name}@${f.dependency.version}  ${c.dim}${id}${c.reset}`);
    if (v.summary) lines.push(`   ${v.summary}`);
    lines.push(`   ${c.dim}why:${c.reset} ${f.reasons.join(' · ')}`);
    lines.push(`   ${c.dim}fix:${c.reset} ${fix}`);
  }
  if (suppressed) lines.push(`\n${c.dim}${suppressed} more findings assessed as IRRELEVANT (use --all to show)${c.reset}`);
  return lines.join('\n');
}
