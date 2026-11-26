import { groupFindings } from './group';
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
  const groups = groupFindings(r.findings);
  const attention = groups.filter((g) => g.level !== 'IRRELEVANT');
  const shown = opts.showAll ? groups : attention;
  const suppressed = groups.length - shown.length;
  const lines: string[] = [];

  lines.push(`${c.yellow}┌──────────────────────────────────────────────────────────┐${c.reset}`);
  lines.push(`${c.yellow}│${c.reset} ${c.bold}ARGUS // THREAT ASSESSMENT${c.reset}`);
  lines.push(`${c.yellow}│${c.reset} target: ${r.repo.name}${r.repo.internetFacing ? '  (internet-facing)' : ''}`);
  lines.push(`${c.yellow}│${c.reset} watching ${r.dependencies.length} packages (${direct} direct) from ${r.lockfile.name}`);
  lines.push(
    `${c.yellow}│${c.reset} ${r.findings.length} known vulnerabilities in ${groups.length} packages, ${attention.length} need attention`,
  );
  lines.push(`${c.yellow}└──────────────────────────────────────────────────────────┘${c.reset}`);

  if (!shown.length) {
    lines.push(`\n${c.white}No relevant threats. ${groups.length} packages assessed as noise.${c.reset}`);
    return lines.join('\n');
  }

  for (const g of shown) {
    const top = g.findings[0];
    const v = top.vulnerability;
    const count = g.findings.length;
    const fix = v.malicious
      ? 'REMOVE NOW'
      : g.fixVersion
        ? `upgrade to ${g.fixVersion}${count > 1 ? ` (fixes ${count - g.unfixed} of ${count})` : ''}`
        : 'no fix yet';
    lines.push('');
    lines.push(
      `${BADGE[g.level]} ${c.bold}${String(g.score).padStart(3)}${c.reset}  ${g.name}@${g.version}  ${c.dim}${count > 1 ? `${count} vulnerabilities` : (v.cveIds[0] ?? v.id)}${c.reset}`,
    );
    lines.push(`   ${c.dim}path:${c.reset} ${['your code', ...g.path].join(' → ')}`);
    for (const f of g.findings.slice(0, opts.showAll ? count : 3)) {
      const id = f.vulnerability.cveIds[0] ?? f.vulnerability.id;
      lines.push(`   ${c.dim}${String(f.score).padStart(3)}${c.reset} ${id}  ${f.vulnerability.summary}`);
    }
    if (!opts.showAll && count > 3) lines.push(`   ${c.dim}... and ${count - 3} more${c.reset}`);
    lines.push(`   ${c.dim}why:${c.reset} ${top.reasons.join(' · ')}`);
    lines.push(`   ${c.dim}fix:${c.reset} ${fix}`);
  }
  if (suppressed) lines.push(`\n${c.dim}${suppressed} more packages assessed as IRRELEVANT (use --all to show)${c.reset}`);
  return lines.join('\n');
}
