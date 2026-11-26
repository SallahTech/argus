import { HistoryFinding, HistoryReport } from './replay';

const c = { reset: '\x1b[0m', dim: '\x1b[2m', bold: '\x1b[1m', red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m' };
const id = (t: HistoryFinding) => t.cveId ?? t.vulnId;
const pkg = (t: HistoryFinding) => `${t.name}@${t.version}`;

export function renderHistory(r: HistoryReport): string {
  const s = r.summary;
  const L: string[] = [];
  L.push(`${c.yellow}┌──────────────────────────────────────────────────────────┐${c.reset}`);
  L.push(`${c.yellow}│${c.reset} ${c.bold}ARGUS // TIME MACHINE${c.reset}  ${r.repo.name}  ${r.from} → ${r.to}`);
  L.push(`${c.yellow}│${c.reset} ${r.snapshots.length} lockfile versions replayed against what was known each day`);
  L.push(`${c.yellow}│${c.reset} ${s.affected} vulnerabilities touched installed versions · ${s.everRelevant} reached RELEVANT`);
  L.push(`${c.yellow}│${c.reset} ${s.exploited} later confirmed exploited (CISA KEV)`);
  L.push(`${c.yellow}└──────────────────────────────────────────────────────────┘${c.reset}`);

  const kev = r.findings.filter((t) => t.kevDate && t.firstRelevant).sort((a, b) => (b.leadDays ?? -1e9) - (a.leadDays ?? -1e9));
  L.push(`\n${c.bold}LEAD TIME${c.reset} ${c.dim}flagged by Argus vs. confirmed exploited by CISA${c.reset}`);
  if (!kev.length) L.push(`  ${c.dim}None of the vulnerabilities in this history were added to CISA KEV.${c.reset}`);
  for (const t of kev) {
    const lead =
      t.leadDays === null
        ? `${c.dim}installed after KEV listing${c.reset}`
        : t.leadDays > 0
          ? `${c.green}${c.bold}+${t.leadDays} days earlier${c.reset}`
          : t.leadDays === 0
            ? 'same day'
            : `${c.dim}${-t.leadDays} days after KEV${c.reset}`;
    L.push(`  ${id(t).padEnd(18)} ${pkg(t).padEnd(28)} RELEVANT ${t.firstRelevant} → KEV ${t.kevDate}   ${lead}`);
  }
  if (s.medianLeadDays !== null) L.push(`  ${c.bold}median: flagged ${s.medianLeadDays} days before CISA confirmed exploitation${c.reset}`);

  const fixed = r.findings.filter((t) => t.firstRelevant && t.removedOn).sort((a, b) => b.daysOpen! - a.daysOpen!);
  L.push(`\n${c.bold}TIME TO FIX${c.reset} ${c.dim}from RELEVANT to upgraded${c.reset}`);
  if (!fixed.length) L.push(`  ${c.dim}No relevant finding was fixed in this period.${c.reset}`);
  for (const t of fixed.slice(0, 15)) L.push(`  ${pkg(t).padEnd(28)} ${id(t).padEnd(18)} ${t.firstRelevant} → ${t.removedOn}   ${t.daysOpen} days`);
  if (s.medianDaysToFix !== null) L.push(`  ${c.bold}median: ${s.medianDaysToFix} days${c.reset}`);

  const open = r.findings.filter((t) => t.firstRelevant && !t.removedOn).sort((a, b) => b.daysOpen! - a.daysOpen!);
  L.push(`\n${c.bold}STILL OPEN${c.reset} ${c.dim}relevant and still installed${c.reset}`);
  if (!open.length) L.push(`  ${c.dim}Nothing. Clean.${c.reset}`);
  for (const t of open.slice(0, 15)) {
    const lvl = t.maxScore >= 70 ? c.red : c.yellow;
    L.push(`  ${lvl}${String(t.maxScore).padStart(3)}${c.reset} ${pkg(t).padEnd(28)} ${id(t).padEnd(18)} open ${t.daysOpen} days (since ${t.firstRelevant})`);
  }
  return L.join('\n');
}
