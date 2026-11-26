#!/usr/bin/env node
import * as path from 'path';
import { renderHistory } from './core/history/render';
import { replayHistory } from './core/history/replay';
import { scanRepo } from './core/pipeline';
import { renderReport } from './core/report';

const USAGE = `usage:
  argus <path-to-repo> [--internet-facing] [--all] [--json]
      threat assessment of the project as it is now
  argus history <path-to-repo> [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--internet-facing] [--json]
      time machine: replay the lockfile's git history against what was known each day
      (default: the last 365 days)

reads package-lock.json, pnpm-lock.yaml or yarn.lock (classic or berry)`;

const flag = (args: string[], name: string) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

async function main() {
  const args = process.argv.slice(2);
  const history = args[0] === 'history';
  const rest = history ? args.slice(1) : args;
  const valued = new Set(['--since', '--until']);
  const target = rest.find((a, i) => !a.startsWith('--') && !valued.has(rest[i - 1]));
  if (!target) {
    console.error(USAGE);
    process.exit(2);
  }
  const repoPath = path.resolve(target);
  const repo = { name: path.basename(repoPath), internetFacing: rest.includes('--internet-facing') };
  const json = rest.includes('--json');

  if (history) {
    const report = await replayHistory(repoPath, repo, {
      since: flag(rest, '--since'),
      until: flag(rest, '--until'),
      onProgress: json ? undefined : (step, detail) => console.error(`\x1b[2m${step.padEnd(8)} ${detail}\x1b[0m`),
    });
    console.log(json ? JSON.stringify(report, null, 2) : renderHistory(report));
    return;
  }

  const result = await scanRepo(repoPath, repo);
  if (json) console.log(JSON.stringify(result.findings, null, 2));
  else console.log(renderReport(result, { showAll: rest.includes('--all') }));

  // non-zero exit when something critical is found, so it can gate CI
  if (result.findings.some((f) => f.level === 'CRITICAL')) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(2);
});
