#!/usr/bin/env node
import * as path from 'path';
import { scanRepo } from './core/pipeline';
import { renderReport } from './core/report';

async function main() {
  const args = process.argv.slice(2);
  const target = args.find((a) => !a.startsWith('--'));
  if (!target) {
    console.error('usage: argus <path-to-repo> [--internet-facing] [--all] [--json]');
    process.exit(2);
  }
  const repoPath = path.resolve(target);
  const result = await scanRepo(repoPath, {
    name: path.basename(repoPath),
    internetFacing: args.includes('--internet-facing'),
  });

  if (args.includes('--json')) console.log(JSON.stringify(result.findings, null, 2));
  else console.log(renderReport(result, { showAll: args.includes('--all') }));

  // non-zero exit when something critical is found, so it can gate CI
  if (result.findings.some((f) => f.level === 'CRITICAL')) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(2);
});
