import { execFileSync } from 'child_process';
import * as path from 'path';
import { findLockfile, LockfileFormat, parseLockfileText, readLockfile } from '../lockfiles';
import { isBerry, Manifest, ProjectContext } from '../lockfiles/yarn';
import { Dependency } from '../types';

/** The project's dependencies as they were at one point in time. */
export interface LockSnapshot {
  /** day this state starts (YYYY-MM-DD) */
  date: string;
  /** commit sha, or 'working-copy' for uncommitted changes */
  sha: string;
  file: string;
  format: LockfileFormat;
  dependencies: Dependency[];
}

const LOCKFILES: Record<string, LockfileFormat | 'yarn'> = {
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
};

function git(repo: string, args: string[]): string {
  return execFileSync('git', args, { cwd: repo, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
}

function tryGit(repo: string, args: string[]): string | null {
  try {
    return git(repo, args);
  } catch {
    return null;
  }
}

export function isGitRepo(repo: string): boolean {
  return tryGit(repo, ['rev-parse', '--is-inside-work-tree'])?.trim() === 'true';
}

/** package.json files and workspace folders read from a commit instead of the disk. */
function gitContext(repo: string, sha: string): ProjectContext {
  const show = (p: string) => tryGit(repo, ['show', `${sha}:${p}`]);
  const exists = (p: string) => tryGit(repo, ['cat-file', '-e', `${sha}:${p}`]) !== null;
  return {
    readManifest(rel: string): Manifest | null {
      const text = show(path.posix.join(rel === '.' ? '' : rel, 'package.json'));
      try {
        return text ? JSON.parse(text) : null;
      } catch {
        return null;
      }
    },
    expandWorkspaces(patterns: string[]): string[] {
      const dirs = new Set<string>();
      for (const p of patterns) {
        const clean = p.replace(/\/+$/, '');
        if (/\/\*\*?$/.test(clean)) {
          const base = clean.replace(/\/\*\*?$/, '');
          for (const name of (tryGit(repo, ['ls-tree', '--name-only', `${sha}:${base}`]) ?? '').split('\n').filter(Boolean))
            if (exists(`${base}/${name}/package.json`)) dirs.add(`${base}/${name}`);
        } else if (exists(`${clean}/package.json`)) dirs.add(clean);
      }
      return [...dirs];
    },
  };
}

/**
 * Every version of the lockfile in git history (last commit of each day),
 * oldest first, plus uncommitted changes as of `until`.
 */
export async function lockfileHistory(
  repo: string,
  opts: { since?: string; until?: string; maxSnapshots?: number } = {},
): Promise<LockSnapshot[]> {
  const until = opts.until ?? new Date().toISOString().slice(0, 10);
  const commits: { sha: string; date: string; file: string }[] = [];
  if (isGitRepo(repo)) {
    for (const file of Object.keys(LOCKFILES)) {
      const log = tryGit(repo, ['log', '--format=%H %cI', '--', file]) ?? '';
      for (const line of log.split('\n').filter(Boolean)) {
        const [sha, iso] = line.split(' ');
        commits.push({ sha, date: iso.slice(0, 10), file });
      }
    }
  }
  // if one commit has two lockfiles (e.g. package-lock.json and yarn.lock), prefer the one Argus scans today
  const preferred = findLockfile(repo)?.name;
  const rank = (f: string) => (f === preferred ? 1 : 0);
  commits.sort((a, b) => a.date.localeCompare(b.date) || rank(a.file) - rank(b.file));

  // one state per day: the last lockfile commit of that day wins
  const byDay = new Map<string, { sha: string; date: string; file: string }>();
  for (const c of commits) if (c.date <= until) byDay.set(c.date, c);
  let days = [...byDay.values()];
  // keep the state that was in force on `since`, then everything after it
  if (opts.since) {
    const before = days.filter((d) => d.date < opts.since!).at(-1);
    days = [...(before ? [{ ...before, date: opts.since }] : []), ...days.filter((d) => d.date >= opts.since!)];
  }
  if (opts.maxSnapshots && days.length > opts.maxSnapshots) {
    // thin evenly, always keeping the first and the latest
    const step = (days.length - 1) / (opts.maxSnapshots - 1);
    days = Array.from({ length: opts.maxSnapshots }, (_, i) => days[Math.round(i * step)]);
  }

  const out: LockSnapshot[] = [];
  let lastText: string | null = null;
  for (const d of days) {
    const text = tryGit(repo, ['show', `${d.sha}:${d.file}`]);
    if (text === null) continue; // the file was deleted in that commit
    const kind = LOCKFILES[d.file];
    const format: LockfileFormat = kind === 'yarn' ? (isBerry(text.slice(0, 2000)) ? 'yarn-berry' : 'yarn-classic') : kind;
    try {
      const dependencies = parseLockfileText(text, format, gitContext(repo, d.sha));
      out.push({ date: d.date, sha: d.sha, file: d.file, format, dependencies });
      lastText = text;
    } catch {
      /* unparseable old lockfile version (e.g. npm v1): skip that day */
    }
  }

  // uncommitted (or never committed) lockfile on disk
  try {
    const { lockfile, dependencies } = await readLockfile(repo);
    const { readFileSync } = await import('fs');
    if (readFileSync(lockfile.file, 'utf8') !== lastText) {
      if (out.at(-1)?.date === until) out.pop(); // the working copy supersedes today's commit
      out.push({ date: until, sha: 'working-copy', file: lockfile.name, format: lockfile.format, dependencies });
    }
  } catch {
    /* no lockfile on disk */
  }
  return out;
}
