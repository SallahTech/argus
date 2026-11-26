import { existsSync, readdirSync, readFileSync, statSync } from 'fs';
import { promises as fs } from 'fs';
import * as path from 'path';
import { Dependency } from '../types';
import { parseNpmLockfile } from './npm';
import { parsePnpmLockfile } from './pnpm';
import { isBerry, Manifest, parseYarnBerryLockfile, parseYarnClassicLockfile, ProjectContext } from './yarn';

export type LockfileFormat = 'npm' | 'pnpm' | 'yarn-berry' | 'yarn-classic';

export interface DetectedLockfile {
  file: string; // absolute path
  name: string; // package-lock.json, pnpm-lock.yaml, yarn.lock
  format: LockfileFormat;
}

const CANDIDATES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

/** Find the project's lockfile. If several exist, the most recently modified wins. */
export function findLockfile(repoPath: string): DetectedLockfile | null {
  const found = CANDIDATES.map((name) => path.join(repoPath, name))
    .filter((f) => existsSync(f))
    .map((file) => ({ file, mtime: statSync(file).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);
  if (!found.length) return null;
  const file = found[0].file;
  const name = path.basename(file);
  const format: LockfileFormat =
    name === 'pnpm-lock.yaml'
      ? 'pnpm'
      : name === 'yarn.lock'
        ? isBerry(readFileSync(file, 'utf8').slice(0, 2000))
          ? 'yarn-berry'
          : 'yarn-classic'
        : 'npm';
  return { file, name, format };
}

export function projectContext(repoPath: string): ProjectContext {
  return {
    readManifest(rel: string): Manifest | null {
      try {
        return JSON.parse(readFileSync(path.join(repoPath, rel, 'package.json'), 'utf8'));
      } catch {
        return null;
      }
    },
    // supports the common shapes: "packages/*", "apps/*", "packages/**", "tools/cli"
    expandWorkspaces(patterns: string[]): string[] {
      const dirs = new Set<string>();
      for (const p of patterns) {
        const clean = p.replace(/\/+$/, '');
        if (clean.endsWith('/*') || clean.endsWith('/**')) {
          const base = clean.replace(/\/\*\*?$/, '');
          try {
            for (const d of readdirSync(path.join(repoPath, base), { withFileTypes: true }))
              if (d.isDirectory() && existsSync(path.join(repoPath, base, d.name, 'package.json'))) dirs.add(`${base}/${d.name}`);
          } catch {
            /* missing folder */
          }
        } else if (existsSync(path.join(repoPath, clean, 'package.json'))) dirs.add(clean);
      }
      return [...dirs];
    },
  };
}

export function parseLockfileText(text: string, format: LockfileFormat, ctx: ProjectContext): Dependency[] {
  switch (format) {
    case 'npm':
      return parseNpmLockfile(text);
    case 'pnpm':
      return parsePnpmLockfile(text);
    case 'yarn-berry':
      return parseYarnBerryLockfile(text, ctx);
    case 'yarn-classic':
      return parseYarnClassicLockfile(text, ctx);
  }
}

/** Yarn 1 records no peer dependencies; read them from installed packages if node_modules exists. */
async function fillPeersFromNodeModules(repoPath: string, deps: Dependency[]) {
  if (!existsSync(path.join(repoPath, 'node_modules'))) return;
  await Promise.all(
    deps.map(async (d) => {
      if (d.peers.length) return;
      try {
        const pkg = JSON.parse(await fs.readFile(path.join(repoPath, 'node_modules', d.name, 'package.json'), 'utf8'));
        if (pkg.version === d.version) d.peers = Object.keys(pkg.peerDependencies ?? {});
      } catch {
        /* not installed at top level */
      }
    }),
  );
}

export async function readLockfile(repoPath: string): Promise<{ lockfile: DetectedLockfile; dependencies: Dependency[] }> {
  const lockfile = findLockfile(repoPath);
  if (!lockfile)
    throw new Error(`No lockfile in ${repoPath} (looked for ${CANDIDATES.join(', ')}). Run your package manager's install first.`);
  const text = await fs.readFile(lockfile.file, 'utf8');
  const dependencies = parseLockfileText(text, lockfile.format, projectContext(repoPath));
  if (lockfile.format === 'yarn-classic') await fillPeersFromNodeModules(repoPath, dependencies);
  return { lockfile, dependencies };
}

export { parseNpmLockfile } from './npm';
export { parsePnpmLockfile } from './pnpm';
export { parseYarnBerryLockfile, parseYarnClassicLockfile } from './yarn';
