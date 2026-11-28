import { existsSync, readFileSync } from 'fs';
import * as path from 'path';

export type Platform = 'linux' | 'windows' | 'macos';

/**
 * Where does this app run? Some vulnerabilities only exist on one OS
 * (e.g. Next.js RCE on Windows-hosted servers).
 *
 * The answer comes from argus.config.json (`"platform": "linux"`) when set,
 * otherwise from deployment files in the repo. Unknown = no claim.
 */
export function detectPlatform(repoPath: string): { platform: Platform; source: string } | null {
  const has = (f: string) => existsSync(path.join(repoPath, f));
  const linuxMarkers: [string, string][] = [
    ['railway.json', 'Railway'],
    ['railway.toml', 'Railway'],
    ['nixpacks.toml', 'Nixpacks'],
    ['vercel.json', 'Vercel'],
    ['netlify.toml', 'Netlify'],
    ['fly.toml', 'Fly.io'],
    ['render.yaml', 'Render'],
    ['app.yaml', 'App Engine'],
    ['Procfile', 'Procfile'],
  ];
  if (has('web.config')) return { platform: 'windows', source: 'web.config (IIS)' };
  if (has('Dockerfile')) {
    const df = readFileSync(path.join(repoPath, 'Dockerfile'), 'utf8');
    if (/^\s*FROM\s+\S*(windows|nanoserver|servercore)/im.test(df)) return { platform: 'windows', source: 'Dockerfile (Windows image)' };
    return { platform: 'linux', source: 'Dockerfile' };
  }
  for (const [f, name] of linuxMarkers) if (has(f)) return { platform: 'linux', source: name };
  return null;
}
