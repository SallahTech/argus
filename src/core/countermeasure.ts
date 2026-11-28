import { LockfileFormat } from './lockfiles';

export interface Countermeasure {
  /** one line: what to do */
  summary: string;
  options: { title: string; code: string }[];
}

type Pm = 'npm' | 'yarn-classic' | 'yarn-berry' | 'pnpm';
const pmOf = (format: LockfileFormat | string | null | undefined): Pm =>
  format === 'pnpm' ? 'pnpm' : format === 'yarn-berry' ? 'yarn-berry' : format === 'yarn-classic' ? 'yarn-classic' : 'npm';

const why = (pm: Pm, name: string) => (pm === 'npm' ? `npm ls ${name}` : pm === 'pnpm' ? `pnpm why ${name}` : `yarn why ${name}`);
const install = (pm: Pm) => (pm === 'npm' ? 'npm install' : pm === 'pnpm' ? 'pnpm install' : 'yarn install');
const add = (pm: Pm, spec: string) => (pm === 'npm' ? `npm install ${spec}` : pm === 'pnpm' ? `pnpm add ${spec}` : `yarn add ${spec}`);
const upgradeLatest = (pm: Pm, name: string) =>
  pm === 'npm'
    ? `npm install ${name}@latest`
    : pm === 'pnpm'
      ? `pnpm update ${name} --latest`
      : pm === 'yarn-berry'
        ? `yarn up ${name}`
        : `yarn upgrade ${name} --latest`;

/**
 * How to fix one vulnerable package, in the project's own package manager.
 *
 * A transitive package is not in your package.json, so "upgrade to 2.1.7" is
 * not something you can do directly: either upgrade the direct dependency that
 * pulls it in, or pin it *under that dependency only* so other versions of the
 * same package (used elsewhere) are left alone.
 */
export function countermeasure(
  name: string,
  fixVersion: string | null,
  path: string[],
  format: LockfileFormat | string | null | undefined,
  direct = path.length <= 1,
): Countermeasure | null {
  if (!fixVersion) return null;
  const pm = pmOf(format);
  const chain = path.length ? path : [name];

  // not in package.json and not reachable from your code: only dev tooling uses it
  if (!direct && chain.length === 1) {
    return {
      summary: `${name} is not in your package.json and only your dev tooling pulls it in, so it doesn't ship to production. Updating your dev dependencies usually brings in ${fixVersion}.`,
      options: [{ title: `See what pulls ${name} in`, code: why(pm, name) }],
    };
  }

  if (chain.length === 1) {
    return {
      summary: `Upgrade ${name} to ${fixVersion}`,
      options: [{ title: `Upgrade ${name}`, code: add(pm, `${name}@${fixVersion}`) }],
    };
  }

  const root = chain[0];
  const parent = chain[chain.length - 2];
  const via = chain.slice(0, -1).join(' → ');
  const pin = `"^${fixVersion}"`;
  const scoped =
    pm === 'npm'
      ? `// package.json\n"overrides": {\n  "${root}": {\n    "${name}": ${pin}\n  }\n}`
      : pm === 'pnpm'
        ? `// package.json\n"pnpm": {\n  "overrides": {\n    "${parent}>${name}": ${pin}\n  }\n}`
        : `// package.json\n"resolutions": {\n  "${root}/**/${name}": ${pin}\n}`;

  return {
    summary: `${name} is not in your package.json: it comes in through ${via}. Upgrade ${root}, or pin ${name} ${fixVersion} under ${pm === 'pnpm' ? parent : root}.`,
    options: [
      {
        title: `Upgrade ${root} (if a newer release pulls in ${name} ≥ ${fixVersion})`,
        code: `${upgradeLatest(pm, root)}   # check the changelog: this can be a major version\n${why(pm, name)}   # confirm the fixed version is in`,
      },
      {
        title: `Or pin ${name} under ${pm === 'pnpm' ? parent : root} only`,
        code: `${scoped}\n\n${install(pm)} && ${why(pm, name)}`,
      },
    ],
  };
}

/** Short form for cards and the CLI. */
export function fixLabel(name: string, fixVersion: string | null, path: string[], direct = path.length <= 1): string {
  if (!fixVersion) return 'no fix yet';
  if (!direct && path.length <= 1) return `dev tooling · ${fixVersion} available`;
  return path.length > 1 ? `via ${path[0]} · pin ${fixVersion}` : `upgrade to ${fixVersion}`;
}
