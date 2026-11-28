import { countermeasure, fixLabel } from '../src/core/countermeasure';

const BRACE = ['typeorm', 'glob', 'minimatch', 'brace-expansion'];

describe('countermeasure', () => {
  it('direct dependency: a plain upgrade in the right package manager', () => {
    expect(countermeasure('next', '16.3.3', ['next'], 'npm')!.options[0].code).toBe('npm install next@16.3.3');
    expect(countermeasure('next', '16.3.3', ['next'], 'yarn-classic')!.options[0].code).toBe('yarn add next@16.3.3');
    expect(countermeasure('next', '16.3.3', ['next'], 'pnpm')!.options[0].code).toBe('pnpm add next@16.3.3');
  });

  it('transitive: names the direct dependency and the path', () => {
    const c = countermeasure('brace-expansion', '2.1.7', BRACE, 'yarn-classic')!;
    expect(c.summary).toBe(
      'brace-expansion is not in your package.json: it comes in through typeorm → glob → minimatch. Upgrade typeorm, or pin brace-expansion 2.1.7 under typeorm.',
    );
    expect(c.options[0].code).toMatch(/^yarn upgrade typeorm --latest/);
  });

  it('transitive: the pin is scoped so other versions of the package are left alone', () => {
    expect(countermeasure('brace-expansion', '2.1.7', BRACE, 'yarn-classic')!.options[1].code).toContain('"typeorm/**/brace-expansion": "^2.1.7"');
    expect(countermeasure('brace-expansion', '2.1.7', BRACE, 'npm')!.options[1].code).toContain('"typeorm": {\n    "brace-expansion": "^2.1.7"');
    expect(countermeasure('brace-expansion', '2.1.7', BRACE, 'pnpm')!.options[1].code).toContain('"minimatch>brace-expansion": "^2.1.7"');
    expect(countermeasure('brace-expansion', '2.1.7', BRACE, 'yarn-berry')!.options[0].code).toMatch(/^yarn up typeorm/);
  });

  it('dev-only transitive copy: says it does not ship, shows how to find what pulls it in', () => {
    const c = countermeasure('brace-expansion', '2.1.7', ['brace-expansion'], 'yarn-classic', false)!;
    expect(c.summary).toMatch(/only your dev tooling pulls it in, so it doesn't ship/);
    expect(c.options).toEqual([{ title: 'See what pulls brace-expansion in', code: 'yarn why brace-expansion' }]);
    expect(fixLabel('brace-expansion', '2.1.7', ['brace-expansion'], false)).toBe('dev tooling · 2.1.7 available');
  });

  it('no fix published: no countermeasure', () => expect(countermeasure('x', null, ['x'], 'npm')).toBeNull());

  it('short labels for cards', () => {
    expect(fixLabel('brace-expansion', '2.1.7', BRACE)).toBe('via typeorm · pin 2.1.7');
    expect(fixLabel('next', '16.3.3', ['next'])).toBe('upgrade to 16.3.3');
  });
});
