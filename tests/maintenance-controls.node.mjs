import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const workflow = readFileSync(new URL('.github/workflows/pages.yml', root), 'utf8');
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

function job(name) {
  const match = workflow.match(new RegExp(`\\n  ${name}:\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)`));
  assert.ok(match, `missing ${name} job`);
  return match[0];
}

test('only the deploy job can mint Pages credentials', () => {
  const header = workflow.slice(0, workflow.indexOf('\njobs:'));
  assert.match(header, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(header, /pages: write|id-token: write/);
  assert.doesNotMatch(job('build'), /pages: write|id-token: write/);
  assert.match(job('deploy'), /permissions:\n      pages: write\n      id-token: write\n/);
});

test('every third-party action is pinned to an immutable commit', () => {
  // Both step shapes, because workflows here use both: `- uses: x@sha`, and a
  // step that opens with `- id:` or `- name:` carrying `uses:` on its own line.
  // Anchored on `- uses:` alone this control could not see the deploy step at
  // all -- the one action that publishes the site -- so unpinning
  // actions/deploy-pages back to @v5 left every control green. Measured.
  const actions = [...workflow.matchAll(/^[ \t]*(?:-[ \t]+)?uses:[ \t]+([^@\s]+)@([^\s]+)/gm)];
  // A declared denominator. Every `uses:` line present must be a `uses:` line
  // parsed, so a step in a shape this pattern cannot read fails here instead
  // of passing unseen -- which is how the hole above stayed quiet.
  const present = workflow.match(/^[ \t]*(?:-[ \t]+)?uses:/gm) ?? [];
  assert.equal(actions.length, present.length,
    `${present.length - actions.length} uses: line(s) this control cannot read`);

  assert.ok(actions.length > 0, 'workflow has no actions');
  for (const [, action, reference] of actions) {
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`);
  }
});

test('pull requests run every gate without packaging a deploy artifact', () => {
  const build = job('build');
  assert.match(build, /run: npm ci/);
  assert.match(build, /run: npx tsc --noEmit/);
  assert.match(build, /run: npm test/);
  assert.match(build, /run: npm run build/);
  assert.match(build, /run: npm run test:a11y/);
  assert.match(build, /run: npm run test:claims/);
  assert.match(build, /run: npx playwright install chromium/);
  assert.doesNotMatch(build, /^\s+run: [^\n]*--with-deps/m);
  assert.match(
    build,
    /uses: actions\/upload-pages-artifact@[0-9a-f]{40}[^\n]*\n\s+if: github\.event_name != 'pull_request'/
  );
});

test('post-merge behavior is direct and fail-closed', () => {
  const autoMerge = job('dependabot-auto-merge');
  assert.doesNotMatch(autoMerge, /dependabot\/fetch-metadata/);
  assert.match(autoMerge, /set -eu/);
  assert.match(autoMerge, /exit 1/);
  assert.match(autoMerge, /gh workflow run pages\.yml --repo "\$GITHUB_REPOSITORY" --ref main/);
  assert.doesNotMatch(autoMerge, /gh workflow run[^\n]*(?:\|\||continue-on-error)/);
});

test('a deployment carries and verifies exact source provenance', () => {
  assert.match(job('build'), /public\/deployment\.json/);
  assert.match(job('deploy'), /deployment\.json\?sha=\$\{GITHUB_SHA\}/);
  assert.match(job('deploy'), /p\.source_sha===process\.argv\[2\]/);
  assert.match(job('deploy'), /p\.repository===process\.argv\[3\]/);
  assert.match(job('deploy'), /grep -Fq 'id="app"'/);
});

test('every job has an explicit timeout', () => {
  for (const name of ['build', 'deploy', 'dependabot-auto-merge']) {
    assert.match(job(name), /timeout-minutes: \d+/);
  }
});

test('the production build enforces these maintenance controls', () => {
  assert.equal(packageJson.scripts['test:maintenance'], 'node --test tests/maintenance-controls.node.mjs');
  assert.match(packageJson.scripts.build, /npm run test:maintenance/);
});

test('the auto-merge path reads the bump type from the pull request and fails closed', async () => {
  // This repository keeps no third-party action in the merge path, so the bump
  // type is derived from the pull request's own text by an in-repo script and
  // the merge step is gated on its answer.
  const autoMerge = job('dependabot-auto-merge');
  assert.match(autoMerge, /\.github\/scripts\/bump-type\.mjs/,
    'the job must read the bump type from the in-repo script');
  assert.match(autoMerge, /if:\s*steps\.bump\.outputs\.bump\s*==\s*'non-major'/,
    'the merge step must run only for a non-major bump');
  const { bumpType } = await import('../.github/scripts/bump-type.mjs');
  // Fails closed, which is the property that matters: anything it cannot read
  // is 'unknown', and 'unknown' does not merge.
  assert.equal(bumpType({ title: 'Bump the npm group across 1 directory', body: 'no versions here' }), 'unknown');
  assert.equal(bumpType({ title: 'a retitled pull request', body: 'prose only' }), 'unknown');
  assert.equal(bumpType({ title: 'Bump x from 1.2.3 to 2.0.0', body: undefined }), 'unknown', 'a missing body must not merge');
  assert.equal(bumpType({ title: 'Bump x from one to two', body: 'b' }), 'unknown');
  // And it still answers the two readable cases.
  assert.equal(bumpType({ title: 'Bump vitest from 5.0.5 to 5.1.0', body: 'b' }), 'non-major');
  assert.equal(bumpType({ title: 'Bump next from 15.5.27 to 16.4.2', body: 'b' }), 'major');
  assert.equal(bumpType({ title: 'Bump zod from 0.4.1 to 0.5.0', body: 'b' }), 'major', '0.x minor is breaking');
});
