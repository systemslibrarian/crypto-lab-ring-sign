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
  const actions = [...workflow.matchAll(/^\s*-\s+uses:\s+([^@\s]+)@([^\s]+)/gm)];
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
