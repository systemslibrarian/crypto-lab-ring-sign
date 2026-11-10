/* Decide whether a Dependabot pull request is a semver-major bump, reading only
 * the pull request's own text. No third-party action enters the merge path, and
 * no API call either: the caller takes the title and body from the triggering
 * event's own payload and passes them in through env, so there is no read that
 * can fail, and the attacker-controlled text never reaches a shell as source.
 *
 * Three answers, and only one of them permits an auto-merge:
 *
 *   'non-major'  every from->to pair parsed, and none of them changed a major
 *   'major'      at least one pair changed a major
 *   'unknown'    nothing parsed, something failed to parse, or there was no body
 *
 * 'unknown' is not 'probably fine'. A grouped pull request that lists no
 * versions, a retitled pull request, a body Dependabot did not write -- all of
 * them land here, and all of them wait for a person. That is the whole point:
 * the failure mode of a version gate is to wave something through, so this one
 * refuses whenever it cannot see the versions for itself.
 *
 * 0.x is treated as the specification says it should be: with a zero major, the
 * minor carries the breaking changes, so 0.4.1 -> 0.5.0 is a major bump.
 */

const PAIR_IN_PROSE = /\bfrom\s+v?(\d[0-9A-Za-z.\-+]*)\s+to\s+v?(\d[0-9A-Za-z.\-+]*)/gi;
// A Dependabot group table row: | [pkg](url) | `1.2.3` | `1.2.4` |
const PAIR_IN_TABLE = /^\s*\|[^|\n]+\|\s*`?v?(\d[0-9A-Za-z.\-+]*)`?\s*\|\s*`?v?(\d[0-9A-Za-z.\-+]*)`?\s*\|/gm;

function parts(version) {
  const core = String(version).split('+')[0].split('-')[0];
  const bits = core.split('.');
  // A bare major is what the github-actions ecosystem writes ("from 5 to 7").
  // It parses: the minor is absent, not unreadable.
  const major = Number(bits[0]);
  const minor = bits.length > 1 ? Number(bits[1]) : 0;
  if (!Number.isInteger(major) || !Number.isInteger(minor)) return null;
  if (major < 0 || minor < 0) return null;
  return { major, minor };
}

export function isMajorChange(from, to) {
  const a = parts(from);
  const b = parts(to);
  if (!a || !b) return null;                 // unparseable: caller must fail closed
  if (a.major !== b.major) return true;
  if (a.major === 0 && a.minor !== b.minor) return true;   // 0.4 -> 0.5 is breaking
  return false;
}

export function pairsFrom(title = '', body = '') {
  const found = [];
  for (const text of [String(title || ''), String(body || '')]) {
    for (const re of [PAIR_IN_PROSE, PAIR_IN_TABLE]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) found.push([m[1], m[2]]);
    }
  }
  return found;
}

export function bumpType({ title, body }) {
  if (body === undefined || body === null || String(body).trim() === '') return 'unknown';
  const found = pairsFrom(title, body);
  if (!found.length) return 'unknown';
  let sawMajor = false;
  for (const [from, to] of found) {
    const major = isMajorChange(from, to);
    if (major === null) return 'unknown';
    if (major) sawMajor = true;
  }
  return sawMajor ? 'major' : 'non-major';
}

if (process.argv[1] && process.argv[1].endsWith('bump-type.mjs')) {
  const verdict = bumpType({ title: process.env.PR_TITLE, body: process.env.PR_BODY });
  process.stdout.write(`bump=${verdict}\n`);
}
