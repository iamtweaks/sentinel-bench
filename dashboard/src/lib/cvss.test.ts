import { parseCvssVector, deriveFromScore, type CvssParseResult } from './cvss';

function assertEq<T>(label: string, got: T, want: T): boolean {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  console.log(ok ? `✓ ${label}` : `✗ ${label}\n   got: ${JSON.stringify(got)}\n   want: ${JSON.stringify(want)}`);
  return ok;
}

let passed = 0, failed = 0;
function check(label: string, ok: boolean) { ok ? passed++ : failed++; }

// Full vector — CVE-style, all 8 metrics
const full = parseCvssVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
check('full vector valid', full.valid === true);
check('AV=Network',       full.attackVector === 'Network');
check('AC=Low',           full.complexity === 'Low');
check('PR=None',          full.authRequired === 'None');
check('UI=None',          full.userInteraction === 'None');
check('S=Unchanged',      full.scope === 'Unchanged');
check('C=H', full.confidentiality === 'High');
check('I=H', full.integrity === 'High');
check('A=H', full.availability === 'High');

// Partial vector — AV only, rest should be null
const partial = parseCvssVector('CVSS:3.0/AV:L');
check('partial valid', partial.valid === true);
check('partial AV=Local', partial.attackVector === 'Local');
check('partial AC null', partial.complexity === null);

// Edge: unknown metric value (e.g. AV:Z) — falls back to null but vector is "valid" because AV key exists
const badVal = parseCvssVector('CVSS:3.1/AV:Z/AC:L');
check('unknown AV value → null', badVal.attackVector === null);
check('bad AV still valid (key exists)', badVal.valid === true);

// Edge: null / empty / garbage
const nul = parseCvssVector(null);
check('null → invalid', nul.valid === false);
check('null all-null', nul.attackVector === null && nul.authRequired === null);

const empty = parseCvssVector('');
check('empty → invalid', empty.valid === false);

const garbage = parseCvssVector('not a vector');
check('garbage → invalid', garbage.valid === false);

// Fallback from numeric score
const fb = deriveFromScore(9.5);
check('deriveFromScore Network',  fb.attackVector === 'Network');
check('deriveFromScore None',     fb.authRequired === 'None');
check('deriveFromScore None UI',  fb.userInteraction === 'None');

const fbLow = deriveFromScore(3.0);
check('deriveFromScore low score → Adjacent', fbLow.attackVector === 'Adjacent');
check('deriveFromScore low score → Low CIA', fbLow.confidentiality === 'Low');

// Case insensitivity
const mixed = parseCvssVector('cvss:3.1/av:n/ac:l');
check('case-insensitive AV', mixed.attackVector === 'Network');
check('case-insensitive AC', mixed.complexity === 'Low');

// Type narrowing: assertEq just verifies JSON round-trip identity of the result shape
assertEq<CvssParseResult>('full result shape', full, {
  attackVector: 'Network', authRequired: 'None', complexity: 'Low',
  userInteraction: 'None', scope: 'Unchanged',
  confidentiality: 'High', integrity: 'High', availability: 'High',
  raw: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', valid: true,
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
