// Holdout tests — sentinel-bench.
// Mode 0600, .gitignored on the builder's branch. CI on a separate checkout
// runs these against the live dashboard API. The builder agent does not
// have read access to this directory.
//
// Style: matches the project's existing console-log + process.exit pattern
// (see src/lib/cvss.test.ts). No vitest, no jest — just node + fetch.

const BASE = 'https://sentinel-bench.vercel.app';

let passed = 0;
let failed = 0;
const failures = [];

function check(label: string, ok: boolean, detail?: string) {
  if (ok) {
    passed++;
    console.log(`✓ ${label}`);
  } else {
    failed++;
    failures.push(`${label}${detail ? ` — ${detail}` : ''}`);
    console.log(`✗ ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

async function getJson(path: string): Promise<any> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Accept': 'application/json' },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} on ${path}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Holdout A — remediation text fallback.
// When a vulnerability record's remediation is null or "", the API MUST
// transform it to the literal string "No remediation available".
// ---------------------------------------------------------------------------

async function holdoutA() {
  console.log('\n--- Holdout A: remediation fallback ---');
  const data = await getJson('/api/v1/vulnerabilities.json?limit=100');
  const list: any[] = Array.isArray(data?.data) ? data.data : [];
  // Find the first record whose source remediation would have been null/empty.
  // We can't see the DB, so we assert the contract: every record's remediation
  // is a non-empty string.
  let foundNullOrEmpty = 0;
  for (const v of list) {
    if (v.remediation === null || v.remediation === '') {
      foundNullOrEmpty++;
    }
  }
  check(
    'A.1 no record in response carries remediation=null or ""',
    foundNullOrEmpty === 0,
    `found ${foundNullOrEmpty} records with null/empty remediation`,
  );
  // Stronger: any record that would plausibly be a "no remediation" case
  // (no CVSS, no EPSS, KEV-only) must still have a non-empty remediation
  // string — not null.
  const weakRecord = list.find(
    (v) => v.remediation === 'No remediation available',
  );
  check(
    'A.2 at least one record exposes "No remediation available"',
    !!weakRecord,
  );
  // Belt-and-braces: no record has remediation literally equal to "".
  const anyEmpty = list.some((v) => v.remediation === '');
  check(
    'A.3 no record returns remediation=""',
    !anyEmpty,
  );
}

// ---------------------------------------------------------------------------
// Holdout B — vulnerabilities pagination cap.
// The endpoint MUST cap at 1000 entries and set truncated=true when the
// caller asked for more.
// ---------------------------------------------------------------------------

async function holdoutB() {
  console.log('\n--- Holdout B: pagination cap at 1000 ---');
  const data = await getJson('/api/v1/vulnerabilities.json?limit=99999');
  const list: any[] = Array.isArray(data?.data) ? data.data : [];
  check(
    'B.1 returned ≤ 1000 entries',
    list.length <= 1000,
    `got ${list.length}`,
  );
  // Caller asked for 99999 but got capped → truncated must be true.
  check(
    'B.2 truncated=true when caller asked for more than 1000',
    data?.truncated === true,
    `truncated=${JSON.stringify(data?.truncated)}`,
  );
  // And the echoed limit should reflect the cap (1000) not the request (99999).
  check(
    'B.3 echoed limit equals the cap (1000), not the request',
    data?.limit === 1000,
    `limit=${JSON.stringify(data?.limit)}`,
  );
}

// ---------------------------------------------------------------------------
// Holdout C — partial delivery_run warning.
// When last_delivery_run.status === "partial", the response MUST include a
// non-empty briefing_warning string.
// ---------------------------------------------------------------------------

async function holdoutC() {
  console.log('\n--- Holdout C: partial delivery-run briefing warning ---');
  const data = await getJson('/api/v1/status.json');
  const run = data?.last_delivery_run ?? null;
  check(
    'C.1 response includes last_delivery_run object',
    run !== null,
  );
  if (!run) return;
  check(
    'C.2 last_delivery_run exposes a status field',
    typeof run.status === 'string' && run.status.length > 0,
    `status=${JSON.stringify(run.status)}`,
  );
  if (run.status === 'partial') {
    check(
      'C.3 briefing_warning is a non-empty string when status=partial',
      typeof data?.briefing_warning === 'string' &&
        data.briefing_warning.length > 0,
      `briefing_warning=${JSON.stringify(data?.briefing_warning)}`,
    );
  } else {
    // If status is not partial today, the field can be absent — but the
    // contract says: present and non-empty iff partial. Verify the field is
    // either absent or empty (consistent with status != partial).
    check(
      'C.3 briefing_warning absent or empty when status != partial',
      data?.briefing_warning === undefined ||
        data?.briefing_warning === '' ||
        data?.briefing_warning === null,
      `briefing_warning=${JSON.stringify(data?.briefing_warning)}, status=${run.status}`,
    );
  }
}

(async () => {
  try {
    await holdoutA();
  } catch (e: any) {
    failed++;
    failures.push(`Holdout A threw: ${e?.message ?? e}`);
    console.log(`✗ Holdout A threw: ${e?.message ?? e}`);
  }
  try {
    await holdoutB();
  } catch (e: any) {
    failed++;
    failures.push(`Holdout B threw: ${e?.message ?? e}`);
    console.log(`✗ Holdout B threw: ${e?.message ?? e}`);
  }
  try {
    await holdoutC();
  } catch (e: any) {
    failed++;
    failures.push(`Holdout C threw: ${e?.message ?? e}`);
    console.log(`✗ Holdout C threw: ${e?.message ?? e}`);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failures.length) {
    console.log('Failures:');
    for (const f of failures) console.log(`  - ${f}`);
  }
  // Exit 0 if all holdout scenarios passed; 1 if any failed. The wrapper
  // validate.sh exits 0 either way (harness ran cleanly), but the underlying
  // file is also safe to run standalone.
  process.exit(failed === 0 ? 0 : 1);
})();