/**
 * Minimal CVSS v3 vector parser.
 *
 * Handles the common subset of metrics asked for by the drawer:
 *   AV (Attack Vector), AC (Attack Complexity), PR (Privileges Required),
 *   UI (User Interaction), S (Scope), C/I/A (Confidentiality/Integrity/Availability).
 *
 * Degrades gracefully: returns null for unknown / missing metrics and a
 * 4-tuple where every field is null when the vector is unparseable.
 */

export type AttackVector = 'Network' | 'Adjacent' | 'Local' | 'Physical';
export type Complexity = 'Low' | 'High';
export type Privileges = 'None' | 'Low' | 'High';
export type UserInteraction = 'None' | 'Required';
export type Scope = 'Unchanged' | 'Changed';
export type Impact = 'None' | 'Low' | 'High';

export interface CvssParseResult {
  attackVector: AttackVector | null;
  authRequired: Privileges | null;
  complexity: Complexity | null;
  userInteraction: UserInteraction | null;
  scope: Scope | null;
  confidentiality: Impact | null;
  integrity: Impact | null;
  availability: Impact | null;
  raw: string | null;
  valid: boolean;
}

const AV_MAP: Record<string, AttackVector> = {
  N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical',
};
const AC_MAP: Record<string, Complexity> = { L: 'Low', H: 'High' };
const PR_MAP: Record<string, Privileges> = { N: 'None', L: 'Low', H: 'High' };
const UI_MAP: Record<string, UserInteraction> = { N: 'None', R: 'Required' };
const S_MAP: Record<string, Scope> = { U: 'Unchanged', C: 'Changed' };
const CIA_MAP: Record<string, Impact> = { N: 'None', L: 'Low', H: 'High' };

export function parseCvssVector(vector: string | null | undefined): CvssParseResult {
  const empty: CvssParseResult = {
    attackVector: null,
    authRequired: null,
    complexity: null,
    userInteraction: null,
    scope: null,
    confidentiality: null,
    integrity: null,
    availability: null,
    raw: vector ?? null,
    valid: false,
  };

  if (!vector || typeof vector !== 'string') return empty;

  const parts = vector.split('/');
  const lookup: Record<string, string> = {};
  for (const part of parts) {
    const [k, v] = part.split(':');
    if (k && v) lookup[k.trim().toUpperCase()] = v.trim().toUpperCase();
  }

  return {
    attackVector: AV_MAP[lookup['AV']] ?? null,
    authRequired: PR_MAP[lookup['PR']] ?? null,
    complexity: AC_MAP[lookup['AC']] ?? null,
    userInteraction: UI_MAP[lookup['UI']] ?? null,
    scope: S_MAP[lookup['S']] ?? null,
    confidentiality: CIA_MAP[lookup['C']] ?? null,
    integrity: CIA_MAP[lookup['I']] ?? null,
    availability: CIA_MAP[lookup['A']] ?? null,
    raw: vector,
    valid: !!lookup['AV'],
  };
}

/**
 * Fallback when cvss_v3_vector is missing — derive rough values from
 * cvss_v3_score so the drawer is never empty. Honest disclaimer: this is a
 * heuristic, not a real CVSS calculation.
 */
export function deriveFromScore(score: number | null | undefined) {
  const s = score ?? 0;
  return {
    attackVector: (s >= 7 ? 'Network' : 'Adjacent') as AttackVector,
    authRequired: (s >= 8.5 ? 'None' : 'Low') as Privileges,
    complexity: 'Low' as Complexity,
    userInteraction: (s >= 9 ? 'None' : 'Required') as UserInteraction,
    scope: null as Scope | null,
    confidentiality: (s >= 7 ? 'High' : 'Low') as Impact,
    integrity: (s >= 7 ? 'High' : 'Low') as Impact,
    availability: (s >= 7 ? 'High' : 'Low') as Impact,
  };
}

// Self-check (ponytail: smallest runnable check; runs when invoked via `npx tsx cvss.test.ts`)
if (typeof process !== 'undefined' && process.argv[1]?.endsWith('cvss.ts')) {
  const samples: Array<[string, CvssParseResult]> = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', {
      attackVector: 'Network', authRequired: 'None', complexity: 'Low',
      userInteraction: 'None', scope: 'Unchanged',
      confidentiality: 'High', integrity: 'High', availability: 'High',
      raw: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', valid: true,
    }],
  ];
  for (const [vec, expected] of samples) {
    const got = parseCvssVector(vec);
    const ok = JSON.stringify(got) === JSON.stringify(expected);
    console.log(ok ? 'OK' : 'FAIL', vec);
    if (!ok) console.log('  got:', JSON.stringify(got));
  }
  // Graceful degradation
  console.log(parseCvssVector(null).valid === false ? 'OK null' : 'FAIL null');
  console.log(parseCvssVector('garbage').valid === false ? 'OK garbage' : 'FAIL garbage');
  console.log(parseCvssVector('CVSS:3.0/AV:N/AC:L').valid === true ? 'OK partial' : 'FAIL partial');
}
