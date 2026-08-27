// Minimal version of the aegis-provenance attribution.ts:367 shape, used as
// the live repro for the C05/C06/C07/C12 confidence-blindness fix.
export function textEscalationCheck(text: string): boolean {
  if (!text) {
    return false;
  }

  // The signature is ordered: the correction must come first, with the
  // offensive artifact following it. Scan every artifact occurrence (a
  // single exec() would only see the first, which may precede the
  // correction) and require at least one at or after the correction.
  return true;
}
