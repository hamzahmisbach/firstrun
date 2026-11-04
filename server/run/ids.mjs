// run_id: 128 random bits as 26 base32 characters. It is the only request-derived value that may
// ever reach a container name, a network name, or a host path (section 4), so every route checks
// RUN_ID_RE before any handler runs.
import { randomBytes } from 'node:crypto';

/** Crockford base32 (0-9, A-Z without I, L, O, U): a subset of [0-9A-Z], easy to read aloud. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export const RUN_ID_RE = /^[0-9A-Z]{26}$/;

export function newRunId() {
  const bytes = randomBytes(16);
  let out = '';
  let acc = 0;
  let bits = 0;
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  // 128 = 25 * 5 + 3: the last character carries the remaining 3 bits.
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

export function isRunId(value) {
  return typeof value === 'string' && RUN_ID_RE.test(value);
}
