// Time-based one-time passwords (RFC 6238 over RFC 4226 HOTP: HMAC-SHA1, 30-second steps, 6 digits), base32 secrets and
// single-use recovery codes. Pure functions; persistence and authorization live in the engine.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export const STEP_SECONDS = 30;
export const DIGITS = 6;

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) { value = (value << 8) | b; bits += 8; while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
export function base32Decode(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0, value = 0; const out: number[] = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i === -1) throw new Error('invalid base32');
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export function newSecret(): string { return base32Encode(randomBytes(20)); }

export function hotp(secret: Buffer, counter: number): string {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = (mac[mac.length - 1] as number) & 15;
  const bin = (((mac[offset] as number) & 0x7f) << 24) | ((mac[offset + 1] as number) << 16) | ((mac[offset + 2] as number) << 8) | (mac[offset + 3] as number);
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0');
}
export const stepAt = (at: Date): number => Math.floor(at.getTime() / 1000 / STEP_SECONDS);
export function totp(secretBase32: string, at: Date): string { return hotp(base32Decode(secretBase32), stepAt(at)); }

/**
 * Returns the matched time step when `code` is valid within ±1 step of `at` and later than `lastStep` (a code is usable
 * once), or null.
 */
export function verifyTotp(secretBase32: string, code: string, at: Date, lastStep: number): number | null {
  if (!/^\d{6}$/.test(code)) return null;
  const key = base32Decode(secretBase32), now = stepAt(at);
  let matched: number | null = null;
  for (const step of [now - 1, now, now + 1]) {
    const expected = Buffer.from(hotp(key, step)), given = Buffer.from(code);
    if (timingSafeEqual(expected, given) && step > lastStep && matched === null) matched = step;
  }
  return matched;
}

export function otpauthUri(issuer: string, account: string, secret: string): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}

/** Ten recovery codes like `k7qm-2xpa-9c4d`; only their hashes are stored. */
export function newRecoveryCodes(count = 10): string[] {
  return Array.from({ length: count }, () => {
    const raw = base32Encode(randomBytes(8)).toLowerCase().slice(0, 12);
    return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
  });
}
export const recoveryHash = (code: string): string => createHash('sha256').update(`e01-recovery:${code.trim().toLowerCase()}`).digest('hex');
