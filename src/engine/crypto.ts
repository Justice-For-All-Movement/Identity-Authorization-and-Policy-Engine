// Password hashing (scrypt), sealing of secrets at rest (AES-256-GCM) and opaque token helpers.
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { DomainError, invariant } from '../contracts.ts';

export const sha256 = (value: string): string => createHash('sha256').update(value).digest('hex');
export const randomToken = (bytes = 32): string => randomBytes(bytes).toString('base64url');
export function sameHash(aHex: string, bHex: string): boolean {
  const a = Buffer.from(aHex, 'hex'), b = Buffer.from(bHex, 'hex');
  return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
}

function derive(password: string, salt: Buffer, n: number, r: number, p: number): Promise<Buffer> {
  return new Promise((resolve, reject) => scrypt(password.normalize('NFKC'), salt, 32, { N: n, r, p, maxmem: 256 * 1024 * 1024 }, (error, key) => error ? reject(error) : resolve(key)));
}
/** `scrypt$N$r$p$salt$hash`; parameters travel with the hash so the cost can be raised without breaking old accounts. */
export async function hashPassword(password: string, n = 32768): Promise<string> {
  invariant(Number.isInteger(n) && n >= 1024 && n <= 1048576 && (n & (n - 1)) === 0, 'invalid_config', 'Invalid scrypt cost');
  const salt = randomBytes(16);
  return `scrypt$${n}$8$1$${salt.toString('base64url')}$${(await derive(password, salt, n, 8, 1)).toString('base64url')}`;
}
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, salt, hash] = parts as [string, string, string, string, string, string];
  const want = Buffer.from(hash, 'base64url');
  const got = await derive(password, Buffer.from(salt, 'base64url'), Number(n), Number(r), Number(p));
  return got.length === want.length && timingSafeEqual(got, want);
}

/** Seals small secrets (signing keys, client secrets, PKCE verifiers) under the deployment key-encryption key. */
export class Sealer {
  readonly #key: Buffer;
  constructor(secret: string) {
    invariant(typeof secret === 'string' && secret.length >= 32, 'invalid_config', 'Key encryption key must be at least 32 characters');
    this.#key = Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.from('e01-identity'), Buffer.from('seal-v1'), 32));
  }
  seal(plain: string, context: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(Buffer.from(context));
    const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
    return `v1.${iv.toString('base64url')}.${body.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}`;
  }
  open(sealed: string, context: string): string {
    try {
      const [v, iv, body, tag] = sealed.split('.') as [string, string, string, string];
      invariant(v === 'v1', 'unavailable', 'Unsupported sealed value');
      const decipher = createDecipheriv('aes-256-gcm', this.#key, Buffer.from(iv, 'base64url'));
      decipher.setAAD(Buffer.from(context));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      return Buffer.concat([decipher.update(Buffer.from(body, 'base64url')), decipher.final()]).toString('utf8');
    } catch {
      throw new DomainError('unavailable', 'Stored secret cannot be opened with the configured key encryption key');
    }
  }
}
