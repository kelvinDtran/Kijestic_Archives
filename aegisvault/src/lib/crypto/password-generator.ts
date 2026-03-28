/**
 * AegisVault — Password Generator
 *
 * Generates cryptographically secure random passwords using the
 * Web Crypto API (crypto.getRandomValues). Never uses Math.random().
 *
 * Algorithm: rejection sampling over uniform random bytes, so each character
 * in the allowed set has exactly equal probability (no modulo bias).
 */

export interface PasswordOptions {
  length:     number;
  uppercase:  boolean;
  lowercase:  boolean;
  digits:     boolean;
  symbols:    boolean;
  // Ambiguous characters (0/O, 1/l/I) — disable for readability
  excludeAmbiguous: boolean;
}

export const DEFAULT_OPTIONS: PasswordOptions = {
  length:           20,
  uppercase:        true,
  lowercase:        true,
  digits:           true,
  symbols:          true,
  excludeAmbiguous: false,
};

const CHAR_SETS = {
  uppercase:  'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lowercase:  'abcdefghijklmnopqrstuvwxyz',
  digits:     '0123456789',
  symbols:    '!@#$%^&*()-_=+[]{}|;:,.<>?',
} as const;

const AMBIGUOUS_CHARS = /[0Ol1Ii]/g;

/**
 * Generate a cryptographically random password.
 * Throws if no character sets are selected or length is out of range.
 */
export function generatePassword(opts: Partial<PasswordOptions> = {}): string {
  const options: PasswordOptions = { ...DEFAULT_OPTIONS, ...opts };

  if (options.length < 4 || options.length > 128) {
    throw new RangeError('Password length must be between 4 and 128');
  }

  // Build the allowed character set
  let charset = '';
  if (options.uppercase) charset += CHAR_SETS.uppercase;
  if (options.lowercase) charset += CHAR_SETS.lowercase;
  if (options.digits)    charset += CHAR_SETS.digits;
  if (options.symbols)   charset += CHAR_SETS.symbols;

  if (options.excludeAmbiguous) {
    charset = charset.replace(AMBIGUOUS_CHARS, '');
  }

  if (charset.length === 0) {
    throw new Error('At least one character set must be selected');
  }

  const password = new Array<string>(options.length);
  const randomBytes = new Uint8Array(options.length * 4); // extra bytes for rejection sampling

  // Rejection-sampling loop — ensures uniform distribution over charset
  let filled = 0;
  while (filled < options.length) {
    crypto.getRandomValues(randomBytes);
    for (let i = 0; i < randomBytes.length && filled < options.length; i++) {
      // Only use byte values that fall within a multiple of charset.length
      // to avoid modulo bias
      const maxUsable = Math.floor(256 / charset.length) * charset.length;
      if (randomBytes[i] < maxUsable) {
        password[filled++] = charset[randomBytes[i] % charset.length];
      }
    }
  }

  return password.join('');
}

/**
 * Estimate password entropy in bits.
 */
export function estimateEntropy(opts: Partial<PasswordOptions> = {}): number {
  const options: PasswordOptions = { ...DEFAULT_OPTIONS, ...opts };
  let charsetSize = 0;
  if (options.uppercase) charsetSize += options.excludeAmbiguous ? 24 : 26;
  if (options.lowercase) charsetSize += options.excludeAmbiguous ? 24 : 26;
  if (options.digits)    charsetSize += options.excludeAmbiguous ? 8  : 10;
  if (options.symbols)   charsetSize += CHAR_SETS.symbols.length;
  if (charsetSize === 0) return 0;
  return Math.floor(options.length * Math.log2(charsetSize));
}

/**
 * Classify entropy as a strength label.
 */
export function strengthLabel(entropy: number): { label: string; color: string } {
  if (entropy < 40) return { label: 'Weak',   color: 'text-aegis-danger' };
  if (entropy < 60) return { label: 'Fair',   color: 'text-aegis-warning' };
  if (entropy < 80) return { label: 'Strong', color: 'text-aegis-success' };
  return              { label: 'Very Strong', color: 'text-aegis-success' };
}
