/**
 * Tests for XChaCha20-Poly1305 Encryption
 *
 * Tests verify:
 *   - Correct encrypt/decrypt round-trips
 *   - Ciphertext is different from plaintext
 *   - Ciphertext is non-deterministic (unique nonces)
 *   - Authentication tag verification (tamper detection)
 *   - Key wrapping (vault item DEK wrapping)
 *   - String and JSON helpers
 */

import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptString,
  decryptString,
  encryptJSON,
  decryptJSON,
  generateItemKey,
  constantTimeEqual,
} from '../../lib/crypto/encryption';
import {
  wrapItemKey,
  unwrapItemKey,
  encryptVaultItem,
  decryptVaultItem,
} from '../../lib/crypto/vault-crypto';
import type { VaultItemData } from '../../types/vault';

const makeKey = (fill = 1) => new Uint8Array(32).fill(fill);

describe('XChaCha20-Poly1305 Encryption', () => {

  describe('encrypt() / decrypt() round-trip', () => {
    it('encrypts and decrypts bytes correctly', () => {
      const key       = generateItemKey();
      const plaintext = new TextEncoder().encode('Hello, AegisVault!');
      const ciphertext = encrypt(key, plaintext);
      const decrypted  = decrypt(key, ciphertext);
      expect(decrypted).toEqual(plaintext);
    });

    it('ciphertext is different from plaintext', () => {
      const key  = makeKey();
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const enc  = encrypt(key, data);
      expect(enc).not.toEqual(data);
    });

    it('each encryption produces a different ciphertext (random nonce)', () => {
      const key  = makeKey();
      const data = new TextEncoder().encode('same message');
      const enc1 = encrypt(key, data);
      const enc2 = encrypt(key, data);
      // Different nonces → different ciphertexts (probabilistically certain)
      expect(enc1).not.toEqual(enc2);
    });

    it('decryption with wrong key fails', () => {
      const key1 = makeKey(1);
      const key2 = makeKey(2);
      const enc  = encrypt(key1, new TextEncoder().encode('secret'));
      expect(() => decrypt(key2, enc)).toThrow();
    });

    it('tampered ciphertext fails authentication', () => {
      const key  = makeKey();
      const enc  = encrypt(key, new TextEncoder().encode('secret'));
      // Flip a byte in the ciphertext (after the 24-byte nonce)
      enc[30] ^= 0xFF;
      expect(() => decrypt(key, enc)).toThrow();
    });

    it('tampered nonce fails authentication', () => {
      const key = makeKey();
      const enc = encrypt(key, new TextEncoder().encode('secret'));
      enc[0] ^= 0xFF; // flip a nonce byte
      expect(() => decrypt(key, enc)).toThrow();
    });

    it('rejects key that is not 32 bytes', () => {
      const badKey = new Uint8Array(16);
      expect(() => encrypt(badKey, new Uint8Array([1]))).toThrow(/32 bytes/);
    });

    it('rejects too-short ciphertext', () => {
      const key = makeKey();
      expect(() => decrypt(key, new Uint8Array(10))).toThrow(/too short/i);
    });

    it('handles empty plaintext', () => {
      const key  = makeKey();
      const enc  = encrypt(key, new Uint8Array(0));
      const dec  = decrypt(key, enc);
      expect(dec).toEqual(new Uint8Array(0));
    });

    it('handles large plaintext (1 MB)', () => {
      const key  = makeKey();
      const big  = new Uint8Array(1024 * 1024).fill(42);
      const enc  = encrypt(key, big);
      const dec  = decrypt(key, enc);
      expect(dec).toEqual(big);
    });
  });

  describe('encryptString / decryptString', () => {
    it('round-trips a string', () => {
      const key = makeKey();
      const enc = encryptString(key, 'my super secret password 123!@#');
      const dec = decryptString(key, enc);
      expect(dec).toBe('my super secret password 123!@#');
    });

    it('handles unicode characters', () => {
      const key = makeKey();
      const str = 'こんにちは 🔐 Δέλτα ≡ secret';
      expect(decryptString(key, encryptString(key, str))).toBe(str);
    });
  });

  describe('encryptJSON / decryptJSON', () => {
    it('round-trips a JSON object', () => {
      const key = makeKey();
      const obj = { title: 'My Secret', password: 'p@ssw0rd!', tags: ['work', 'personal'] };
      const enc = encryptJSON(key, obj);
      const dec = decryptJSON(key, enc);
      expect(dec).toEqual(obj);
    });
  });

  describe('generateItemKey()', () => {
    it('generates a 32-byte key', () => {
      expect(generateItemKey().length).toBe(32);
    });

    it('generates unique keys', () => {
      expect(generateItemKey()).not.toEqual(generateItemKey());
    });
  });

  describe('constantTimeEqual()', () => {
    it('returns true for equal arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3]);
      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it('returns false for different arrays', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it('returns false for different lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2]);
      expect(constantTimeEqual(a, b)).toBe(false);
    });
  });
});

describe('Vault Crypto — Key Wrapping & Item Encryption', () => {
  const vaultKey = makeKey(10);

  describe('wrapItemKey() / unwrapItemKey()', () => {
    it('wraps and unwraps a key correctly', () => {
      const itemKey  = generateItemKey();
      const wrapped  = wrapItemKey(vaultKey, itemKey);
      const unwrapped = unwrapItemKey(vaultKey, wrapped);
      expect(unwrapped).toEqual(itemKey);
    });

    it('returns a base64 string', () => {
      const wrapped = wrapItemKey(vaultKey, generateItemKey());
      expect(typeof wrapped).toBe('string');
      // Valid base64
      expect(() => Buffer.from(wrapped, 'base64')).not.toThrow();
    });

    it('unwrap with wrong vault key fails', () => {
      const itemKey  = generateItemKey();
      const wrapped  = wrapItemKey(vaultKey, itemKey);
      const wrongKey = makeKey(99);
      expect(() => unwrapItemKey(wrongKey, wrapped)).toThrow();
    });
  });

  describe('encryptVaultItem() / decryptVaultItem()', () => {
    const testData: VaultItemData = {
      title:       'GitHub Account',
      website:     'github.com',
      username:    'johndoe',
      email:       'john@example.com',
      password:    's3cur3P@ssw0rd!',
      notes:       'Work account',
      tags:        ['work', 'dev'],
      customFields: [{ id: '1', key: 'Recovery Email', value: 'backup@example.com', isSecret: false }],
      riskLevel:   'normal',
    };

    it('encrypts and decrypts vault item data correctly', () => {
      const encrypted = encryptVaultItem(vaultKey, 'PASSWORD', false, false, testData);
      const fakeEncryptedItem = {
        id:              'item-1',
        userId:          'user-1',
        isArchived:      false,
        createdAt:       new Date().toISOString(),
        updatedAt:       new Date().toISOString(),
        ...encrypted,
      };

      const decrypted = decryptVaultItem(vaultKey, fakeEncryptedItem);

      expect(decrypted.data.title).toBe(testData.title);
      expect(decrypted.data.password).toBe(testData.password);
      expect(decrypted.data.username).toBe(testData.username);
      expect(decrypted.data.tags).toEqual(testData.tags);
      expect(decrypted.itemType).toBe('PASSWORD');
    });

    it('encrypted data does not contain plaintext', () => {
      const encrypted = encryptVaultItem(vaultKey, 'PASSWORD', false, false, testData);
      // The encrypted blob should not contain the password in plaintext
      expect(encrypted.encryptedData).not.toContain(testData.password!);
      expect(encrypted.encryptedData).not.toContain(testData.title);
    });

    it('decryption with wrong vault key fails', () => {
      const encrypted = encryptVaultItem(vaultKey, 'PASSWORD', false, false, testData);
      const wrongKey  = makeKey(99);
      const fakeItem  = {
        id: 'x', userId: 'x', isArchived: false,
        createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
        ...encrypted,
      };
      expect(() => decryptVaultItem(wrongKey, fakeItem)).toThrow();
    });

    it('preserves non-sensitive metadata (itemType, flags)', () => {
      const encrypted = encryptVaultItem(vaultKey, 'CRYPTO', true, true, { ...testData, riskLevel: 'high-risk' });
      expect(encrypted.itemType).toBe('CRYPTO');
      expect(encrypted.isFavorite).toBe(true);
      expect(encrypted.isHighRisk).toBe(true);
    });
  });
});
