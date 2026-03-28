/**
 * Tests for KDF (Key Derivation Functions)
 *
 * These tests verify the cryptographic correctness of:
 *   - Argon2id master key derivation
 *   - HKDF vault key derivation
 *   - Salt generation
 *   - Parameter validation
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  generateKdfSalt,
  deriveMasterKey,
  deriveVaultKey,
  zeroKey,
  KDF_VERSION,
} from '../../lib/crypto/kdf';

describe('KDF — Key Derivation', () => {

  describe('generateKdfSalt()', () => {
    it('generates a salt with correct structure', () => {
      const salt = generateKdfSalt();
      expect(salt.version).toBe(KDF_VERSION);
      expect(typeof salt.salt).toBe('string');
      expect(salt.salt).toMatch(/^[0-9a-f]{64}$/); // 32 bytes = 64 hex chars
    });

    it('generates unique salts', () => {
      const salt1 = generateKdfSalt();
      const salt2 = generateKdfSalt();
      expect(salt1.salt).not.toBe(salt2.salt);
    });

    it('includes KDF parameters', () => {
      const salt = generateKdfSalt();
      expect(salt.memory).toBeGreaterThanOrEqual(16384);
      expect(salt.iterations).toBeGreaterThanOrEqual(1);
      expect(salt.parallelism).toBeGreaterThanOrEqual(1);
    });
  });

  describe('deriveMasterKey()', () => {
    // Use VERY low params for testing speed — do not use these in production
    const testSalt = {
      version:     KDF_VERSION,
      salt:        'a'.repeat(64),  // 32 bytes hex
      memory:      1024,   // 1 MB — minimal for tests
      iterations:  1,
      parallelism: 1,
    };

    it('derives a 32-byte key', async () => {
      const key = await deriveMasterKey('test-password', testSalt);
      expect(key).toBeInstanceOf(Uint8Array);
      expect(key.length).toBe(32);
    });

    it('is deterministic — same password + salt = same key', async () => {
      const key1 = await deriveMasterKey('my-master-password', testSalt);
      const key2 = await deriveMasterKey('my-master-password', testSalt);
      expect(key1).toEqual(key2);
    });

    it('different passwords produce different keys', async () => {
      const key1 = await deriveMasterKey('password-one', testSalt);
      const key2 = await deriveMasterKey('password-two', testSalt);
      expect(key1).not.toEqual(key2);
    });

    it('different salts produce different keys', async () => {
      const salt2 = { ...testSalt, salt: 'b'.repeat(64) };
      const key1  = await deriveMasterKey('password', testSalt);
      const key2  = await deriveMasterKey('password', salt2);
      expect(key1).not.toEqual(key2);
    });

    it('rejects empty password', async () => {
      await expect(deriveMasterKey('', testSalt)).rejects.toThrow();
    });

    it('rejects wrong salt length', async () => {
      const badSalt = { ...testSalt, salt: 'abc' }; // too short
      await expect(deriveMasterKey('password', badSalt)).rejects.toThrow();
    });

    it('rejects unsupported KDF version', async () => {
      const badSalt = { ...testSalt, version: 99 };
      await expect(deriveMasterKey('password', badSalt)).rejects.toThrow(/version/i);
    });
  });

  describe('deriveVaultKey()', () => {
    it('derives a 32-byte vault key from master key', () => {
      const masterKey = new Uint8Array(32).fill(42);
      const vaultKey  = deriveVaultKey(masterKey);
      expect(vaultKey).toBeInstanceOf(Uint8Array);
      expect(vaultKey.length).toBe(32);
    });

    it('is deterministic', () => {
      const masterKey = new Uint8Array(32).fill(42);
      const vk1 = deriveVaultKey(masterKey);
      const vk2 = deriveVaultKey(masterKey);
      expect(vk1).toEqual(vk2);
    });

    it('different master keys produce different vault keys', () => {
      const mk1 = new Uint8Array(32).fill(1);
      const mk2 = new Uint8Array(32).fill(2);
      expect(deriveVaultKey(mk1)).not.toEqual(deriveVaultKey(mk2));
    });

    it('vault key is different from master key (domain separation)', () => {
      const masterKey = new Uint8Array(32).fill(42);
      const vaultKey  = deriveVaultKey(masterKey);
      expect(masterKey).not.toEqual(vaultKey);
    });

    it('rejects wrong-length master key', () => {
      const badKey = new Uint8Array(16); // wrong size
      expect(() => deriveVaultKey(badKey)).toThrow();
    });
  });

  describe('zeroKey()', () => {
    it('overwrites key bytes with zeros', () => {
      const key = new Uint8Array([1, 2, 3, 4, 5]);
      zeroKey(key);
      expect(Array.from(key)).toEqual([0, 0, 0, 0, 0]);
    });
  });

  describe('Key hierarchy integration', () => {
    it('full derivation: password → master key → vault key', async () => {
      const testSalt = {
        version:     KDF_VERSION,
        salt:        'c'.repeat(64),
        memory:      1024,
        iterations:  1,
        parallelism: 1,
      };

      const masterKey = await deriveMasterKey('integration-test-password', testSalt);
      const vaultKey  = deriveVaultKey(masterKey);

      expect(masterKey.length).toBe(32);
      expect(vaultKey.length).toBe(32);
      expect(masterKey).not.toEqual(vaultKey);

      // Deterministic: same inputs → same outputs
      const masterKey2 = await deriveMasterKey('integration-test-password', testSalt);
      const vaultKey2  = deriveVaultKey(masterKey2);

      expect(masterKey).toEqual(masterKey2);
      expect(vaultKey).toEqual(vaultKey2);
    });
  });
});
