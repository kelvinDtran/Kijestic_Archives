/**
 * Tests for JWT token management
 */

import { describe, it, expect } from 'vitest';
import { generateRefreshToken, hashToken } from '../../lib/auth/jwt';

describe('Auth — JWT & Token Utilities', () => {

  describe('generateRefreshToken()', () => {
    it('generates token and hash', () => {
      const { token, hash } = generateRefreshToken();
      expect(typeof token).toBe('string');
      expect(typeof hash).toBe('string');
      expect(token.length).toBeGreaterThan(32);
      expect(hash.length).toBe(64); // SHA-256 hex
    });

    it('each call generates a unique token', () => {
      const t1 = generateRefreshToken();
      const t2 = generateRefreshToken();
      expect(t1.token).not.toBe(t2.token);
      expect(t1.hash).not.toBe(t2.hash);
    });

    it('token and hash are consistent', () => {
      const { token, hash } = generateRefreshToken();
      expect(hashToken(token)).toBe(hash);
    });
  });

  describe('hashToken()', () => {
    it('produces a consistent SHA-256 hash', () => {
      const token = 'test-token-value';
      const h1 = hashToken(token);
      const h2 = hashToken(token);
      expect(h1).toBe(h2);
      expect(h1.length).toBe(64);
    });

    it('different tokens produce different hashes', () => {
      expect(hashToken('token-a')).not.toBe(hashToken('token-b'));
    });
  });
});
