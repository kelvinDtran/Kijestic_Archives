'use client';

/**
 * AegisVault — Vault Context
 *
 * Manages the vault's lock/unlock state and holds the master key in memory.
 *
 * SECURITY CRITICAL:
 *   - The vault key (VEK) is stored ONLY in React state (JavaScript heap).
 *   - It is NEVER written to localStorage, sessionStorage, or IndexedDB.
 *   - It is NEVER sent to the server.
 *   - It is cleared immediately on:
 *       • Explicit vault lock
 *       • User logout
 *       • Inactivity timeout (see useVaultLock hook)
 *       • Browser/tab close (React state is volatile)
 *
 * LIMITATION:
 *   JavaScript does not have memory encryption or secure memory zones.
 *   The VEK exists in plaintext in the JS heap while the vault is unlocked.
 *   This is an accepted limitation of browser-based cryptography.
 *   The inactivity lock minimizes the window of exposure.
 */

import React, {
  createContext,
  useContext,
  useState,
  useCallback,
  useRef,
  useEffect,
  useMemo,
} from 'react';
import { deriveMasterKey, deriveVaultKey, zeroKey } from '@/lib/crypto/kdf';
import type { KdfParams } from '@/types/vault';

// ── Types ──────────────────────────────────────────────────────────────────────

export interface VaultContextValue {
  // Lock state
  isLocked:     boolean;
  isUnlocking:  boolean;
  unlockError:  string | null;

  // Unlock the vault with master password
  unlock: (masterPassword: string) => Promise<void>;

  // Lock the vault (clears key from memory)
  lock:   () => void;

  // Get the current vault key — throws if vault is locked
  // DO NOT store the returned key anywhere persistent
  getVaultKey: () => Uint8Array;

  // Last unlock timestamp (for display purposes)
  lastUnlockedAt: Date | null;
}

// ── Context ────────────────────────────────────────────────────────────────────

const VaultContext = createContext<VaultContextValue | null>(null);

// ── Provider ───────────────────────────────────────────────────────────────────

interface VaultProviderProps {
  children: React.ReactNode;
  kdfParams: KdfParams;
  onLock?: () => void;
}

export function VaultProvider({ children, kdfParams, onLock }: VaultProviderProps) {
  const [isLocked, setIsLocked] = useState(true);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [lastUnlockedAt, setLastUnlockedAt] = useState<Date | null>(null);

  // The vault key is stored in a ref, not in state.
  // Using a ref means:
  //   1. React doesn't re-render when the key changes (security: no unnecessary re-renders)
  //   2. The key doesn't get captured in closures unnecessarily
  const vaultKeyRef = useRef<Uint8Array | null>(null);

  /**
   * Unlock the vault by deriving the master key from the master password.
   * Fetches KDF params from the server (already provided via props here).
   */
  const unlock = useCallback(async (masterPassword: string) => {
    if (!masterPassword.trim()) {
      setUnlockError('Master password is required');
      return;
    }

    setIsUnlocking(true);
    setUnlockError(null);

    try {
      // Derive master key via Argon2id (expensive — shows loading for ~0.5-2s)
      const masterKey = await deriveMasterKey(masterPassword, kdfParams);

      // Derive vault encryption key (VEK) via HKDF
      const vaultKey = deriveVaultKey(masterKey);

      // Zero out the master key — we only need the VEK going forward
      zeroKey(masterKey);

      // Store VEK in ref (not state — avoids React reconciliation touching the key)
      vaultKeyRef.current = vaultKey;

      setIsLocked(false);
      setLastUnlockedAt(new Date());
    } catch (err) {
      setUnlockError(
        err instanceof Error ? err.message : 'Failed to unlock vault. Check your master password.',
      );
    } finally {
      setIsUnlocking(false);
    }
  }, [kdfParams]);

  /**
   * Lock the vault — clears the key from memory immediately.
   */
  const lock = useCallback(() => {
    if (vaultKeyRef.current) {
      // Best-effort memory zeroing
      zeroKey(vaultKeyRef.current);
      vaultKeyRef.current = null;
    }
    setIsLocked(true);
    setUnlockError(null);
    onLock?.();
  }, [onLock]);

  /**
   * Get the current vault key.
   * Only call this when you need to perform a crypto operation.
   * Do NOT store the returned reference in component state or closures.
   */
  const getVaultKey = useCallback((): Uint8Array => {
    if (isLocked || !vaultKeyRef.current) {
      throw new Error('Vault is locked. Unlock it before accessing secrets.');
    }
    return vaultKeyRef.current;
  }, [isLocked]);

  // ── Cleanup on unmount ───────────────────────────────────────────────────────
  useEffect(() => {
    return () => {
      if (vaultKeyRef.current) {
        zeroKey(vaultKeyRef.current);
        vaultKeyRef.current = null;
      }
    };
  }, []);

  // ── Visibility change: lock on tab hide (optional, uncomment to enable) ──────
  // This is aggressive but maximizes security:
  // useEffect(() => {
  //   const handleVisibilityChange = () => {
  //     if (document.hidden) lock();
  //   };
  //   document.addEventListener('visibilitychange', handleVisibilityChange);
  //   return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  // }, [lock]);

  const value = useMemo<VaultContextValue>(
    () => ({ isLocked, isUnlocking, unlockError, unlock, lock, getVaultKey, lastUnlockedAt }),
    [isLocked, isUnlocking, unlockError, unlock, lock, getVaultKey, lastUnlockedAt],
  );

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

// ── Hook ───────────────────────────────────────────────────────────────────────

export function useVault(): VaultContextValue {
  const ctx = useContext(VaultContext);
  if (!ctx) {
    throw new Error('useVault must be used inside <VaultProvider>');
  }
  return ctx;
}

export default VaultContext;
