'use client';

/**
 * Vault Unlock Modal
 *
 * Shown over the entire vault UI when the vault is locked.
 * User must enter their master password to unlock the vault (derive the VEK).
 * The master password is NEVER sent to the server — it stays in the browser.
 */

import { useState, useRef, useEffect } from 'react';
import { Shield, Eye, EyeOff, Loader2, Lock } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';

export function VaultUnlockModal() {
  const { unlock, isUnlocking, unlockError, lastUnlockedAt } = useVault();
  const [masterPw, setMasterPw] = useState('');
  const [showPw, setShowPw]     = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!masterPw.trim()) return;
    try {
      await unlock(masterPw);
      // If unlock succeeded the modal will unmount (isLocked → false),
      // but clear the field defensively in case the parent keeps it mounted.
      setMasterPw('');
    } catch {
      // unlock() threw — error is displayed via unlockError from context.
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-aegis-bg/95 backdrop-blur-sm">
      <div className="w-full max-w-sm mx-4">
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-full bg-aegis-primary-muted flex items-center justify-center mx-auto mb-4">
            <Lock className="w-8 h-8 text-aegis-primary" />
          </div>
          <h2 className="text-xl font-semibold text-aegis-text mb-1">Vault Locked</h2>
          <p className="text-sm text-aegis-muted">
            Enter your master password to decrypt your vault
          </p>
          {lastUnlockedAt && (
            <p className="text-xs text-aegis-muted mt-1">
              Last unlocked: {lastUnlockedAt.toLocaleTimeString()}
            </p>
          )}
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {unlockError && (
            <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2">
              {unlockError}
            </div>
          )}

          <div className="relative">
            <input
              ref={inputRef}
              type={showPw ? 'text' : 'password'}
              value={masterPw}
              onChange={(e) => setMasterPw(e.target.value)}
              className="aegis-input pr-10 text-center font-mono text-lg tracking-wider"
              placeholder="Master password"
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              disabled={isUnlocking}
            />
            <button
              type="button"
              onClick={() => setShowPw((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-aegis-subtle"
              disabled={isUnlocking}
            >
              {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          <button type="submit" disabled={isUnlocking || !masterPw} className="aegis-btn-primary w-full">
            {isUnlocking ? (
              <span className="flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Deriving key… (this takes a moment)</span>
              </span>
            ) : (
              <span className="flex items-center justify-center gap-2">
                <Shield className="w-4 h-4" />
                Unlock Vault
              </span>
            )}
          </button>
        </form>

        <p className="text-xs text-aegis-muted text-center mt-4 leading-relaxed">
          Your master password is processed locally on your device.
          It is never sent to the server.
        </p>
      </div>
    </div>
  );
}
