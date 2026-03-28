'use client';

/**
 * AegisVault — Inactivity Lock Hook
 *
 * Automatically locks the vault after a period of inactivity.
 * Tracks mouse movement, keyboard input, and click events to reset the timer.
 *
 * When the timer expires, the vault is locked (master key cleared from memory).
 * The user must re-enter their master password to continue.
 */

import { useEffect, useRef, useCallback } from 'react';

interface UseVaultLockOptions {
  /** Inactivity timeout in seconds. 0 = disable auto-lock. */
  timeoutSeconds: number;
  /** Called when the inactivity timer fires */
  onLock: () => void;
  /** Whether the vault is currently unlocked */
  isUnlocked: boolean;
}

export function useVaultLock({
  timeoutSeconds,
  onLock,
  isUnlocked,
}: UseVaultLockOptions): {
  resetTimer: () => void;
} {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const resetTimer = useCallback(() => {
    if (!isUnlocked || timeoutSeconds <= 0) return;
    clearTimer();
    timerRef.current = setTimeout(onLock, timeoutSeconds * 1000);
  }, [isUnlocked, timeoutSeconds, onLock, clearTimer]);

  useEffect(() => {
    if (!isUnlocked || timeoutSeconds <= 0) {
      clearTimer();
      return;
    }

    // Activity events that reset the inactivity timer
    const events: string[] = [
      'mousedown',
      'mousemove',
      'keydown',
      'scroll',
      'touchstart',
      'click',
      'focus',
    ];

    const handleActivity = () => resetTimer();

    // Start the timer initially
    resetTimer();

    events.forEach((evt) => {
      window.addEventListener(evt, handleActivity, { passive: true });
    });

    return () => {
      clearTimer();
      events.forEach((evt) => {
        window.removeEventListener(evt, handleActivity);
      });
    };
  }, [isUnlocked, timeoutSeconds, resetTimer, clearTimer]);

  // Lock when tab becomes hidden (aggressive mode — enable if desired)
  useEffect(() => {
    const handleVisibility = () => {
      // Uncomment to lock on tab switch:
      // if (document.hidden && isUnlocked) onLock();
    };
    document.addEventListener('visibilitychange', handleVisibility);
    return () => document.removeEventListener('visibilitychange', handleVisibility);
  }, [isUnlocked, onLock]);

  return { resetTimer };
}
