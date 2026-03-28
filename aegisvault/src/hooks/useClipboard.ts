'use client';

/**
 * AegisVault — Secure Clipboard Hook
 *
 * Copies secrets to the clipboard with an automatic clear after a timeout.
 * This mitigates the risk of secrets remaining in the clipboard indefinitely.
 *
 * SECURITY NOTES:
 *   - Clipboard data persists until cleared or overwritten.
 *   - We auto-clear after 30 seconds (configurable).
 *   - The clipboard API requires the page to be focused in some browsers.
 *   - We cannot prevent clipboard managers or OS-level monitoring from
 *     capturing the data — this is a known limitation of web clipboards.
 */

import { useState, useCallback, useRef } from 'react';

const DEFAULT_CLEAR_AFTER_MS = 30_000; // 30 seconds

interface UseClipboardOptions {
  clearAfterMs?: number;
}

interface UseClipboardReturn {
  copied: boolean;
  copyToClipboard: (text: string) => Promise<void>;
  clearClipboard:  () => Promise<void>;
  timeUntilClear:  number;  // seconds remaining until auto-clear
  error: string | null;
}

export function useClipboard({
  clearAfterMs = DEFAULT_CLEAR_AFTER_MS,
}: UseClipboardOptions = {}): UseClipboardReturn {
  const [copied, setCopied] = useState(false);
  const [error, setError]   = useState<string | null>(null);
  const [timeUntilClear, setTimeUntilClear] = useState(0);

  const clearTimerRef    = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef     = useRef<ReturnType<typeof setInterval> | null>(null);
  const copiedValueRef   = useRef<string>('');

  const clearTimers = useCallback(() => {
    if (clearTimerRef.current) {
      clearTimeout(clearTimerRef.current);
      clearTimerRef.current = null;
    }
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
      countdownRef.current = null;
    }
    setTimeUntilClear(0);
  }, []);

  const clearClipboard = useCallback(async () => {
    clearTimers();
    try {
      // Replace clipboard with empty string instead of clearing
      // (navigator.clipboard.writeText('') is more reliable than clear())
      await navigator.clipboard.writeText('');
    } catch {
      // Some browsers don't allow writing empty string — acceptable failure
    }
    copiedValueRef.current = '';
    setCopied(false);
  }, [clearTimers]);

  const copyToClipboard = useCallback(async (text: string) => {
    setError(null);
    clearTimers();

    try {
      await navigator.clipboard.writeText(text);
      copiedValueRef.current = text;
      setCopied(true);

      // Start countdown display
      const endTime = Date.now() + clearAfterMs;
      setTimeUntilClear(Math.ceil(clearAfterMs / 1000));

      countdownRef.current = setInterval(() => {
        const remaining = Math.ceil((endTime - Date.now()) / 1000);
        if (remaining <= 0) {
          clearTimers();
          setTimeUntilClear(0);
        } else {
          setTimeUntilClear(remaining);
        }
      }, 1000);

      // Schedule clipboard clear
      clearTimerRef.current = setTimeout(async () => {
        // Only clear if the clipboard still has our content
        // (avoid clearing if user copied something else)
        try {
          const current = await navigator.clipboard.readText().catch(() => '');
          if (current === copiedValueRef.current) {
            await clearClipboard();
          }
        } catch {
          await clearClipboard();
        }
        setCopied(false);
      }, clearAfterMs);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Failed to copy. Click the field and use Ctrl+C.',
      );
      setCopied(false);
    }
  }, [clearAfterMs, clearTimers, clearClipboard]);

  return { copied, copyToClipboard, clearClipboard, timeUntilClear, error };
}
