'use client';

/**
 * SecretField — Secure display of a secret value
 *
 * Features:
 *   - Hidden by default (blurred), revealed on click
 *   - Auto-re-hides after a configurable timeout
 *   - Copy button with clipboard auto-clear countdown
 *   - Never renders the secret in cleartext attributes (no title/placeholder/aria leaks)
 *   - Works with passwords, API keys, seed phrases, etc.
 */

import { useState, useEffect, useRef } from 'react';
import { Eye, EyeOff, Copy, Check, Clock } from 'lucide-react';
import { useClipboard } from '@/hooks/useClipboard';
import { cn } from '@/lib/utils';

interface SecretFieldProps {
  value: string;
  label?: string;
  multiline?: boolean;
  /** Auto-hide the secret after this many seconds (0 = never) */
  autoHideAfterSeconds?: number;
  className?: string;
  /** Whether to show the copy button */
  showCopy?: boolean;
}

export function SecretField({
  value,
  label,
  multiline = false,
  autoHideAfterSeconds = 30,
  className,
  showCopy = true,
}: SecretFieldProps) {
  const [isRevealed, setIsRevealed] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const { copied, copyToClipboard, timeUntilClear } = useClipboard({ clearAfterMs: 30_000 });

  const reveal = () => {
    setIsRevealed(true);

    if (autoHideAfterSeconds > 0) {
      // Clear any existing timers
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);

      setSecondsLeft(autoHideAfterSeconds);

      countdownRef.current = setInterval(() => {
        setSecondsLeft((s) => {
          if (s <= 1) {
            clearInterval(countdownRef.current!);
            return 0;
          }
          return s - 1;
        });
      }, 1000);

      hideTimerRef.current = setTimeout(() => {
        setIsRevealed(false);
        setSecondsLeft(0);
      }, autoHideAfterSeconds * 1000);
    }
  };

  const hide = () => {
    setIsRevealed(false);
    setSecondsLeft(0);
    if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
  };

  useEffect(() => {
    return () => {
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, []);

  const displayValue = isRevealed ? value : '•'.repeat(Math.min(value.length, 24));

  return (
    <div className={cn('space-y-1', className)}>
      {label && (
        <span className="block text-xs font-medium text-aegis-muted uppercase tracking-wide">
          {label}
        </span>
      )}
      <div className="flex items-start gap-2 group">
        <div className="flex-1 min-w-0">
          {multiline ? (
            <pre
              className={cn(
                'secret-value text-sm text-aegis-text bg-aegis-elevated rounded-aegis px-3 py-2 break-all whitespace-pre-wrap font-mono leading-relaxed transition-all duration-200',
                !isRevealed && 'secret-blurred select-none',
              )}
              onClick={!isRevealed ? reveal : undefined}
              aria-label={label ?? 'Secret value'}
            >
              {displayValue}
            </pre>
          ) : (
            <div
              className={cn(
                'secret-value text-sm text-aegis-text bg-aegis-elevated rounded-aegis px-3 py-2 font-mono break-all transition-all duration-200',
                !isRevealed && 'secret-blurred select-none cursor-pointer',
              )}
              onClick={!isRevealed ? reveal : undefined}
              aria-label={label ?? 'Secret value (click to reveal)'}
            >
              {displayValue}
            </div>
          )}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-1 shrink-0 mt-0.5">
          {/* Reveal/hide toggle */}
          <button
            onClick={isRevealed ? hide : reveal}
            className="w-7 h-7 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-subtle hover:bg-aegis-elevated transition-colors"
            title={isRevealed ? 'Hide secret' : 'Reveal secret'}
            aria-label={isRevealed ? 'Hide secret' : 'Reveal secret'}
          >
            {isRevealed ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
          </button>

          {/* Copy button */}
          {showCopy && (
            <button
              onClick={() => copyToClipboard(value)}
              className={cn(
                'w-7 h-7 rounded-aegis flex items-center justify-center transition-colors',
                copied
                  ? 'text-aegis-success bg-aegis-success-muted'
                  : 'text-aegis-muted hover:text-aegis-subtle hover:bg-aegis-elevated',
              )}
              title={copied ? `Clears in ${timeUntilClear}s` : 'Copy to clipboard'}
              aria-label="Copy secret to clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          )}
        </div>
      </div>

      {/* Status messages */}
      <div className="flex items-center gap-3 text-xs text-aegis-muted">
        {isRevealed && autoHideAfterSeconds > 0 && secondsLeft > 0 && (
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            Hides in {secondsLeft}s
          </span>
        )}
        {copied && timeUntilClear > 0 && (
          <span className="flex items-center gap-1 text-aegis-success">
            <Check className="w-3 h-3" />
            Copied — clears in {timeUntilClear}s
          </span>
        )}
      </div>
    </div>
  );
}
