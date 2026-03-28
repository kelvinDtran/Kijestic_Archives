'use client';

/**
 * PasswordGenerator — Inline password generator popup
 *
 * Appears next to password fields. Generates a cryptographically
 * random password and lets the user apply it directly to the form.
 */

import { useState, useEffect, useRef } from 'react';
import { RefreshCw, Clipboard, Check, Wand2, X } from 'lucide-react';
import {
  generatePassword,
  estimateEntropy,
  strengthLabel,
  DEFAULT_OPTIONS,
  type PasswordOptions,
} from '@/lib/crypto/password-generator';

interface PasswordGeneratorProps {
  onUse: (password: string) => void;
  onClose: () => void;
}

export function PasswordGenerator({ onUse, onClose }: PasswordGeneratorProps) {
  const [options, setOptions] = useState<PasswordOptions>(DEFAULT_OPTIONS);
  const [password, setPassword] = useState('');
  const [copied, setCopied] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  // Generate on mount and whenever options change
  useEffect(() => {
    try {
      setPassword(generatePassword(options));
    } catch {
      setPassword('');
    }
  }, [options]);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [onClose]);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const regenerate = () => {
    try {
      setPassword(generatePassword(options));
    } catch {
      /* invalid options — keep old password */
    }
  };

  const copyPassword = async () => {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const entropy   = estimateEntropy(options);
  const strength  = strengthLabel(entropy);
  const anyChosen = options.uppercase || options.lowercase || options.digits || options.symbols;

  const toggleOption = (key: keyof PasswordOptions, value: boolean) => {
    setOptions((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <div
      ref={containerRef}
      className="absolute z-50 right-0 top-full mt-1 w-80 bg-aegis-surface border border-aegis-border rounded-lg shadow-xl p-4 space-y-4"
    >
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-sm font-medium text-aegis-text">
          <Wand2 className="w-4 h-4 text-aegis-primary" />
          Password Generator
        </div>
        <button onClick={onClose} className="text-aegis-muted hover:text-aegis-text">
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Generated password display */}
      <div className="bg-aegis-elevated rounded-aegis px-3 py-2.5 font-mono text-sm text-aegis-text break-all leading-relaxed min-h-[3rem]">
        {password || <span className="text-aegis-muted italic">Select character types</span>}
      </div>

      {/* Strength */}
      {password && (
        <div className="flex items-center justify-between text-xs">
          <span className="text-aegis-muted">{entropy} bits entropy</span>
          <span className={`font-medium ${strength.color}`}>{strength.label}</span>
        </div>
      )}

      {/* Length slider */}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-xs text-aegis-muted">Length</label>
          <span className="text-xs font-mono text-aegis-text">{options.length}</span>
        </div>
        <input
          type="range"
          min={8}
          max={64}
          value={options.length}
          onChange={(e) => toggleOption('length', Number(e.target.value))}
          className="w-full h-1.5 bg-aegis-border rounded-full appearance-none cursor-pointer accent-aegis-primary"
        />
        <div className="flex justify-between text-xs text-aegis-muted mt-0.5">
          <span>8</span><span>64</span>
        </div>
      </div>

      {/* Character sets */}
      <div className="grid grid-cols-2 gap-1.5">
        {([
          { key: 'uppercase',  label: 'A–Z Uppercase' },
          { key: 'lowercase',  label: 'a–z Lowercase' },
          { key: 'digits',     label: '0–9 Digits' },
          { key: 'symbols',    label: '!@# Symbols' },
        ] as { key: keyof PasswordOptions; label: string }[]).map(({ key, label }) => (
          <label key={key} className="flex items-center gap-2 cursor-pointer text-xs text-aegis-subtle hover:text-aegis-text">
            <input
              type="checkbox"
              checked={options[key] as boolean}
              onChange={(e) => toggleOption(key, e.target.checked)}
              className="rounded border-aegis-border w-3.5 h-3.5"
            />
            {label}
          </label>
        ))}
      </div>

      {/* Exclude ambiguous */}
      <label className="flex items-center gap-2 cursor-pointer text-xs text-aegis-subtle hover:text-aegis-text">
        <input
          type="checkbox"
          checked={options.excludeAmbiguous}
          onChange={(e) => toggleOption('excludeAmbiguous', e.target.checked)}
          className="rounded border-aegis-border w-3.5 h-3.5"
        />
        Exclude ambiguous characters (0/O, 1/l/I)
      </label>

      {/* Actions */}
      <div className="flex gap-2 pt-1">
        <button
          type="button"
          onClick={regenerate}
          disabled={!anyChosen}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-aegis text-xs text-aegis-muted hover:text-aegis-text hover:bg-aegis-elevated transition-colors disabled:opacity-40"
          title="Regenerate"
        >
          <RefreshCw className="w-3.5 h-3.5" /> New
        </button>
        <button
          type="button"
          onClick={copyPassword}
          disabled={!password}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-aegis text-xs text-aegis-muted hover:text-aegis-text hover:bg-aegis-elevated transition-colors disabled:opacity-40"
          title="Copy to clipboard"
        >
          {copied ? <><Check className="w-3.5 h-3.5 text-aegis-success" /> Copied</> : <><Clipboard className="w-3.5 h-3.5" /> Copy</>}
        </button>
        <button
          type="button"
          onClick={() => { onUse(password); onClose(); }}
          disabled={!password}
          className="flex-1 aegis-btn-primary text-xs py-1.5 disabled:opacity-40"
        >
          Use Password
        </button>
      </div>
    </div>
  );
}
