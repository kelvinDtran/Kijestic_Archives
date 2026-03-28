'use client';

/**
 * CryptoWarning — High-risk item warning component
 *
 * Displayed when a vault item is classified as high-risk (crypto seed phrases,
 * private keys, wallet secrets). Adds extra friction and prominent warnings.
 */

import { useState } from 'react';
import { AlertTriangle, Shield, ExternalLink } from 'lucide-react';

interface CryptoWarningProps {
  onAcknowledge: () => void;
  onCancel: () => void;
  action?: 'store' | 'view' | 'copy' | 'export';
}

export function CryptoWarning({ onAcknowledge, onCancel, action = 'store' }: CryptoWarningProps) {
  const [confirmed, setConfirmed] = useState(false);

  const actionMessages = {
    store:  'storing a crypto seed phrase or private key',
    view:   'viewing a high-risk crypto secret',
    copy:   'copying a high-risk crypto secret to clipboard',
    export: 'exporting a high-risk crypto secret',
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="w-full max-w-md bg-aegis-surface border border-aegis-highrisk rounded-aegis-xl p-6 shadow-danger-glow animate-slide-up">
        {/* Header */}
        <div className="flex items-start gap-3 mb-5">
          <div className="w-10 h-10 rounded-full bg-aegis-highrisk-muted flex items-center justify-center shrink-0">
            <AlertTriangle className="w-5 h-5 text-aegis-highrisk" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-aegis-highrisk mb-0.5">
              High-Risk Secret Warning
            </h2>
            <p className="text-sm text-aegis-subtle">
              You are {actionMessages[action]}
            </p>
          </div>
        </div>

        {/* Warning content */}
        <div className="space-y-3 mb-6">
          <div className="bg-aegis-highrisk-muted border border-aegis-highrisk/30 rounded-aegis p-3">
            <p className="text-sm font-semibold text-aegis-highrisk mb-2">
              Seed phrases and private keys require extreme caution:
            </p>
            <ul className="text-sm text-aegis-subtle space-y-1.5">
              <li className="flex items-start gap-2">
                <span className="text-aegis-highrisk mt-0.5">▸</span>
                <span>Anyone with access to your seed phrase has <strong className="text-aegis-text">complete, irrevocable control</strong> over your wallet</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-aegis-highrisk mt-0.5">▸</span>
                <span>Storing secrets in <em>any</em> internet-connected system increases attack surface</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-aegis-highrisk mt-0.5">▸</span>
                <span>Hardware wallets (Ledger, Trezor) are the gold standard for long-term storage</span>
              </li>
              <li className="flex items-start gap-2">
                <span className="text-aegis-highrisk mt-0.5">▸</span>
                <span>Consider offline, air-gapped storage for high-value wallets</span>
              </li>
            </ul>
          </div>

          <div className="flex items-start gap-2 bg-aegis-elevated rounded-aegis px-3 py-2">
            <Shield className="w-4 h-4 text-aegis-primary shrink-0 mt-0.5" />
            <p className="text-xs text-aegis-subtle">
              AegisVault encrypts this with client-side encryption. The server cannot read it.
              However, no internet-connected system is risk-free for seed phrase storage.
            </p>
          </div>
        </div>

        {/* Confirmation checkbox */}
        <label className="flex items-start gap-3 cursor-pointer mb-5">
          <div
            onClick={() => setConfirmed((v) => !v)}
            className={`w-5 h-5 rounded border-2 shrink-0 mt-0.5 flex items-center justify-center transition-colors cursor-pointer ${
              confirmed ? 'bg-aegis-highrisk border-aegis-highrisk' : 'border-aegis-border'
            }`}
          >
            {confirmed && <span className="text-white text-xs font-bold">✓</span>}
          </div>
          <span className="text-sm text-aegis-subtle leading-relaxed">
            I understand the risks and accept full responsibility. I have considered
            offline alternatives for this high-risk secret.
          </span>
        </label>

        {/* Actions */}
        <div className="flex gap-3">
          <button onClick={onCancel} className="aegis-btn-ghost flex-1">
            Cancel
          </button>
          <button
            onClick={onAcknowledge}
            disabled={!confirmed}
            className="flex-1 bg-aegis-highrisk hover:bg-orange-600 text-white font-medium px-4 py-2 rounded-aegis text-sm disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Proceed Anyway
          </button>
        </div>
      </div>
    </div>
  );
}

/** Inline warning badge for vault list items */
export function HighRiskBadge() {
  return (
    <span className="high-risk-badge flex items-center gap-1">
      <AlertTriangle className="w-3 h-3" />
      High Risk
    </span>
  );
}
