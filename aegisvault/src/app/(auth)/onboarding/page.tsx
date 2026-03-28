'use client';

/**
 * Onboarding: Set up the vault master password.
 * This is the CRITICAL security onboarding step.
 * The master password is used for Argon2id key derivation.
 * It is NEVER sent to the server.
 */

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Shield, AlertTriangle, Eye, EyeOff, CheckCircle2 } from 'lucide-react';
import { validateMasterPasswordStrength } from '@/lib/auth/password';

const STEPS = ['understand', 'setup', 'confirm', 'done'] as const;
type Step = typeof STEPS[number];

export default function OnboardingPage() {
  const router = useRouter();
  const [step, setStep]           = useState<Step>('understand');
  const [masterPw, setMasterPw]   = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [showPw, setShowPw]       = useState(false);
  const [understood, setUnderstood] = useState({ neverSent: false, noRecovery: false, different: false });

  const strength = validateMasterPasswordStrength(masterPw);
  const allUnderstood = Object.values(understood).every(Boolean);

  const handleContinueFromUnderstand = () => {
    if (allUnderstood) setStep('setup');
  };

  const handleSetupContinue = () => {
    if (masterPw !== confirmPw) return;
    if (!strength.valid) return;
    setStep('confirm');
  };

  const handleFinish = () => {
    // Master password is intentionally NOT stored anywhere
    // The user will be prompted to enter it when unlocking the vault
    router.push('/dashboard');
  };

  return (
    <div className="aegis-card animate-fade-in max-w-lg">

      {/* Step: Understand */}
      {step === 'understand' && (
        <>
          <div className="flex items-center gap-3 mb-6">
            <div className="w-10 h-10 rounded-full bg-aegis-primary-muted flex items-center justify-center">
              <Shield className="w-5 h-5 text-aegis-primary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold text-aegis-text">How AegisVault Works</h1>
              <p className="text-sm text-aegis-muted">Read carefully before setting up your vault</p>
            </div>
          </div>

          <div className="space-y-4 mb-6">
            <div className="bg-aegis-elevated rounded-aegis-lg p-4 space-y-3">
              <h2 className="text-sm font-semibold text-aegis-text">Two separate passwords</h2>
              <div className="space-y-2">
                <div className="flex items-start gap-3">
                  <div className="w-5 h-5 rounded-full bg-aegis-border flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-xs text-aegis-muted">1</span>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-aegis-text">Account Password</p>
                    <p className="text-xs text-aegis-muted">Identifies you to the server. Used for login only. Can be reset if forgotten.</p>
                  </div>
                </div>
                <div className="flex items-start gap-3">
                  <div className="w-5 h-5 rounded-full bg-aegis-primary-muted flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-xs text-aegis-primary">2</span>
                  </div>
                  <div>
                    <p className="text-sm font-medium text-aegis-text">Vault Master Password</p>
                    <p className="text-xs text-aegis-muted">Encrypts all your secrets. <strong className="text-aegis-warning">Never sent to the server.</strong> Cannot be reset — if lost, vault data is permanently unrecoverable.</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-aegis-danger-muted border border-aegis-danger rounded-aegis-lg p-4">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-aegis-danger shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-aegis-danger mb-1">Zero-knowledge encryption</p>
                  <p className="text-xs text-aegis-subtle leading-relaxed">
                    Your secrets are encrypted on your device before being stored.
                    We never see your master password or your vault contents.
                    This means <strong className="text-aegis-danger">there is NO password recovery</strong> if you forget your master password.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-3 mb-6">
            <p className="text-sm font-medium text-aegis-subtle">Confirm you understand:</p>
            {[
              { key: 'neverSent', label: 'My vault master password is never sent to the server' },
              { key: 'noRecovery', label: 'Forgetting my master password means permanent vault data loss' },
              { key: 'different', label: 'My master password should be different from my account password' },
            ].map(({ key, label }) => (
              <label key={key} className="flex items-start gap-3 cursor-pointer group">
                <div className={`w-5 h-5 rounded border-2 shrink-0 mt-0.5 flex items-center justify-center transition-colors ${understood[key as keyof typeof understood] ? 'bg-aegis-primary border-aegis-primary' : 'border-aegis-border group-hover:border-aegis-primary'}`}
                  onClick={() => setUnderstood((u) => ({ ...u, [key]: !u[key as keyof typeof understood] }))}>
                  {understood[key as keyof typeof understood] && <CheckCircle2 className="w-3 h-3 text-white" />}
                </div>
                <span className="text-sm text-aegis-subtle leading-relaxed">{label}</span>
              </label>
            ))}
          </div>

          <button
            onClick={handleContinueFromUnderstand}
            disabled={!allUnderstood}
            className="aegis-btn-primary w-full"
          >
            I understand — Set up Master Password
          </button>
        </>
      )}

      {/* Step: Setup */}
      {step === 'setup' && (
        <>
          <h1 className="text-lg font-semibold text-aegis-text mb-1">Set Vault Master Password</h1>
          <p className="text-sm text-aegis-muted mb-6">
            This encrypts all your secrets. Use a strong, unique password you can remember.
          </p>

          <div className="space-y-4">
            <div>
              <label className="block text-sm text-aegis-subtle mb-1.5">Master Password</label>
              <div className="relative">
                <input
                  type={showPw ? 'text' : 'password'}
                  value={masterPw}
                  onChange={(e) => setMasterPw(e.target.value)}
                  className="aegis-input pr-10"
                  placeholder="Create a strong master password"
                  autoComplete="new-password"
                />
                <button type="button" onClick={() => setShowPw((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted">
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              {masterPw && (
                <div className="mt-1.5 space-y-1">
                  <div className="flex gap-1">
                    {[0,1,2,3].map((i) => (
                      <div key={i} className={`h-1 flex-1 rounded-full transition-colors ${i <= strength.score ? ['bg-red-500','bg-yellow-500','bg-yellow-400','bg-green-400','bg-green-500'][strength.score] : 'bg-aegis-border'}`} />
                    ))}
                  </div>
                  {strength.feedback.map((f, i) => (
                    <p key={i} className="text-xs text-aegis-muted">{f}</p>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm text-aegis-subtle mb-1.5">Confirm Master Password</label>
              <input
                type="password" value={confirmPw}
                onChange={(e) => setConfirmPw(e.target.value)}
                className={`aegis-input ${confirmPw && confirmPw !== masterPw ? 'border-aegis-danger' : ''}`}
                placeholder="Confirm master password"
              />
            </div>

            <button
              onClick={handleSetupContinue}
              disabled={!strength.valid || masterPw !== confirmPw || !masterPw}
              className="aegis-btn-primary w-full"
            >
              Continue
            </button>
          </div>
        </>
      )}

      {/* Step: Confirm / Recovery reminder */}
      {step === 'confirm' && (
        <>
          <div className="text-center mb-6">
            <div className="w-16 h-16 rounded-full bg-aegis-warning-muted flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="w-8 h-8 text-aegis-warning" />
            </div>
            <h1 className="text-lg font-semibold text-aegis-text mb-2">Save Your Master Password</h1>
            <p className="text-sm text-aegis-muted">Before you continue, make sure you&apos;ve saved it somewhere safe.</p>
          </div>

          <div className="bg-aegis-elevated rounded-aegis-lg p-4 mb-6 space-y-2">
            <p className="text-sm font-medium text-aegis-text">Recommended storage:</p>
            <ul className="text-sm text-aegis-subtle space-y-1 list-disc list-inside">
              <li>A different, trusted password manager</li>
              <li>Written on paper in a secure location</li>
              <li>Printed in an emergency kit (do NOT print actual vault secrets)</li>
            </ul>
          </div>

          <div className="space-y-3">
            <button onClick={handleFinish} className="aegis-btn-primary w-full">
              I&apos;ve saved my master password — Go to Vault
            </button>
            <button onClick={() => setStep('setup')} className="aegis-btn-ghost w-full text-sm">
              ← Go back and change it
            </button>
          </div>
        </>
      )}
    </div>
  );
}
