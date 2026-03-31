'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Lock, Mail, Shield, Fingerprint, Loader2, KeyRound, MessageCircle, Phone } from 'lucide-react';

type RecoveryType = 'backup' | 'telegram' | 'whatsapp';

export default function LoginPage() {
  const router = useRouter();

  // Credential fields
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  // Passkey-first flow state
  const [preAuthToken, setPreAuthToken]       = useState<string | null>(null);
  const [recoveryType, setRecoveryType]       = useState<RecoveryType | null>(null);
  const [recoveryCode, setRecoveryCode]       = useState('');
  const [showRecovery, setShowRecovery]       = useState(false);
  const [availableRecovery, setAvailableRecovery] = useState<{ telegram: boolean; whatsapp: boolean }>({
    telegram: false,
    whatsapp: false,
  });

  // Loading states
  const [isLoading, setIsLoading]               = useState(false);
  const [isPasskeyLoading, setIsPasskeyLoading] = useState(false);
  const [isSendingCode, setIsSendingCode]       = useState(false);
  const [isVerifyingRecovery, setIsVerifyingRecovery] = useState(false);

  const [error, setError] = useState<string | null>(null);

  // ── Step 1: email + password submit ────────────────────────────────────────

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email, password }),
        credentials: 'include',
      });

      const data = await res.json();

      if (data.success) {
        // No passkeys enrolled — logged in directly
        router.push('/dashboard');
        return;
      }

      if (!data.success && data.code === 'PASSKEY_REQUIRED') {
        setPreAuthToken(data.preAuthToken);
        setAvailableRecovery({
          telegram:  data.data?.telegramEnabled  ?? false,
          whatsapp:  data.data?.whatsappEnabled  ?? false,
        });
        setIsLoading(false);
        return;
      }

      throw new Error(data.error ?? 'Login failed');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setIsLoading(false);
    }
  };

  // ── Passkey verification (post-password) ───────────────────────────────────

  const handleVerifyPasskey = async () => {
    if (!preAuthToken) return;
    setError(null);
    setIsPasskeyLoading(true);
    try {
      const { startAuthentication } = await import('@simplewebauthn/browser');

      // 1. Get authentication options — pass preAuthToken instead of email
      const optRes = await fetch('/api/auth/webauthn/authenticate', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ preAuthToken }),
        credentials: 'include',
      });
      if (!optRes.ok) throw new Error('Failed to start passkey authentication');
      const { data: optData } = await optRes.json();

      // 2. Invoke browser passkey UI
      const authResponse = await startAuthentication({ optionsJSON: optData.options });

      // 3. Verify with server — pass preAuthToken
      const verifyRes = await fetch('/api/auth/webauthn/authenticate/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ response: authResponse, preAuthToken }),
        credentials: 'include',
      });
      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(err.error ?? 'Passkey verification failed');
      }

      router.push('/dashboard');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey sign-in failed';
      if (!message.includes('cancelled') && !message.includes('abort')) {
        setError(message);
      }
    } finally {
      setIsPasskeyLoading(false);
    }
  };

  // ── Passwordless passkey sign-in (pre-password, existing button) ───────────

  const handlePasskeySignIn = async () => {
    setError(null);
    setIsPasskeyLoading(true);
    try {
      const { startAuthentication } = await import('@simplewebauthn/browser');

      const optRes = await fetch('/api/auth/webauthn/authenticate', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: email || undefined }),
        credentials: 'include',
      });
      if (!optRes.ok) throw new Error('Failed to start passkey authentication');
      const { data: optData } = await optRes.json();

      const authResponse = await startAuthentication({ optionsJSON: optData.options });

      const verifyRes = await fetch('/api/auth/webauthn/authenticate/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ response: authResponse }),
        credentials: 'include',
      });
      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(err.error ?? 'Passkey verification failed');
      }

      router.push('/dashboard');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey sign-in failed';
      if (!message.includes('cancelled') && !message.includes('abort')) {
        setError(message);
      }
    } finally {
      setIsPasskeyLoading(false);
    }
  };

  // ── Recovery: send code via Telegram or WhatsApp ───────────────────────────

  const handleSendRecoveryCode = async (type: 'telegram' | 'whatsapp') => {
    if (!preAuthToken) return;
    setError(null);
    setIsSendingCode(true);
    try {
      const res = await fetch('/api/auth/mfa/send-code', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ preAuthToken, type }),
        credentials: 'include',
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? `Failed to send ${type} code`);
      setRecoveryType(type);
      setShowRecovery(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to send ${type} code`);
    } finally {
      setIsSendingCode(false);
    }
  };

  // ── Recovery: verify submitted code ───────────────────────────────────────

  const handleVerifyRecovery = async () => {
    if (!preAuthToken || !recoveryType) return;
    setError(null);
    setIsVerifyingRecovery(true);
    try {
      const res = await fetch('/api/auth/mfa/verify-login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ preAuthToken, code: recoveryCode, type: recoveryType }),
        credentials: 'include',
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Verification failed');
      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifyingRecovery(false);
    }
  };

  // ── Navigation helpers ─────────────────────────────────────────────────────

  const backToPasskeyPrompt = () => {
    setShowRecovery(false);
    setRecoveryType(null);
    setRecoveryCode('');
    setError(null);
  };

  const backToLogin = () => {
    setPreAuthToken(null);
    setAvailableRecovery({ telegram: false, whatsapp: false });
    setShowRecovery(false);
    setRecoveryType(null);
    setRecoveryCode('');
    setError(null);
  };

  // ── Recovery description ──────────────────────────────────────────────────

  const recoveryDescription = () => {
    if (recoveryType === 'backup')   return 'Enter your backup code:';
    if (recoveryType === 'telegram') return 'Enter the code sent to your Telegram:';
    if (recoveryType === 'whatsapp') return 'Enter the code sent to your WhatsApp:';
    return 'Enter your recovery code:';
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="aegis-card animate-fade-in">

      {/* State 3 — Recovery code entry */}
      {preAuthToken && showRecovery && recoveryType ? (
        <>
          <h1 className="text-xl font-semibold text-aegis-text mb-1">Enter recovery code</h1>
          <p className="text-sm text-aegis-muted mb-6">{recoveryDescription()}</p>

          {error && (
            <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <input
              type="text"
              inputMode={recoveryType === 'backup' ? 'text' : 'numeric'}
              autoComplete="one-time-code"
              value={recoveryCode}
              onChange={(e) => setRecoveryCode(e.target.value)}
              className={`aegis-input w-full ${recoveryType !== 'backup' ? 'text-center text-2xl tracking-[0.5em] font-mono' : ''}`}
              placeholder={recoveryType === 'backup' ? 'XXXX-XXXX-XXXX-XXXX-XXXX' : '000000'}
              maxLength={recoveryType === 'backup' ? 64 : 6}
              autoFocus
            />
            <button
              type="button"
              onClick={handleVerifyRecovery}
              disabled={isVerifyingRecovery || !recoveryCode.trim()}
              className="aegis-btn-primary w-full flex items-center justify-center gap-2"
            >
              {isVerifyingRecovery ? (
                <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Verifying…</>
              ) : (
                'Verify Recovery Code'
              )}
            </button>
            <button
              type="button"
              onClick={backToPasskeyPrompt}
              className="aegis-btn-ghost w-full text-center text-sm"
            >
              ← Back
            </button>
          </div>
        </>
      ) : preAuthToken && !showRecovery ? (
        /* State 2 — Passkey prompt */
        <>
          <h1 className="text-xl font-semibold text-aegis-text mb-1">Verify with your passkey</h1>
          <p className="text-sm text-aegis-muted mb-6">
            Use your device passkey or biometrics to complete sign-in.
          </p>

          {error && (
            <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
              {error}
            </div>
          )}

          <div className="space-y-3">
            {/* Primary passkey button */}
            <button
              type="button"
              onClick={handleVerifyPasskey}
              disabled={isPasskeyLoading || isSendingCode}
              className="aegis-btn-primary w-full flex items-center justify-center gap-2 text-sm"
            >
              {isPasskeyLoading ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Waiting for passkey…</>
              ) : (
                <><Fingerprint className="w-5 h-5" /> Verify with Passkey</>
              )}
            </button>

            {/* Recovery divider */}
            <div className="flex items-center gap-3 my-2">
              <hr className="flex-1 border-aegis-border" />
              <span className="text-xs text-aegis-muted">or recover access</span>
              <hr className="flex-1 border-aegis-border" />
            </div>

            {/* Backup code — always available */}
            <button
              type="button"
              onClick={() => { setRecoveryType('backup'); setShowRecovery(true); }}
              disabled={isPasskeyLoading || isSendingCode}
              className="aegis-btn-ghost w-full flex items-center justify-center gap-2 text-sm"
            >
              <KeyRound className="w-4 h-4" /> Use backup code
            </button>

            {/* Telegram — if enrolled */}
            {availableRecovery.telegram && (
              <button
                type="button"
                onClick={() => handleSendRecoveryCode('telegram')}
                disabled={isPasskeyLoading || isSendingCode}
                className="aegis-btn-ghost w-full flex items-center justify-center gap-2 text-sm"
              >
                {isSendingCode ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Sending…</>
                ) : (
                  <><MessageCircle className="w-4 h-4" /> Send Telegram code</>
                )}
              </button>
            )}

            {/* WhatsApp — if enrolled */}
            {availableRecovery.whatsapp && (
              <button
                type="button"
                onClick={() => handleSendRecoveryCode('whatsapp')}
                disabled={isPasskeyLoading || isSendingCode}
                className="aegis-btn-ghost w-full flex items-center justify-center gap-2 text-sm"
              >
                {isSendingCode ? (
                  <><Loader2 className="w-4 h-4 animate-spin" /> Sending…</>
                ) : (
                  <><Phone className="w-4 h-4" /> Send WhatsApp code</>
                )}
              </button>
            )}

            <button
              type="button"
              onClick={backToLogin}
              className="aegis-btn-ghost w-full text-center text-sm"
            >
              ← Back to login
            </button>
          </div>
        </>
      ) : (
        /* State 1 — Email + Password form */
        <>
          <h1 className="text-xl font-semibold text-aegis-text mb-1">Sign in</h1>
          <p className="text-sm text-aegis-muted mb-6">
            Enter your credentials to access your vault
          </p>

          {error && (
            <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email */}
            <div>
              <label className="block text-sm text-aegis-subtle mb-1.5" htmlFor="email">
                Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="aegis-input pl-9"
                  placeholder="you@example.com"
                  required
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm text-aegis-subtle mb-1.5" htmlFor="password">
                Account Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="aegis-input pl-9 pr-10"
                  placeholder="Account password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-aegis-subtle"
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button type="submit" disabled={isLoading} className="aegis-btn-primary w-full mt-2">
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Passwordless passkey sign-in */}
          <div className="flex items-center gap-3 my-4">
            <hr className="flex-1 border-aegis-border" />
            <span className="text-xs text-aegis-muted">or</span>
            <hr className="flex-1 border-aegis-border" />
          </div>
          <button
            type="button"
            onClick={handlePasskeySignIn}
            disabled={isPasskeyLoading}
            className="aegis-btn-secondary w-full flex items-center justify-center gap-2 text-sm"
          >
            {isPasskeyLoading
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Waiting for passkey…</>
              : <><Fingerprint className="w-4 h-4" /> Sign in with passkey</>}
          </button>

          <div className="mt-6 pt-4 border-t border-aegis-border text-center">
            <p className="text-sm text-aegis-muted">
              Don&apos;t have an account?{' '}
              <Link href="/register" className="text-aegis-primary hover:underline">
                Create one
              </Link>
            </p>
          </div>

          {/* Security note */}
          <div className="mt-4 flex items-start gap-2 bg-aegis-elevated rounded-aegis px-3 py-2">
            <Shield className="w-3.5 h-3.5 text-aegis-muted mt-0.5 shrink-0" />
            <p className="text-xs text-aegis-muted leading-relaxed">
              You&apos;ll be asked for your{' '}
              <span className="text-aegis-subtle">vault master password</span> separately
              to decrypt your secrets. Your account password only verifies your identity.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
