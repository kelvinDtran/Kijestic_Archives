'use client';

import { useState, useRef } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Lock, Mail, Shield, Fingerprint, Loader2 } from 'lucide-react';

type MfaType = 'totp' | 'telegram' | 'email';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail]       = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [requiresMfa, setRequiresMfa]   = useState(false);
  const [mfaType, setMfaType]           = useState<MfaType | null>(null);
  const [mfaToken, setMfaToken]         = useState<string | null>(null);
  const [mfaCode, setMfaCode]           = useState('');
  const [isLoading, setIsLoading]       = useState(false);
  const [isPasskeyLoading, setIsPasskeyLoading] = useState(false);
  const [isResending, setIsResending]   = useState(false);
  const [error, setError]               = useState<string | null>(null);
  const totpRef = useRef<HTMLInputElement>(null);
  const mfaCodeRef = useRef<HTMLInputElement>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      // Telegram / Email MFA verification path
      if (requiresMfa && (mfaType === 'telegram' || mfaType === 'email')) {
        const res = await fetch('/api/auth/mfa/verify-login', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ mfaToken, code: mfaCode }),
          credentials: 'include',
        });

        const data = await res.json();

        if (!res.ok) throw new Error(data.error ?? 'Verification failed');

        router.push('/dashboard');
        return;
      }

      // TOTP path (and initial credential submission)
      const res = await fetch('/api/auth/login', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          email,
          password,
          ...(requiresMfa && mfaType === 'totp' && { totpCode }),
        }),
        credentials: 'include',
      });

      const data = await res.json();

      if (!res.ok) {
        if (data.code === 'MFA_REQUIRED') {
          const type: MfaType = data.mfaType ?? 'totp';
          setMfaType(type);
          setRequiresMfa(true);

          if (type === 'totp') {
            setTimeout(() => totpRef.current?.focus(), 100);
          } else {
            // Server already sent the code for Telegram/Email; store token for verification
            if (data.mfaToken) setMfaToken(data.mfaToken);
            setTimeout(() => mfaCodeRef.current?.focus(), 100);
          }

          setIsLoading(false);
          return;
        }
        throw new Error(data.error ?? 'Login failed');
      }

      router.push('/dashboard');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setIsLoading(false);
    }
  };

  const handleResendCode = async () => {
    if (!mfaToken || isResending) return;
    setError(null);
    setIsResending(true);
    try {
      const res = await fetch('/api/auth/mfa/send-code', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ mfaToken }),
        credentials: 'include',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error ?? 'Failed to resend code');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resend code');
    } finally {
      setIsResending(false);
    }
  };

  const handleBack = () => {
    setRequiresMfa(false);
    setMfaType(null);
    setMfaToken(null);
    setTotpCode('');
    setMfaCode('');
  };

  const handlePasskeySignIn = async () => {
    setError(null);
    setIsPasskeyLoading(true);
    try {
      // Dynamically import browser library to avoid SSR issues
      const { startAuthentication } = await import('@simplewebauthn/browser');

      // 1. Get authentication options from server
      const optRes = await fetch('/api/auth/webauthn/authenticate', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: email || undefined }),
        credentials: 'include',
      });
      if (!optRes.ok) throw new Error('Failed to start passkey authentication');
      const { data: optData } = await optRes.json();

      // 2. Invoke browser passkey UI
      const authResponse = await startAuthentication({ optionsJSON: optData.options });

      // 3. Verify with server
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
      // User cancelled passkey prompt — don't show an error for that case
      const message = err instanceof Error ? err.message : 'Passkey sign-in failed';
      if (!message.includes('cancelled') && !message.includes('abort')) {
        setError(message);
      }
    } finally {
      setIsPasskeyLoading(false);
    }
  };

  const renderMfaStep = () => {
    if (mfaType === 'totp') {
      return (
        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5" htmlFor="totp">
            Authenticator Code
          </label>
          <input
            id="totp"
            ref={totpRef}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            className="aegis-input text-center text-2xl tracking-[0.5em] font-mono"
            placeholder="000000"
            maxLength={6}
            required
          />
          <p className="text-xs text-aegis-muted mt-1.5">
            Enter the 6-digit code from your authenticator app
          </p>
        </div>
      );
    }

    if (mfaType === 'telegram') {
      return (
        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5" htmlFor="mfa-code">
            Telegram Verification Code
          </label>
          <input
            id="mfa-code"
            ref={mfaCodeRef}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            className="aegis-input text-center text-2xl tracking-[0.5em] font-mono"
            placeholder="000000"
            maxLength={6}
            required
          />
          <p className="text-xs text-aegis-muted mt-1.5">
            A 6-digit code was sent to your Telegram. Enter it below.
          </p>
          <button
            type="button"
            onClick={handleResendCode}
            disabled={isResending}
            className="mt-2 text-xs text-aegis-primary hover:underline disabled:opacity-50"
          >
            {isResending ? 'Sending…' : 'Resend to Telegram'}
          </button>
        </div>
      );
    }

    if (mfaType === 'email') {
      return (
        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5" htmlFor="mfa-code">
            Email Verification Code
          </label>
          <input
            id="mfa-code"
            ref={mfaCodeRef}
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            className="aegis-input text-center text-2xl tracking-[0.5em] font-mono"
            placeholder="000000"
            maxLength={6}
            required
          />
          <p className="text-xs text-aegis-muted mt-1.5">
            A 6-digit code was sent to your email. Enter it below.
          </p>
          <button
            type="button"
            onClick={handleResendCode}
            disabled={isResending}
            className="mt-2 text-xs text-aegis-primary hover:underline disabled:opacity-50"
          >
            {isResending ? 'Sending…' : 'Resend code'}
          </button>
        </div>
      );
    }

    return null;
  };

  const submitLabel = () => {
    if (!requiresMfa) return 'Sign In';
    return 'Verify Code';
  };

  const submitLoadingLabel = () => {
    if (!requiresMfa) return 'Signing in…';
    return 'Verifying…';
  };

  return (
    <div className="aegis-card animate-fade-in">
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
        {!requiresMfa ? (
          <>
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
          </>
        ) : (
          renderMfaStep()
        )}

        <button type="submit" disabled={isLoading} className="aegis-btn-primary w-full mt-2">
          {isLoading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              {submitLoadingLabel()}
            </span>
          ) : (
            submitLabel()
          )}
        </button>

        {requiresMfa && (
          <button
            type="button"
            onClick={handleBack}
            className="aegis-btn-ghost w-full text-center text-sm"
          >
            ← Back
          </button>
        )}
      </form>

      {/* Passkey sign-in */}
      {!requiresMfa && (
        <>
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
        </>
      )}

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
    </div>
  );
}
