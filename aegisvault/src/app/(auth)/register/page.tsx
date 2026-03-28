'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff, Mail, Lock, AlertTriangle } from 'lucide-react';
import { generateKdfSalt } from '@/lib/crypto/kdf';
import { validatePasswordStrength } from '@/lib/auth/password';

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail]     = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm]   = useState('');
  const [showPw, setShowPw]     = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError]         = useState<string | null>(null);

  const strength = validatePasswordStrength(password);
  const strengthColors = ['bg-red-500', 'bg-red-400', 'bg-yellow-400', 'bg-green-400', 'bg-green-500'];
  const strengthLabels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirm) {
      setError('Passwords do not match');
      return;
    }
    if (!strength.valid) {
      setError('Password is too weak: ' + strength.feedback[0]);
      return;
    }

    setIsLoading(true);
    try {
      // Generate KDF salt client-side
      const kdfSalt = generateKdfSalt();

      const res = await fetch('/api/auth/register', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          email,
          password,
          kdfSalt:        kdfSalt.salt,
          kdfVersion:     kdfSalt.version,
          kdfMemory:      kdfSalt.memory,
          kdfIterations:  kdfSalt.iterations,
          kdfParallelism: kdfSalt.parallelism,
        }),
        credentials: 'include',
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Registration failed');

      // Redirect to onboarding to set up master password
      router.push('/onboarding');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
      setIsLoading(false);
    }
  };

  return (
    <div className="aegis-card animate-fade-in">
      <h1 className="text-xl font-semibold text-aegis-text mb-1">Create Account</h1>
      <p className="text-sm text-aegis-muted mb-6">Set up your AegisVault account</p>

      {error && (
        <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5">Email</label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
            <input
              type="email" autoComplete="email"
              value={email} onChange={(e) => setEmail(e.target.value)}
              className="aegis-input pl-9" placeholder="you@example.com" required
            />
          </div>
        </div>

        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5">Account Password</label>
          <p className="text-xs text-aegis-muted mb-1.5">
            Used for login only — NOT for encrypting your secrets.
          </p>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
            <input
              type={showPw ? 'text' : 'password'} autoComplete="new-password"
              value={password} onChange={(e) => setPassword(e.target.value)}
              className="aegis-input pl-9 pr-10" placeholder="Account password" required
            />
            <button type="button" onClick={() => setShowPw((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-aegis-muted hover:text-aegis-subtle">
              {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>
          {password && (
            <div className="mt-1.5">
              <div className="flex gap-1 mb-1">
                {[0,1,2,3].map((i) => (
                  <div key={i}
                    className={`h-1 flex-1 rounded-full transition-colors ${i <= strength.score ? strengthColors[strength.score] : 'bg-aegis-border'}`}
                  />
                ))}
              </div>
              <p className="text-xs text-aegis-muted">{strengthLabels[strength.score]}</p>
            </div>
          )}
        </div>

        <div>
          <label className="block text-sm text-aegis-subtle mb-1.5">Confirm Password</label>
          <input
            type="password" autoComplete="new-password"
            value={confirm} onChange={(e) => setConfirm(e.target.value)}
            className={`aegis-input ${confirm && confirm !== password ? 'border-aegis-danger' : ''}`}
            placeholder="Confirm password" required
          />
          {confirm && confirm !== password && (
            <p className="text-xs text-aegis-danger mt-1">Passwords do not match</p>
          )}
        </div>

        {/* Important security notice */}
        <div className="bg-aegis-warning-muted border border-aegis-warning rounded-aegis px-3 py-3">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-aegis-warning shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-semibold text-aegis-warning mb-1">Read before continuing</p>
              <ul className="text-xs text-aegis-subtle space-y-1 list-disc list-inside">
                <li>On the next step, you&apos;ll set a <strong className="text-aegis-text">vault master password</strong></li>
                <li>Your secrets are encrypted with this password, not your account password</li>
                <li>If you forget your master password, <strong className="text-aegis-warning">your data cannot be recovered</strong></li>
                <li>Store it somewhere safe (password manager, printed paper)</li>
              </ul>
            </div>
          </div>
        </div>

        <button type="submit" disabled={isLoading} className="aegis-btn-primary w-full">
          {isLoading ? (
            <span className="flex items-center justify-center gap-2">
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Creating account…
            </span>
          ) : 'Create Account & Continue'}
        </button>
      </form>

      <div className="mt-6 pt-4 border-t border-aegis-border text-center">
        <p className="text-sm text-aegis-muted">
          Already have an account?{' '}
          <Link href="/login" className="text-aegis-primary hover:underline">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
