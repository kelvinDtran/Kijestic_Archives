'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { Shield, Clock, Key, Download, Upload, Trash2, CheckCircle2, AlertTriangle, Loader2, Fingerprint, Plus, Pencil, Smartphone, Phone, Mail } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useVault } from '@/contexts/VaultContext';
import {
  createExportPackage,
  decryptExportPackage,
  decryptVaultItem,
  encryptVaultItem,
  type VaultExportPackage,
} from '@/lib/crypto/vault-crypto';
import type { DecryptedVaultItem, EncryptedVaultItem } from '@/types/vault';

export default function SettingsPage() {
  const { isLocked, getVaultKey } = useVault();
  const [lockTimeout, setLockTimeout] = useState(300);
  const [saved, setSaved] = useState(false);
  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Export state
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Import state
  const [isImporting, setIsImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importSuccess, setImportSuccess] = useState<string | null>(null);
  const importFileRef = useRef<HTMLInputElement>(null);

  // Passkey state
  interface PasskeyCredential { id: string; name: string; deviceType: string; backedUp: boolean; transports: string[]; createdAt: string; lastUsedAt: string | null; }
  const [passkeys, setPasskeys] = useState<PasskeyCredential[]>([]);
  const [isRegisteringPasskey, setIsRegisteringPasskey] = useState(false);
  const [passkeyError, setPasskeyError] = useState<string | null>(null);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState<string | null>(null);

  // Rename state
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState('');
  const [isSavingRename, setIsSavingRename] = useState(false);

  // SMS MFA state
  const [smsEnabled, setSmsEnabled] = useState(false);
  const [phoneNumber, setPhoneNumber] = useState<string | null>(null);
  const [smsStep, setSmsStep] = useState<'idle' | 'verify'>('idle');
  const [smsPhoneInput, setSmsPhoneInput] = useState('');
  const [smsCodeInput, setSmsCodeInput] = useState('');
  const [isSendingCode, setIsSendingCode] = useState(false);
  const [isVerifyingSms, setIsVerifyingSms] = useState(false);
  const [isDisablingSms, setIsDisablingSms] = useState(false);
  const [smsDisableCode, setSmsDisableCode] = useState('');
  const [showSmsDisableForm, setShowSmsDisableForm] = useState(false);
  const [smsError, setSmsError] = useState<string | null>(null);
  const [smsSuccess, setSmsSuccess] = useState<string | null>(null);

  // Email MFA state
  const [emailMfaEnabled, setEmailMfaEnabled] = useState(false);
  const [emailMfaStep, setEmailMfaStep] = useState<'idle' | 'verify'>('idle');
  const [emailMfaCode, setEmailMfaCode] = useState('');
  const [isEnablingEmail, setIsEnablingEmail] = useState(false);
  const [isVerifyingEmail, setIsVerifyingEmail] = useState(false);
  const [isDisablingEmail, setIsDisablingEmail] = useState(false);
  const [emailDisableCode, setEmailDisableCode] = useState('');
  const [showEmailDisableForm, setShowEmailDisableForm] = useState(false);
  const [emailMfaError, setEmailMfaError] = useState<string | null>(null);
  const [emailMfaSuccess, setEmailMfaSuccess] = useState<string | null>(null);

  const fetchPasskeys = useCallback(async () => {
    const res = await fetch('/api/auth/webauthn/credentials', { credentials: 'include' });
    if (res.ok) {
      const { data } = await res.json();
      setPasskeys(data.credentials);
    }
  }, []);

  useEffect(() => {
    fetchPasskeys();
  }, [fetchPasskeys]);

  const registerPasskey = async () => {
    setPasskeyError(null);
    setIsRegisteringPasskey(true);
    try {
      const { startRegistration } = await import('@simplewebauthn/browser');

      // 1. Get registration options
      const optRes = await fetch('/api/auth/webauthn/register', { method: 'POST', credentials: 'include' });
      if (!optRes.ok) throw new Error('Failed to start passkey registration');
      const { data: optData } = await optRes.json();

      // 2. Trigger browser passkey creation
      const registrationResponse = await startRegistration({ optionsJSON: optData.options });

      // 3. Verify and store
      const verifyRes = await fetch('/api/auth/webauthn/register/verify', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ response: registrationResponse }),
        credentials: 'include',
      });
      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(err.error ?? 'Passkey registration failed');
      }

      await fetchPasskeys();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Registration failed';
      if (!message.includes('cancelled') && !message.includes('abort')) {
        setPasskeyError(message);
      }
    } finally {
      setIsRegisteringPasskey(false);
    }
  };

  const deletePasskey = async (id: string) => {
    if (!confirm('Remove this passkey? You won\'t be able to sign in with it anymore.')) return;
    setDeletingPasskeyId(id);
    try {
      await fetch(`/api/auth/webauthn/credentials/${id}`, { method: 'DELETE', credentials: 'include' });
      setPasskeys((prev) => prev.filter((p) => p.id !== id));
    } finally {
      setDeletingPasskeyId(null);
    }
  };

  const startRename = (pk: PasskeyCredential) => {
    setRenamingId(pk.id);
    setRenameValue(pk.name);
  };

  const cancelRename = () => {
    setRenamingId(null);
    setRenameValue('');
  };

  const saveRename = async (id: string) => {
    const trimmed = renameValue.trim();
    if (!trimmed) return;
    setIsSavingRename(true);
    try {
      const res = await fetch(`/api/auth/webauthn/credentials/${id}`, {
        method:  'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ name: trimmed }),
        credentials: 'include',
      });
      if (res.ok) {
        setPasskeys((prev) => prev.map((p) => p.id === id ? { ...p, name: trimmed } : p));
        cancelRename();
      }
    } finally {
      setIsSavingRename(false);
    }
  };

  useEffect(() => {
    fetch('/api/account/preferences', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => {
        if (d.success) {
          setLockTimeout(d.data.lockTimeout ?? 300);
          setMfaEnabled(d.data.totpEnabled ?? false);
          setSmsEnabled(d.data.smsEnabled ?? false);
          setPhoneNumber(d.data.phoneNumber ?? null);
          setEmailMfaEnabled(d.data.emailMfaEnabled ?? false);
        }
      })
      .catch(() => {})
      .finally(() => setIsLoading(false));
  }, []);

  const savePreferences = async () => {
    await fetch('/api/account/preferences', {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ lockTimeout }),
      credentials: 'include',
    });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  // ── Export ────────────────────────────────────────────────────────────────

  const handleExport = async () => {
    setIsExporting(true);
    setExportError(null);
    try {
      const vaultKey = getVaultKey();

      // 1. Fetch all encrypted items from server
      const res = await fetch('/api/vault/export', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch vault items');
      const { data } = await res.json();
      const encryptedItems: EncryptedVaultItem[] = data.items;

      // 2. Decrypt all items client-side
      const decryptedItems: DecryptedVaultItem[] = encryptedItems.map((item) =>
        decryptVaultItem(vaultKey, item),
      );

      // 3. Re-package with a fresh export key
      const exportPackage: VaultExportPackage = createExportPackage(vaultKey, decryptedItems);

      // 4. Trigger download
      const blob = new Blob([JSON.stringify(exportPackage, null, 2)], { type: 'application/json' });
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `aegisvault-backup-${new Date().toISOString().slice(0, 10)}.aegisvault`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  // ── Import ────────────────────────────────────────────────────────────────

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsImporting(true);
    setImportError(null);
    setImportSuccess(null);

    try {
      const vaultKey = getVaultKey();

      // 1. Read the file
      const text = await file.text();
      const pkg: VaultExportPackage = JSON.parse(text);

      // 2. Decrypt the export package client-side
      const decryptedItems = decryptExportPackage(vaultKey, pkg);

      // 3. Re-encrypt each item with the current vault key (fresh DEK per item)
      const reEncryptedItems = decryptedItems.map((item) => {
        const encrypted = encryptVaultItem(
          vaultKey,
          item.itemType,
          item.isFavorite,
          item.isHighRisk,
          item.data,
        );
        return {
          ...encrypted,
          isArchived: item.isArchived,
        };
      });

      // 4. Send to import API
      const res = await fetch('/api/vault/import', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ items: reEncryptedItems }),
        credentials: 'include',
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error ?? 'Import failed');
      }

      const { data } = await res.json();
      setImportSuccess(`Successfully imported ${data.imported} item${data.imported !== 1 ? 's' : ''}.`);
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Import failed. The file may be corrupted or from a different vault.');
    } finally {
      setIsImporting(false);
      // Reset the file input so the same file can be re-selected if needed
      if (importFileRef.current) importFileRef.current.value = '';
    }
  };

  // ── SMS MFA ───────────────────────────────────────────────────────────────

  const maskPhone = (num: string) => {
    // E.164: keep country code prefix and last 4 digits, mask the rest
    const cleaned = num.replace(/\s/g, '');
    if (cleaned.length <= 5) return cleaned;
    const prefix = cleaned.slice(0, cleaned.indexOf(' ') !== -1 ? cleaned.indexOf(' ') : 2);
    const last4 = cleaned.slice(-4);
    return `${prefix} *** *** ${last4}`;
  };

  const sendSmsCode = async () => {
    setSmsError(null);
    if (!smsPhoneInput.trim()) {
      setSmsError('Please enter a phone number in E.164 format (e.g. +16025551234)');
      return;
    }
    setIsSendingCode(true);
    try {
      const res = await fetch('/api/auth/mfa/sms/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phoneNumber: smsPhoneInput.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to send verification code');
      setSmsStep('verify');
    } catch (err) {
      setSmsError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setIsSendingCode(false);
    }
  };

  const verifySmsCode = async () => {
    setSmsError(null);
    if (!smsCodeInput.trim()) {
      setSmsError('Please enter the 6-digit code');
      return;
    }
    setIsVerifyingSms(true);
    try {
      const res = await fetch('/api/auth/mfa/sms/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: smsCodeInput.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Verification failed');
      setSmsEnabled(true);
      setPhoneNumber(smsPhoneInput.trim());
      setSmsStep('idle');
      setSmsPhoneInput('');
      setSmsCodeInput('');
      setSmsSuccess('SMS MFA enabled successfully');
      setTimeout(() => setSmsSuccess(null), 3000);
    } catch (err) {
      setSmsError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifyingSms(false);
    }
  };

  const disableSms = async () => {
    setSmsError(null);
    if (!smsDisableCode.trim()) {
      setSmsError('Please enter your current SMS code or password to disable');
      return;
    }
    setIsDisablingSms(true);
    try {
      const res = await fetch('/api/auth/mfa/sms/setup', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: smsDisableCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable SMS MFA');
      setSmsEnabled(false);
      setPhoneNumber(null);
      setShowSmsDisableForm(false);
      setSmsDisableCode('');
      setSmsSuccess('SMS MFA disabled');
      setTimeout(() => setSmsSuccess(null), 3000);
    } catch (err) {
      setSmsError(err instanceof Error ? err.message : 'Failed to disable SMS MFA');
    } finally {
      setIsDisablingSms(false);
    }
  };

  // ── Email MFA ─────────────────────────────────────────────────────────────

  const enableEmailMfa = async () => {
    setEmailMfaError(null);
    setIsEnablingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/setup', {
        method: 'POST',
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to send verification code');
      setEmailMfaStep('verify');
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setIsEnablingEmail(false);
    }
  };

  const verifyEmailMfa = async () => {
    setEmailMfaError(null);
    if (!emailMfaCode.trim()) {
      setEmailMfaError('Please enter the 6-digit code');
      return;
    }
    setIsVerifyingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: emailMfaCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Verification failed');
      setEmailMfaEnabled(true);
      setEmailMfaStep('idle');
      setEmailMfaCode('');
      setEmailMfaSuccess('Email MFA enabled successfully');
      setTimeout(() => setEmailMfaSuccess(null), 3000);
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setIsVerifyingEmail(false);
    }
  };

  const disableEmailMfa = async () => {
    setEmailMfaError(null);
    if (!emailDisableCode.trim()) {
      setEmailMfaError('Please enter your current email code or password to disable');
      return;
    }
    setIsDisablingEmail(true);
    try {
      const res = await fetch('/api/auth/mfa/email/setup', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: emailDisableCode.trim() }),
        credentials: 'include',
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error ?? 'Failed to disable Email MFA');
      setEmailMfaEnabled(false);
      setShowEmailDisableForm(false);
      setEmailDisableCode('');
      setEmailMfaSuccess('Email MFA disabled');
      setTimeout(() => setEmailMfaSuccess(null), 3000);
    } catch (err) {
      setEmailMfaError(err instanceof Error ? err.message : 'Failed to disable Email MFA');
    } finally {
      setIsDisablingEmail(false);
    }
  };

  const timeoutOptions = [
    { label: '1 minute',   value: 60 },
    { label: '5 minutes',  value: 300 },
    { label: '15 minutes', value: 900 },
    { label: '30 minutes', value: 1800 },
    { label: '1 hour',     value: 3600 },
    { label: 'Never',      value: 0 },
  ];

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-aegis-text">Settings</h1>
        <p className="text-sm text-aegis-muted">Vault and security preferences</p>
      </div>

      {/* Vault lock settings */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Clock className="w-4 h-4 text-aegis-muted" /> Auto-Lock
        </h2>
        <div>
          <label className="block text-sm text-aegis-subtle mb-2">
            Lock vault after inactivity
          </label>
          <select
            value={lockTimeout}
            onChange={(e) => setLockTimeout(Number(e.target.value))}
            className="aegis-input w-auto"
          >
            {timeoutOptions.map(({ label, value }) => (
              <option key={value} value={value}>{label}</option>
            ))}
          </select>
          {lockTimeout === 0 && (
            <p className="text-xs text-aegis-warning mt-1.5">
              ⚠️ Disabling auto-lock reduces security. Not recommended.
            </p>
          )}
        </div>
        <button onClick={savePreferences} className="aegis-btn-primary flex items-center gap-2 text-sm">
          {saved ? <><CheckCircle2 className="w-4 h-4" /> Saved</> : 'Save Changes'}
        </button>
      </section>

      {/* MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Shield className="w-4 h-4 text-aegis-muted" /> Two-Factor Authentication
        </h2>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-aegis-subtle">Authenticator App (TOTP)</p>
            <p className="text-xs text-aegis-muted mt-0.5">
              {mfaEnabled ? 'MFA is enabled on your account' : 'Add an extra layer of login security'}
            </p>
          </div>
          <div className={`text-xs px-2 py-1 rounded-full border ${mfaEnabled ? 'bg-aegis-success-muted border-aegis-success text-aegis-success' : 'bg-aegis-elevated border-aegis-border text-aegis-muted'}`}>
            {mfaEnabled ? 'Enabled' : 'Disabled'}
          </div>
        </div>
        {mfaEnabled ? (
          <button className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted">
            Disable MFA
          </button>
        ) : (
          <a href="/api/auth/mfa/setup" className="aegis-btn-primary inline-flex items-center gap-2 text-sm">
            <Key className="w-4 h-4" /> Enable MFA
          </a>
        )}
      </section>

      {/* SMS MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Phone className="w-4 h-4 text-aegis-muted" /> SMS Two-Factor Authentication
        </h2>

        {smsError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {smsError}
          </div>
        )}
        {smsSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> {smsSuccess}
          </div>
        )}

        {smsEnabled && phoneNumber ? (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-aegis-subtle">SMS MFA: Enabled</p>
                <p className="text-xs text-aegis-muted mt-0.5">{maskPhone(phoneNumber)}</p>
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showSmsDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current SMS code or account password to disable SMS MFA:
                </p>
                <input
                  type="text"
                  value={smsDisableCode}
                  onChange={(e) => setSmsDisableCode(e.target.value)}
                  placeholder="Code or password"
                  maxLength={128}
                  className="aegis-input text-sm w-full max-w-xs"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={disableSms}
                    disabled={isDisablingSms}
                    className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted flex items-center gap-2"
                  >
                    {isDisablingSms ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Confirm Disable
                  </button>
                  <button
                    onClick={() => { setShowSmsDisableForm(false); setSmsDisableCode(''); setSmsError(null); }}
                    className="text-xs text-aegis-muted hover:text-aegis-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowSmsDisableForm(true)}
                className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted"
              >
                Disable SMS MFA
              </button>
            )}
          </>
        ) : smsStep === 'verify' ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">
              A 6-digit code was sent to <span className="text-aegis-text font-medium">{smsPhoneInput}</span>.
              Enter it below to activate SMS MFA.
            </p>
            <input
              type="text"
              value={smsCodeInput}
              onChange={(e) => setSmsCodeInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              maxLength={6}
              className="aegis-input text-sm w-40 tracking-widest text-center"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={verifySmsCode}
                disabled={isVerifyingSms || smsCodeInput.length !== 6}
                className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
              >
                {isVerifyingSms ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                Verify
              </button>
              <button
                onClick={() => { setSmsStep('idle'); setSmsCodeInput(''); setSmsError(null); }}
                className="text-xs text-aegis-muted hover:text-aegis-text"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Add Phone Number</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Enter your number in E.164 format (e.g. +16025551234)
              </p>
            </div>
            <input
              type="tel"
              value={smsPhoneInput}
              onChange={(e) => setSmsPhoneInput(e.target.value)}
              placeholder="+16025551234"
              maxLength={20}
              className="aegis-input text-sm w-64"
            />
            <button
              onClick={sendSmsCode}
              disabled={isSendingCode || !smsPhoneInput.trim()}
              className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
            >
              {isSendingCode
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending…</>
                : <><Phone className="w-4 h-4" /> Send Verification Code</>}
            </button>
          </div>
        )}
      </section>

      {/* Email MFA */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Mail className="w-4 h-4 text-aegis-muted" /> Email Two-Factor Authentication
        </h2>

        {emailMfaError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {emailMfaError}
          </div>
        )}
        {emailMfaSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" /> {emailMfaSuccess}
          </div>
        )}

        {emailMfaEnabled ? (
          <>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-aegis-subtle">Email MFA: Enabled</p>
                <p className="text-xs text-aegis-muted mt-0.5">
                  A one-time code is sent to your account email during login
                </p>
              </div>
              <div className="text-xs px-2 py-1 rounded-full border bg-aegis-success-muted border-aegis-success text-aegis-success">
                Enabled
              </div>
            </div>

            {showEmailDisableForm ? (
              <div className="space-y-2">
                <p className="text-xs text-aegis-muted">
                  Enter your current email code or account password to disable Email MFA:
                </p>
                <input
                  type="text"
                  value={emailDisableCode}
                  onChange={(e) => setEmailDisableCode(e.target.value)}
                  placeholder="Code or password"
                  maxLength={128}
                  className="aegis-input text-sm w-full max-w-xs"
                />
                <div className="flex items-center gap-2">
                  <button
                    onClick={disableEmailMfa}
                    disabled={isDisablingEmail}
                    className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted flex items-center gap-2"
                  >
                    {isDisablingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                    Confirm Disable
                  </button>
                  <button
                    onClick={() => { setShowEmailDisableForm(false); setEmailDisableCode(''); setEmailMfaError(null); }}
                    className="text-xs text-aegis-muted hover:text-aegis-text"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              <button
                onClick={() => setShowEmailDisableForm(true)}
                className="aegis-btn-ghost text-sm text-aegis-danger hover:bg-aegis-danger-muted"
              >
                Disable Email MFA
              </button>
            )}
          </>
        ) : emailMfaStep === 'verify' ? (
          <div className="space-y-3">
            <p className="text-sm text-aegis-subtle">
              A 6-digit code was sent to your account email. Enter it below to activate Email MFA.
            </p>
            <input
              type="text"
              value={emailMfaCode}
              onChange={(e) => setEmailMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              maxLength={6}
              className="aegis-input text-sm w-40 tracking-widest text-center"
            />
            <div className="flex items-center gap-2">
              <button
                onClick={verifyEmailMfa}
                disabled={isVerifyingEmail || emailMfaCode.length !== 6}
                className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
              >
                {isVerifyingEmail ? <Loader2 className="w-4 h-4 animate-spin" /> : <CheckCircle2 className="w-4 h-4" />}
                Verify
              </button>
              <button
                onClick={() => { setEmailMfaStep('idle'); setEmailMfaCode(''); setEmailMfaError(null); }}
                className="text-xs text-aegis-muted hover:text-aegis-text"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <p className="text-sm text-aegis-subtle">Enable Email MFA</p>
              <p className="text-xs text-aegis-muted mt-0.5">
                Receive a one-time code at your account email during login
              </p>
            </div>
            <button
              onClick={enableEmailMfa}
              disabled={isEnablingEmail}
              className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50"
            >
              {isEnablingEmail
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Sending code…</>
                : <><Mail className="w-4 h-4" /> Enable Email MFA</>}
            </button>
          </div>
        )}
      </section>

      {/* Passkeys */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Fingerprint className="w-4 h-4 text-aegis-muted" /> Passkeys
        </h2>
        <p className="text-sm text-aegis-subtle">
          Sign in with your device biometrics or hardware security key — no password required.
        </p>

        {/* Cross-device info banner */}
        <div className="flex gap-2.5 bg-aegis-elevated border border-aegis-border rounded-lg px-3 py-2.5">
          <Smartphone className="w-4 h-4 text-aegis-muted flex-shrink-0 mt-0.5" />
          <p className="text-xs text-aegis-muted leading-relaxed">
            When adding a passkey, your browser will offer options including scanning a QR code
            with your phone. This allows you to authenticate from your phone even on a shared
            computer. You can add a passkey from this device (fingerprint / Face ID) or from
            your phone — the browser will show both options automatically.
          </p>
        </div>

        {passkeyError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" /> {passkeyError}
          </div>
        )}

        {passkeys.length > 0 && (
          <ul className="space-y-2">
            {passkeys.map((pk) => (
              <li key={pk.id} className="bg-aegis-elevated border border-aegis-border rounded-lg px-3 py-2">
                {renamingId === pk.id ? (
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') saveRename(pk.id);
                        if (e.key === 'Escape') cancelRename();
                      }}
                      maxLength={64}
                      autoFocus
                      className="aegis-input text-sm flex-1 h-7 py-0"
                    />
                    <button
                      onClick={() => saveRename(pk.id)}
                      disabled={isSavingRename || !renameValue.trim()}
                      className="text-xs text-aegis-accent hover:text-aegis-accent/80 disabled:opacity-50 flex-shrink-0"
                    >
                      {isSavingRename ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : 'Save'}
                    </button>
                    <button
                      onClick={cancelRename}
                      className="text-xs text-aegis-muted hover:text-aegis-text flex-shrink-0"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-sm text-aegis-text truncate">{pk.name}</p>
                      <p className="text-xs text-aegis-muted">
                        {pk.transports?.includes('hybrid')
                          ? 'Phone / Cross-Device'
                          : pk.deviceType === 'multiDevice'
                            ? 'Synced passkey'
                            : 'Device-bound key'}
                        {pk.backedUp && ' · backed up'}
                        {' · '}
                        {pk.lastUsedAt
                          ? `used ${formatDistanceToNow(new Date(pk.lastUsedAt), { addSuffix: true })}`
                          : `added ${formatDistanceToNow(new Date(pk.createdAt), { addSuffix: true })}`}
                      </p>
                    </div>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      <button
                        onClick={() => startRename(pk)}
                        className="p-1.5 text-aegis-muted hover:text-aegis-text transition-colors"
                        title="Rename passkey"
                      >
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => deletePasskey(pk.id)}
                        disabled={deletingPasskeyId === pk.id}
                        className="p-1.5 text-aegis-muted hover:text-aegis-danger transition-colors"
                        title="Remove passkey"
                      >
                        {deletingPasskeyId === pk.id
                          ? <Loader2 className="w-4 h-4 animate-spin" />
                          : <Trash2 className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}

        <div className="space-y-1.5">
          <button
            onClick={registerPasskey}
            disabled={isRegisteringPasskey}
            className="aegis-btn-secondary text-sm flex items-center gap-2"
          >
            {isRegisteringPasskey
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Waiting for passkey…</>
              : <><Plus className="w-4 h-4" /> Add Passkey</>}
          </button>
          {isRegisteringPasskey && (
            <p className="text-xs text-aegis-muted">
              Follow the browser prompt — you can use this device or scan the QR code with your phone.
            </p>
          )}
        </div>
      </section>

      {/* Backup & Export */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Download className="w-4 h-4 text-aegis-muted" /> Backup & Export
        </h2>
        <p className="text-sm text-aegis-subtle">
          Export an encrypted backup of your entire vault. The file is protected by
          your master password — without it, the file cannot be decrypted.
        </p>

        {exportError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            {exportError}
          </div>
        )}

        <div className="flex items-center gap-3">
          <button
            onClick={handleExport}
            disabled={isLocked || isExporting}
            className="aegis-btn-primary text-sm flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            title={isLocked ? 'Unlock vault to export' : 'Export encrypted vault'}
          >
            {isExporting
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Exporting…</>
              : <><Download className="w-4 h-4" /> Export Encrypted Vault</>}
          </button>
          {isLocked && <p className="text-xs text-aegis-muted">Unlock vault to export</p>}
        </div>
      </section>

      {/* Import */}
      <section className="aegis-card space-y-4">
        <h2 className="text-sm font-semibold text-aegis-text flex items-center gap-2">
          <Upload className="w-4 h-4 text-aegis-muted" /> Import
        </h2>
        <p className="text-sm text-aegis-subtle">
          Import a <code className="text-xs font-mono bg-aegis-elevated px-1 py-0.5 rounded">.aegisvault</code> backup
          file. Items are decrypted and re-encrypted with your current vault key before storage.
        </p>

        {importError && (
          <div className="flex items-center gap-2 text-xs text-aegis-danger bg-aegis-danger-muted border border-aegis-danger/30 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            {importError}
          </div>
        )}
        {importSuccess && (
          <div className="flex items-center gap-2 text-xs text-aegis-success bg-aegis-success-muted border border-aegis-success/30 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
            {importSuccess}
          </div>
        )}

        <div className="flex items-center gap-3">
          <input
            ref={importFileRef}
            type="file"
            accept=".aegisvault,application/json"
            onChange={handleImportFile}
            disabled={isLocked || isImporting}
            className="hidden"
            id="import-file-input"
          />
          <label
            htmlFor="import-file-input"
            className={`aegis-btn-secondary text-sm flex items-center gap-2 cursor-pointer ${isLocked || isImporting ? 'opacity-50 cursor-not-allowed pointer-events-none' : ''}`}
            title={isLocked ? 'Unlock vault to import' : 'Select .aegisvault file'}
          >
            {isImporting
              ? <><Loader2 className="w-4 h-4 animate-spin" /> Importing…</>
              : <><Upload className="w-4 h-4" /> Select .aegisvault File</>}
          </label>
          {isLocked && <p className="text-xs text-aegis-muted">Unlock vault to import</p>}
        </div>
      </section>

      {/* Danger zone */}
      <section className="aegis-card border-aegis-danger/30 space-y-4">
        <h2 className="text-sm font-semibold text-aegis-danger flex items-center gap-2">
          <Trash2 className="w-4 h-4" /> Danger Zone
        </h2>
        <div>
          <p className="text-sm text-aegis-subtle mb-2">Delete Account</p>
          <p className="text-xs text-aegis-muted mb-3">
            Permanently deletes your account and all encrypted vault data. This cannot be undone.
          </p>
          <button className="aegis-btn-ghost text-aegis-danger hover:bg-aegis-danger-muted text-sm border border-aegis-danger/30">
            Delete Account Permanently
          </button>
        </div>
      </section>
    </div>
  );
}
