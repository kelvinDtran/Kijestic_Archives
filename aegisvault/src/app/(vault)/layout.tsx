'use client';

import { useState, useEffect } from 'react';
import { VaultProvider, useVault } from '@/contexts/VaultContext';
import { useVaultLock } from '@/hooks/useVaultLock';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { VaultUnlockModal } from '@/components/layout/VaultUnlockModal';
import type { KdfParams } from '@/types/vault';

function VaultLayoutInner({ children }: { children: React.ReactNode }) {
  const { isLocked, lock } = useVault();
  const [lockTimeout, setLockTimeout] = useState(300);

  // Load lock timeout preference
  useEffect(() => {
    fetch('/api/account/preferences', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => { if (d.data?.lockTimeout) setLockTimeout(d.data.lockTimeout); })
      .catch(() => {});
  }, []);

  // Inactivity auto-lock
  useVaultLock({
    timeoutSeconds: lockTimeout,
    onLock:         lock,
    isUnlocked:     !isLocked,
  });

  return (
    <div className="flex h-screen overflow-hidden bg-aegis-bg">
      {/* Sidebar navigation */}
      <Sidebar />

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>

      {/* Vault lock overlay — shown when vault is locked */}
      {isLocked && <VaultUnlockModal />}
    </div>
  );
}

// Wrapper that fetches KDF params before rendering the vault
export default function VaultLayout({ children }: { children: React.ReactNode }) {
  const [kdfParams, setKdfParams] = useState<KdfParams | null>(null);
  const [error, setError]         = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/kdf/salt', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => {
        if (d.success) {
          setKdfParams({
            salt:        d.data.salt,
            version:     d.data.version,
            memory:      d.data.memory,
            iterations:  d.data.iterations,
            parallelism: d.data.parallelism,
          });
        } else {
          setError('Failed to load vault configuration');
        }
      })
      .catch(() => setError('Network error loading vault'));
  }, []);

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-aegis-bg">
        <div className="text-center">
          <p className="text-aegis-danger mb-2">{error}</p>
          <button onClick={() => window.location.reload()} className="aegis-btn-ghost text-sm">
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (!kdfParams) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-aegis-bg">
        <div className="w-6 h-6 border-2 border-aegis-border border-t-aegis-primary rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <VaultProvider kdfParams={kdfParams}>
      <VaultLayoutInner>{children}</VaultLayoutInner>
    </VaultProvider>
  );
}
