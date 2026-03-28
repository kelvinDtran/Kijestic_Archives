'use client';

import { useState, useEffect, useCallback } from 'react';
import { Shield, RefreshCw, ChevronDown, Loader2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

// Human-readable labels and color classes for each audit event type
const EVENT_META: Record<string, { label: string; color: string }> = {
  AUTH_REGISTER:                 { label: 'Account registered',        color: 'text-aegis-success' },
  AUTH_LOGIN_SUCCESS:            { label: 'Signed in',                 color: 'text-aegis-success' },
  AUTH_LOGIN_FAILED:             { label: 'Failed sign-in attempt',    color: 'text-aegis-danger' },
  AUTH_LOGOUT:                   { label: 'Signed out',                color: 'text-aegis-muted' },
  AUTH_ALL_SESSIONS_REVOKED:     { label: 'All sessions revoked',      color: 'text-aegis-warning' },
  AUTH_SESSION_REVOKED:          { label: 'Session revoked',           color: 'text-aegis-warning' },
  AUTH_PASSWORD_CHANGED:         { label: 'Password changed',          color: 'text-aegis-warning' },
  AUTH_MFA_ENABLED:              { label: 'MFA enabled',               color: 'text-aegis-success' },
  AUTH_MFA_DISABLED:             { label: 'MFA disabled',              color: 'text-aegis-warning' },
  AUTH_MFA_CHALLENGE_SUCCESS:    { label: 'MFA verified',              color: 'text-aegis-success' },
  AUTH_MFA_CHALLENGE_FAILED:     { label: 'MFA verification failed',   color: 'text-aegis-danger' },
  AUTH_WEBAUTHN_REGISTERED:      { label: 'Passkey added',             color: 'text-aegis-success' },
  AUTH_WEBAUTHN_REMOVED:         { label: 'Passkey removed',           color: 'text-aegis-warning' },
  AUTH_WEBAUTHN_CHALLENGE_SUCCESS: { label: 'Signed in with passkey',  color: 'text-aegis-success' },
  VAULT_UNLOCKED:                { label: 'Vault unlocked',            color: 'text-aegis-muted' },
  VAULT_ITEM_CREATED:            { label: 'Item added',                color: 'text-aegis-text' },
  VAULT_ITEM_UPDATED:            { label: 'Item updated',              color: 'text-aegis-text' },
  VAULT_ITEM_DELETED:            { label: 'Item deleted',              color: 'text-aegis-warning' },
  VAULT_ITEM_ARCHIVED:           { label: 'Item archived',             color: 'text-aegis-muted' },
  VAULT_FILE_UPLOADED:           { label: 'File uploaded',             color: 'text-aegis-text' },
  VAULT_FILE_DELETED:            { label: 'File deleted',              color: 'text-aegis-warning' },
  VAULT_EXPORTED:                { label: 'Vault exported',            color: 'text-aegis-warning' },
  VAULT_IMPORTED:                { label: 'Vault imported',            color: 'text-aegis-warning' },
  ACCOUNT_SETTINGS_UPDATED:      { label: 'Settings updated',          color: 'text-aegis-text' },
  SUSPICIOUS_ACTIVITY:           { label: 'Suspicious activity',       color: 'text-aegis-danger' },
};

interface AuditEntry {
  id:            string;
  event:         string;
  createdAt:     string;
  metadata:      Record<string, unknown> | null;
  userAgentHint: string | null;
}

function EventBadge({ event }: { event: string }) {
  const meta = EVENT_META[event] ?? { label: event, color: 'text-aegis-muted' };
  return (
    <span className={`text-sm font-medium ${meta.color}`}>
      {meta.label}
    </span>
  );
}

function MetadataHints({ metadata, userAgentHint }: { metadata: Record<string, unknown> | null; userAgentHint: string | null }) {
  if (!metadata && !userAgentHint) return null;

  const hints: string[] = [];
  if (metadata?.itemType)    hints.push(String(metadata.itemType));
  if (metadata?.itemCount)   hints.push(`${metadata.itemCount} items`);
  if (metadata?.mfa)         hints.push('with MFA');
  if (metadata?.reason)      hints.push(String(metadata.reason).replace(/_/g, ' '));
  if (metadata?.encryptedSize) hints.push(`${Math.round(Number(metadata.encryptedSize) / 1024)} KB`);
  if (userAgentHint)         hints.push(userAgentHint.slice(0, 30) + (userAgentHint.length > 30 ? '…' : ''));

  if (hints.length === 0) return null;

  return (
    <span className="text-xs text-aegis-muted ml-2">
      {hints.join(' · ')}
    </span>
  );
}

export default function AuditLogPage() {
  const [logs, setLogs]         = useState<AuditEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError]       = useState<string | null>(null);
  const [limit, setLimit]       = useState(50);
  const [hasMore, setHasMore]   = useState(false);

  const fetchLogs = useCallback(async (fetchLimit: number) => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/audit?limit=${fetchLimit + 1}`, { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch audit log');
      const { data } = await res.json();
      const all: AuditEntry[] = data.logs;
      setHasMore(all.length > fetchLimit);
      setLogs(all.slice(0, fetchLimit));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLogs(limit);
  }, [fetchLogs, limit]);

  const loadMore = () => setLimit((prev) => prev + 50);

  return (
    <div className="max-w-2xl space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-aegis-text flex items-center gap-2">
            <Shield className="w-5 h-5 text-aegis-muted" />
            Security Audit Log
          </h1>
          <p className="text-sm text-aegis-muted mt-0.5">
            Security events for your account. Sensitive values are never logged.
          </p>
        </div>
        <button
          onClick={() => fetchLogs(limit)}
          disabled={isLoading}
          className="p-2 rounded-aegis text-aegis-muted hover:text-aegis-text hover:bg-aegis-elevated transition-colors"
          title="Refresh"
        >
          {isLoading
            ? <Loader2 className="w-4 h-4 animate-spin" />
            : <RefreshCw className="w-4 h-4" />}
        </button>
      </div>

      {error && (
        <div className="aegis-card border-aegis-danger/30 text-sm text-aegis-danger">
          {error}
        </div>
      )}

      {/* Log entries */}
      {logs.length === 0 && !isLoading ? (
        <div className="aegis-card text-center py-12 text-aegis-muted text-sm">
          No audit events found.
        </div>
      ) : (
        <div className="aegis-card p-0 overflow-hidden divide-y divide-aegis-border">
          {logs.map((log) => (
            <div key={log.id} className="flex items-start justify-between gap-4 px-4 py-3">
              <div className="flex flex-col gap-0.5 min-w-0">
                <div className="flex items-center flex-wrap gap-x-1">
                  <EventBadge event={log.event} />
                  <MetadataHints metadata={log.metadata} userAgentHint={log.userAgentHint} />
                </div>
              </div>
              <time
                className="text-xs text-aegis-muted flex-shrink-0 mt-0.5"
                dateTime={log.createdAt}
                title={new Date(log.createdAt).toLocaleString()}
              >
                {formatDistanceToNow(new Date(log.createdAt), { addSuffix: true })}
              </time>
            </div>
          ))}

          {isLoading && (
            <div className="flex justify-center py-4">
              <Loader2 className="w-4 h-4 text-aegis-muted animate-spin" />
            </div>
          )}
        </div>
      )}

      {hasMore && !isLoading && (
        <div className="flex justify-center">
          <button
            onClick={loadMore}
            className="aegis-btn-ghost text-sm flex items-center gap-1.5"
          >
            <ChevronDown className="w-4 h-4" /> Load more
          </button>
        </div>
      )}
    </div>
  );
}
