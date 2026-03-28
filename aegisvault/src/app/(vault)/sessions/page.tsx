'use client';

import { useEffect, useState } from 'react';
import { Monitor, Trash2, LogOut, RefreshCw } from 'lucide-react';
import { formatRelativeTime } from '@/lib/utils';

interface SessionInfo {
  id:         string;
  userAgent:  string | null;
  lastUsedAt: string;
  createdAt:  string;
  expiresAt:  string;
  isCurrent:  boolean;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [revoking, setRevoking]   = useState<string | null>(null);

  const fetchSessions = async () => {
    setIsLoading(true);
    const res = await fetch('/api/sessions', { credentials: 'include' });
    const data = await res.json();
    if (data.success) setSessions(data.data.sessions);
    setIsLoading(false);
  };

  useEffect(() => { fetchSessions(); }, []);

  const revokeSession = async (id: string) => {
    setRevoking(id);
    await fetch(`/api/sessions/${id}`, { method: 'DELETE', credentials: 'include' });
    await fetchSessions();
    setRevoking(null);
  };

  const revokeAll = async () => {
    if (!confirm('Sign out from all other devices?')) return;
    await fetch('/api/sessions', { method: 'DELETE', credentials: 'include' });
    await fetchSessions();
  };

  const parseUserAgent = (ua: string | null): string => {
    if (!ua) return 'Unknown device';
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Edge')) return 'Edge';
    return ua.slice(0, 50);
  };

  return (
    <div className="max-w-2xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-aegis-text">Active Sessions</h1>
          <p className="text-sm text-aegis-muted">Manage where you're signed in</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchSessions} className="w-8 h-8 rounded-aegis bg-aegis-elevated border border-aegis-border flex items-center justify-center text-aegis-muted hover:text-aegis-primary">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={revokeAll} className="aegis-btn-ghost flex items-center gap-1.5 text-sm text-aegis-danger hover:bg-aegis-danger-muted">
            <LogOut className="w-4 h-4" /> Revoke All
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <div key={i} className="h-16 bg-aegis-surface rounded-aegis-lg animate-pulse" />)}
        </div>
      ) : (
        <div className="space-y-2">
          {sessions.map((session) => (
            <div key={session.id}
              className={`aegis-card flex items-center gap-3 ${session.isCurrent ? 'border-aegis-primary/30' : ''}`}>
              <div className="w-9 h-9 rounded-full bg-aegis-elevated flex items-center justify-center shrink-0">
                <Monitor className="w-4 h-4 text-aegis-muted" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-medium text-aegis-text">
                    {parseUserAgent(session.userAgent)}
                  </p>
                  {session.isCurrent && (
                    <span className="text-xs bg-aegis-primary-muted text-aegis-primary px-1.5 py-0.5 rounded-full">
                      Current
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs text-aegis-muted mt-0.5">
                  <span>Last active {formatRelativeTime(session.lastUsedAt)}</span>
                  <span>·</span>
                  <span>Created {formatRelativeTime(session.createdAt)}</span>
                </div>
              </div>
              {!session.isCurrent && (
                <button
                  onClick={() => revokeSession(session.id)}
                  disabled={revoking === session.id}
                  className="w-8 h-8 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-danger hover:bg-aegis-danger-muted transition-colors"
                  title="Revoke this session"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
