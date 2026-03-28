'use client';

import { useMemo } from 'react';
import Link from 'next/link';
import { Shield, Key, Star, AlertTriangle, Clock, Plus, Vault } from 'lucide-react';
import { useVaultItems } from '@/hooks/useVaultItems';
import { useVault } from '@/contexts/VaultContext';
import { ITEM_TYPE_LABELS, ITEM_TYPE_ICONS, formatRelativeTime } from '@/lib/utils';

export default function DashboardPage() {
  const { isLocked } = useVault();
  const { items, isLoading } = useVaultItems();

  const stats = useMemo(() => ({
    total:      items.length,
    favorites:  items.filter((i) => i.isFavorite).length,
    highRisk:   items.filter((i) => i.isHighRisk).length,
    crypto:     items.filter((i) => i.itemType === 'CRYPTO').length,
    recentItems: [...items]
      .sort((a, b) => b.updatedAt.getTime() - a.updatedAt.getTime())
      .slice(0, 5),
    byType: Object.entries(
      items.reduce((acc, i) => {
        acc[i.itemType] = (acc[i.itemType] ?? 0) + 1;
        return acc;
      }, {} as Record<string, number>),
    ).sort((a, b) => b[1] - a[1]),
  }), [items]);

  if (isLocked) {
    return (
      <div className="max-w-lg mx-auto pt-16 text-center">
        <div className="w-16 h-16 rounded-full bg-aegis-primary-muted flex items-center justify-center mx-auto mb-4">
          <Shield className="w-8 h-8 text-aegis-primary" />
        </div>
        <h1 className="text-xl font-semibold text-aegis-text mb-2">Welcome back</h1>
        <p className="text-aegis-muted text-sm">Enter your master password to unlock your vault and access your secrets.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-aegis-text">Dashboard</h1>
          <p className="text-sm text-aegis-muted">Your vault overview</p>
        </div>
        <Link href="/vault" className="aegis-btn-primary flex items-center gap-2 text-sm">
          <Plus className="w-4 h-4" /> Add Secret
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Total Secrets', value: stats.total,     icon: Vault,         color: 'text-aegis-primary' },
          { label: 'Favorites',     value: stats.favorites, icon: Star,          color: 'text-yellow-400' },
          { label: 'High-Risk',     value: stats.highRisk,  icon: AlertTriangle, color: 'text-aegis-highrisk' },
          { label: 'Crypto Items',  value: stats.crypto,    icon: Key,           color: 'text-aegis-success' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="aegis-card">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-aegis-muted">{label}</span>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <div className="text-2xl font-semibold text-aegis-text">
              {isLoading ? '…' : value}
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent items */}
        <div className="lg:col-span-2 aegis-card">
          <h2 className="text-sm font-medium text-aegis-text mb-3 flex items-center gap-2">
            <Clock className="w-4 h-4 text-aegis-muted" /> Recently Updated
          </h2>
          {isLoading ? (
            <div className="space-y-2">
              {[...Array(3)].map((_, i) => <div key={i} className="h-10 bg-aegis-elevated rounded-aegis animate-pulse" />)}
            </div>
          ) : stats.recentItems.length === 0 ? (
            <div className="text-center py-6">
              <p className="text-sm text-aegis-muted mb-2">No secrets yet</p>
              <Link href="/vault" className="text-aegis-primary text-sm hover:underline">Add your first secret →</Link>
            </div>
          ) : (
            <div className="space-y-1">
              {stats.recentItems.map((item) => (
                <Link key={item.id} href="/vault"
                  className="flex items-center gap-3 px-3 py-2 rounded-aegis hover:bg-aegis-elevated transition-colors">
                  <span className="text-base">{ITEM_TYPE_ICONS[item.itemType]}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-aegis-text truncate">{item.data.title}</p>
                    {item.data.website && (
                      <p className="text-xs text-aegis-muted truncate">{item.data.website}</p>
                    )}
                  </div>
                  <span className="text-xs text-aegis-muted shrink-0">{formatRelativeTime(item.updatedAt)}</span>
                  {item.isHighRisk && <AlertTriangle className="w-3 h-3 text-aegis-highrisk shrink-0" />}
                </Link>
              ))}
            </div>
          )}
        </div>

        {/* By type */}
        <div className="aegis-card">
          <h2 className="text-sm font-medium text-aegis-text mb-3">By Type</h2>
          {isLoading ? (
            <div className="space-y-2">
              {[...Array(4)].map((_, i) => <div key={i} className="h-6 bg-aegis-elevated rounded animate-pulse" />)}
            </div>
          ) : stats.byType.length === 0 ? (
            <p className="text-sm text-aegis-muted">None yet</p>
          ) : (
            <div className="space-y-2">
              {stats.byType.map(([type, count]) => (
                <div key={type} className="flex items-center gap-2">
                  <span className="text-sm">{ITEM_TYPE_ICONS[type]}</span>
                  <span className="text-sm text-aegis-subtle flex-1">{ITEM_TYPE_LABELS[type]}</span>
                  <span className="text-sm font-medium text-aegis-text">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Security reminder */}
      <div className="mt-4 flex items-start gap-3 bg-aegis-elevated border border-aegis-border rounded-aegis-lg px-4 py-3">
        <Shield className="w-4 h-4 text-aegis-primary shrink-0 mt-0.5" />
        <div className="text-xs text-aegis-muted leading-relaxed">
          <strong className="text-aegis-subtle">Zero-knowledge encryption active.</strong>{' '}
          All secrets are encrypted locally with your master password before storage.
          The server cannot read your vault contents.
        </div>
      </div>
    </div>
  );
}
