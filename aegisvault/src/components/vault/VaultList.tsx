'use client';

import { useState } from 'react';
import { Star, Archive, Trash2, Edit2, Clock, AlertTriangle, Copy } from 'lucide-react';
import { useClipboard } from '@/hooks/useClipboard';
import { HighRiskBadge } from './CryptoWarning';
import { cn, ITEM_TYPE_LABELS, ITEM_TYPE_ICONS, formatRelativeTime } from '@/lib/utils';
import type { DecryptedVaultItem } from '@/types/vault';

interface VaultListProps {
  items:           DecryptedVaultItem[];
  onSelect:        (item: DecryptedVaultItem) => void;
  onEdit:          (item: DecryptedVaultItem) => void;
  onDelete:        (id: string) => Promise<void>;
  onToggleFavorite: (id: string) => Promise<void>;
  onArchive:       (id: string, archived: boolean) => Promise<void>;
  isLoading:       boolean;
}

export function VaultList({
  items, onSelect, onEdit, onDelete, onToggleFavorite, onArchive, isLoading,
}: VaultListProps) {
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const { copyToClipboard, copied } = useClipboard();

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm('Permanently delete this vault item? This cannot be undone.')) return;
    setDeletingId(id);
    await onDelete(id).finally(() => setDeletingId(null));
  };

  if (isLoading) {
    return (
      <div className="space-y-2">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-16 bg-aegis-surface rounded-aegis-lg animate-pulse" />
        ))}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="text-center py-16">
        <div className="text-4xl mb-3">🔒</div>
        <h3 className="text-base font-medium text-aegis-subtle mb-1">No items found</h3>
        <p className="text-sm text-aegis-muted">Add your first secret to get started</p>
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      {items.map((item) => (
        <div
          key={item.id}
          onClick={() => onSelect(item)}
          className={cn(
            'group flex items-center gap-3 px-4 py-3 bg-aegis-surface hover:bg-aegis-elevated border border-aegis-border hover:border-aegis-border-hover rounded-aegis-lg cursor-pointer transition-colors',
            item.isHighRisk && 'border-aegis-highrisk/30 hover:border-aegis-highrisk/50',
          )}
        >
          {/* Icon */}
          <div className="text-xl shrink-0 w-8 text-center select-none">
            {ITEM_TYPE_ICONS[item.itemType] ?? '📦'}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="text-sm font-medium text-aegis-text truncate">
                {item.data.title}
              </span>
              {item.isHighRisk && <HighRiskBadge />}
              {item.isFavorite && (
                <Star className="w-3 h-3 text-yellow-400 fill-yellow-400 shrink-0" />
              )}
            </div>
            <div className="flex items-center gap-2 text-xs text-aegis-muted">
              <span className="bg-aegis-elevated px-1.5 py-0.5 rounded text-aegis-muted text-xs">
                {ITEM_TYPE_LABELS[item.itemType]}
              </span>
              {item.data.website && (
                <span className="truncate">{item.data.website}</span>
              )}
              {item.data.username && (
                <span className="truncate">· {item.data.username}</span>
              )}
              <span className="ml-auto flex items-center gap-1 shrink-0">
                <Clock className="w-3 h-3" />
                {formatRelativeTime(item.updatedAt)}
              </span>
            </div>
          </div>

          {/* Actions (shown on hover) */}
          <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
            {/* Quick copy password */}
            {item.data.password && (
              <button
                onClick={(e) => { e.stopPropagation(); copyToClipboard(item.data.password!); }}
                className="w-7 h-7 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-primary hover:bg-aegis-elevated"
                title="Copy password"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            )}
            {/* Favorite toggle */}
            <button
              onClick={(e) => { e.stopPropagation(); onToggleFavorite(item.id); }}
              className={cn(
                'w-7 h-7 rounded-aegis flex items-center justify-center transition-colors',
                item.isFavorite
                  ? 'text-yellow-400'
                  : 'text-aegis-muted hover:text-yellow-400 hover:bg-aegis-elevated',
              )}
              title={item.isFavorite ? 'Unfavorite' : 'Favorite'}
            >
              <Star className={cn('w-3.5 h-3.5', item.isFavorite && 'fill-yellow-400')} />
            </button>
            {/* Edit */}
            <button
              onClick={(e) => { e.stopPropagation(); onEdit(item); }}
              className="w-7 h-7 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-primary hover:bg-aegis-elevated"
              title="Edit"
            >
              <Edit2 className="w-3.5 h-3.5" />
            </button>
            {/* Archive */}
            <button
              onClick={(e) => { e.stopPropagation(); onArchive(item.id, !item.isArchived); }}
              className="w-7 h-7 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-subtle hover:bg-aegis-elevated"
              title={item.isArchived ? 'Unarchive' : 'Archive'}
            >
              <Archive className="w-3.5 h-3.5" />
            </button>
            {/* Delete */}
            <button
              onClick={(e) => handleDelete(item.id, e)}
              disabled={deletingId === item.id}
              className="w-7 h-7 rounded-aegis flex items-center justify-center text-aegis-muted hover:text-aegis-danger hover:bg-aegis-danger-muted"
              title="Delete"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}
