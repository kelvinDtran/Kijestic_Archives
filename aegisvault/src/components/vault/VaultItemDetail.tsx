'use client';

import { useState } from 'react';
import { ArrowLeft, Edit2, Trash2, Star, Archive, AlertTriangle, ExternalLink } from 'lucide-react';
import { SecretField } from './SecretField';
import { HighRiskBadge } from './CryptoWarning';
import { ITEM_TYPE_LABELS, ITEM_TYPE_ICONS, formatDate, cn } from '@/lib/utils';
import type { DecryptedVaultItem } from '@/types/vault';

interface VaultItemDetailProps {
  item:     DecryptedVaultItem;
  onClose:  () => void;
  onEdit:   (item: DecryptedVaultItem) => void;
  onDelete: (id: string) => Promise<void>;
}

export function VaultItemDetail({ item, onClose, onEdit, onDelete }: VaultItemDetailProps) {
  const [isDeleting, setIsDeleting] = useState(false);

  const handleDelete = async () => {
    if (!confirm(`Delete "${item.data.title}"? This cannot be undone.`)) return;
    setIsDeleting(true);
    await onDelete(item.id).finally(() => setIsDeleting(false));
  };

  const { data } = item;

  return (
    <div className="max-w-2xl animate-fade-in">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button onClick={onClose} className="w-8 h-8 rounded-aegis bg-aegis-elevated flex items-center justify-center text-aegis-muted hover:text-aegis-text">
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-xl">{ITEM_TYPE_ICONS[item.itemType]}</span>
            <h1 className="text-xl font-semibold text-aegis-text truncate">{data.title}</h1>
            {item.isHighRisk && <HighRiskBadge />}
            {item.isFavorite && <Star className="w-4 h-4 text-yellow-400 fill-yellow-400" />}
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs bg-aegis-elevated px-1.5 py-0.5 rounded text-aegis-muted">
              {ITEM_TYPE_LABELS[item.itemType]}
            </span>
            <span className="text-xs text-aegis-muted">Updated {formatDate(item.updatedAt)}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => onEdit(item)} className="aegis-btn-ghost flex items-center gap-1.5 text-sm py-1.5">
            <Edit2 className="w-3.5 h-3.5" /> Edit
          </button>
          <button onClick={handleDelete} disabled={isDeleting} className="aegis-btn-ghost text-aegis-danger hover:bg-aegis-danger-muted py-1.5 text-sm flex items-center gap-1.5">
            <Trash2 className="w-3.5 h-3.5" /> Delete
          </button>
        </div>
      </div>

      {/* High risk warning */}
      {item.isHighRisk && (
        <div className="bg-aegis-highrisk-muted border border-aegis-highrisk/40 rounded-aegis px-4 py-3 mb-4 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-aegis-highrisk shrink-0 mt-0.5" />
          <p className="text-sm text-aegis-subtle">
            This item is flagged as high-risk. Handle with extreme care. Consider using a hardware wallet for long-term storage of crypto credentials.
          </p>
        </div>
      )}

      {/* Fields */}
      <div className="aegis-card space-y-5">
        {/* Website / URL */}
        {(data.website || data.url) && (
          <div className="flex items-start gap-4">
            {data.website && (
              <div className="flex-1">
                <label className="block text-xs font-medium text-aegis-muted uppercase tracking-wide mb-1.5">Website</label>
                <p className="text-sm text-aegis-text">{data.website}</p>
              </div>
            )}
            {data.url && (
              <a href={data.url} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-xs text-aegis-primary hover:underline mt-5">
                Open <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        )}

        {/* Username / Email */}
        {(data.username || data.email) && (
          <div className="grid grid-cols-2 gap-4">
            {data.username && (
              <SecretField value={data.username} label="Username" autoHideAfterSeconds={0} />
            )}
            {data.email && (
              <SecretField value={data.email} label="Email" autoHideAfterSeconds={0} />
            )}
          </div>
        )}

        {/* Password */}
        {data.password && (
          <SecretField value={data.password} label="Password" />
        )}

        {/* API Key */}
        {data.apiKeyValue && (
          <SecretField value={data.apiKeyValue} label={data.apiKeyName ?? 'API Key'} />
        )}

        {/* Crypto fields */}
        {data.walletAddress && (
          <SecretField value={data.walletAddress} label="Wallet Address" autoHideAfterSeconds={0} />
        )}
        {data.seedPhrase && (
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <label className="text-xs font-medium text-aegis-highrisk uppercase tracking-wide">
                Seed Phrase ⚠️ Extreme Sensitivity
              </label>
            </div>
            <SecretField value={data.seedPhrase} label="" multiline autoHideAfterSeconds={15} />
          </div>
        )}
        {data.privateKey && (
          <SecretField value={data.privateKey} label="Private Key ⚠️" autoHideAfterSeconds={15} />
        )}

        {/* Recovery codes */}
        {data.recoveryCodes && data.recoveryCodes.length > 0 && (
          <div>
            <label className="block text-xs font-medium text-aegis-muted uppercase tracking-wide mb-2">
              Recovery Codes ({data.recoveryCodes.length})
            </label>
            <div className="grid grid-cols-2 gap-2">
              {data.recoveryCodes.map((code) => (
                <SecretField key={code} value={code} autoHideAfterSeconds={30} />
              ))}
            </div>
          </div>
        )}

        {/* Custom fields */}
        {data.customFields?.length > 0 && (
          <div className="space-y-3">
            <label className="block text-xs font-medium text-aegis-muted uppercase tracking-wide">
              Custom Fields
            </label>
            {data.customFields.map((field, i) => (
              <SecretField
                key={field.id ?? i}
                value={field.value}
                label={field.key}
                autoHideAfterSeconds={field.isSecret ? 30 : 0}
              />
            ))}
          </div>
        )}

        {/* Notes */}
        {data.notes && (
          <div>
            <label className="block text-xs font-medium text-aegis-muted uppercase tracking-wide mb-1.5">Notes</label>
            <p className="text-sm text-aegis-subtle whitespace-pre-wrap leading-relaxed">{data.notes}</p>
          </div>
        )}

        {/* Tags */}
        {data.tags && data.tags.length > 0 && (
          <div>
            <label className="block text-xs font-medium text-aegis-muted uppercase tracking-wide mb-1.5">Tags</label>
            <div className="flex flex-wrap gap-1.5">
              {data.tags.map((tag) => (
                <span key={tag} className="text-xs bg-aegis-elevated border border-aegis-border text-aegis-subtle px-2 py-0.5 rounded-full">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Metadata */}
      <div className="mt-4 text-xs text-aegis-muted flex gap-4">
        <span>Created {formatDate(item.createdAt)}</span>
        <span>Updated {formatDate(item.updatedAt)}</span>
        <span className="ml-auto font-mono text-aegis-muted/50">{item.id.slice(0, 8)}…</span>
      </div>
    </div>
  );
}
