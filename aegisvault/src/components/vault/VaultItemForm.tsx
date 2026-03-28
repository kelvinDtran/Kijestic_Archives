'use client';

/**
 * VaultItemForm — Create/Edit vault item form
 * Handles all item types with appropriate fields.
 * Encrypts data client-side before sending to server.
 */

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Plus, Trash2, Eye, EyeOff, AlertTriangle, Wand2 } from 'lucide-react';
import { CryptoWarning } from './CryptoWarning';
import { PasswordGenerator } from './PasswordGenerator';
import type { ItemType, VaultItemFormData } from '@/types/vault';
import { ITEM_TYPE_LABELS } from '@/lib/utils';

const FormSchema = z.object({
  title:       z.string().min(1, 'Title is required').max(200),
  itemType:    z.string(),
  isFavorite:  z.boolean().default(false),
  isHighRisk:  z.boolean().default(false),
  website:     z.string().max(500).optional(),
  username:    z.string().max(200).optional(),
  email:       z.string().email().optional().or(z.literal('')),
  password:    z.string().max(1000).optional(),
  url:         z.string().url().optional().or(z.literal('')),
  notes:       z.string().max(10000).optional(),
  tags:        z.string().max(200).optional(),
  // Crypto fields
  seedPhrase:  z.string().max(1000).optional(),
  privateKey:  z.string().max(1000).optional(),
  walletAddress: z.string().max(200).optional(),
  // API Key fields
  apiKeyValue: z.string().max(1000).optional(),
  apiKeyName:  z.string().max(200).optional(),
  // Recovery codes
  recoveryCodes: z.string().max(5000).optional(),
});

type FormValues = z.infer<typeof FormSchema>;

interface VaultItemFormProps {
  onSubmit: (data: VaultItemFormData) => Promise<void>;
  onCancel: () => void;
  initialValues?: Partial<FormValues & { itemType: ItemType }>;
  isEditing?: boolean;
}

export function VaultItemForm({ onSubmit, onCancel, initialValues, isEditing }: VaultItemFormProps) {
  const [showPassword, setShowPassword] = useState(false);
  const [showPasswordGenerator, setShowPasswordGenerator] = useState(false);
  const [showHighRiskWarning, setShowHighRiskWarning] = useState(false);
  const [pendingHighRisk, setPendingHighRisk] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [customFields, setCustomFields] = useState<Array<{ id: string; key: string; value: string; isSecret: boolean }>>([]);

  const { register, handleSubmit, watch, setValue, formState: { errors } } = useForm<FormValues>({
    resolver: zodResolver(FormSchema),
    defaultValues: {
      itemType:   initialValues?.itemType ?? 'PASSWORD',
      isFavorite: initialValues?.isFavorite ?? false,
      isHighRisk: initialValues?.isHighRisk ?? false,
      ...initialValues,
    },
  });

  const watchedType     = watch('itemType') as ItemType;
  const watchedHighRisk = watch('isHighRisk');

  const handleHighRiskToggle = (checked: boolean) => {
    if (checked && !isEditing) {
      setPendingHighRisk(true);
      setShowHighRiskWarning(true);
    } else {
      setValue('isHighRisk', checked);
    }
  };

  const handleWarningAcknowledge = () => {
    setValue('isHighRisk', true);
    setShowHighRiskWarning(false);
    setPendingHighRisk(false);
  };

  const processSubmit = async (values: FormValues) => {
    setIsSubmitting(true);
    try {
      const tags = values.tags
        ? values.tags.split(',').map((t) => t.trim()).filter(Boolean)
        : [];

      const formData: VaultItemFormData = {
        itemType:   values.itemType as ItemType,
        isFavorite: values.isFavorite,
        isHighRisk: values.isHighRisk,
        data: {
          title:      values.title,
          website:    values.website,
          username:   values.username,
          email:      values.email,
          password:   values.password,
          url:        values.url,
          notes:      values.notes,
          tags,
          customFields,
          riskLevel:  values.isHighRisk ? 'high-risk' : 'normal',
          // Crypto fields
          ...(watchedType === 'CRYPTO' && {
            seedPhrase:    values.seedPhrase,
            privateKey:    values.privateKey,
            walletAddress: values.walletAddress,
          }),
          // API key fields
          ...(watchedType === 'API_KEY' && {
            apiKeyValue: values.apiKeyValue,
            apiKeyName:  values.apiKeyName,
          }),
          // Recovery codes
          ...(watchedType === 'RECOVERY_CODE' && {
            recoveryCodes: values.recoveryCodes
              ? values.recoveryCodes.split('\n').map((c) => c.trim()).filter(Boolean)
              : [],
          }),
        },
      };

      await onSubmit(formData);
    } finally {
      setIsSubmitting(false);
    }
  };

  const addCustomField = () => {
    setCustomFields((f) => [...f, { id: Math.random().toString(36).slice(2), key: '', value: '', isSecret: false }]);
  };

  return (
    <>
      <form onSubmit={handleSubmit(processSubmit)} className="space-y-4">
        {/* Item type */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs text-aegis-muted mb-1.5">Type</label>
            <select {...register('itemType')} className="aegis-input text-sm">
              {Object.entries(ITEM_TYPE_LABELS).map(([value, label]) => (
                <option key={value} value={value}>{label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs text-aegis-muted mb-1.5">Title *</label>
            <input {...register('title')} className="aegis-input text-sm" placeholder="e.g. GitHub Account" />
            {errors.title && <p className="text-xs text-aegis-danger mt-1">{errors.title.message}</p>}
          </div>
        </div>

        {/* Common fields */}
        {['PASSWORD', 'API_KEY', 'CRYPTO'].includes(watchedType) && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">Website / Service</label>
              <input {...register('website')} className="aegis-input text-sm" placeholder="github.com" />
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">URL</label>
              <input {...register('url')} className="aegis-input text-sm" placeholder="https://..." />
            </div>
          </div>
        )}

        {watchedType === 'PASSWORD' && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-aegis-muted mb-1.5">Username</label>
                <input {...register('username')} className="aegis-input text-sm" autoComplete="off" />
              </div>
              <div>
                <label className="block text-xs text-aegis-muted mb-1.5">Email</label>
                <input {...register('email')} type="email" className="aegis-input text-sm" autoComplete="off" />
              </div>
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">Password</label>
              <div className="relative">
                <input
                  {...register('password')}
                  type={showPassword ? 'text' : 'password'}
                  className="aegis-input text-sm font-mono pr-16"
                  autoComplete="off"
                  spellCheck={false}
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  <button type="button" onClick={() => setShowPasswordGenerator((v) => !v)}
                    className="p-1 text-aegis-muted hover:text-aegis-primary transition-colors"
                    title="Generate password">
                    <Wand2 className="w-3.5 h-3.5" />
                  </button>
                  <button type="button" onClick={() => setShowPassword((v) => !v)}
                    className="p-1 text-aegis-muted hover:text-aegis-text transition-colors">
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {showPasswordGenerator && (
                  <PasswordGenerator
                    onUse={(pwd) => setValue('password', pwd)}
                    onClose={() => setShowPasswordGenerator(false)}
                  />
                )}
              </div>
            </div>
          </>
        )}

        {watchedType === 'API_KEY' && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">API Key Name</label>
              <input {...register('apiKeyName')} className="aegis-input text-sm" placeholder="Production API Key" />
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">API Key Value</label>
              <input {...register('apiKeyValue')} type="password" className="aegis-input text-sm font-mono" autoComplete="off" />
            </div>
          </div>
        )}

        {watchedType === 'CRYPTO' && (
          <div className="space-y-3">
            <div className="bg-aegis-highrisk-muted border border-aegis-highrisk/30 rounded-aegis px-3 py-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-aegis-highrisk shrink-0" />
              <p className="text-xs text-aegis-subtle">Crypto secrets carry extreme risk. Consider hardware wallet storage.</p>
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">Wallet Address (public — safe to store)</label>
              <input {...register('walletAddress')} className="aegis-input text-sm font-mono" />
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">Seed Phrase / Mnemonic ⚠️</label>
              <textarea {...register('seedPhrase')} rows={3}
                className="aegis-input text-sm font-mono resize-none" autoComplete="off" spellCheck={false} />
            </div>
            <div>
              <label className="block text-xs text-aegis-muted mb-1.5">Private Key ⚠️</label>
              <input {...register('privateKey')} type="password" className="aegis-input text-sm font-mono" autoComplete="off" />
            </div>
          </div>
        )}

        {watchedType === 'RECOVERY_CODE' && (
          <div>
            <label className="block text-xs text-aegis-muted mb-1.5">Recovery Codes (one per line)</label>
            <textarea {...register('recoveryCodes')} rows={6}
              className="aegis-input text-sm font-mono resize-none" autoComplete="off" spellCheck={false} />
          </div>
        )}

        {/* Notes */}
        <div>
          <label className="block text-xs text-aegis-muted mb-1.5">Notes</label>
          <textarea {...register('notes')} rows={3} className="aegis-input text-sm resize-none" />
        </div>

        {/* Tags */}
        <div>
          <label className="block text-xs text-aegis-muted mb-1.5">Tags (comma-separated)</label>
          <input {...register('tags')} className="aegis-input text-sm" placeholder="work, personal, crypto" />
        </div>

        {/* Custom fields */}
        {customFields.length > 0 && (
          <div className="space-y-2">
            <label className="block text-xs text-aegis-muted">Custom Fields</label>
            {customFields.map((field, i) => (
              <div key={field.id} className="flex gap-2">
                <input
                  value={field.key}
                  onChange={(e) => setCustomFields((f) => f.map((x, idx) => idx === i ? { ...x, key: e.target.value } : x))}
                  className="aegis-input text-sm flex-1" placeholder="Field name"
                />
                <input
                  value={field.value}
                  onChange={(e) => setCustomFields((f) => f.map((x, idx) => idx === i ? { ...x, value: e.target.value } : x))}
                  type={field.isSecret ? 'password' : 'text'}
                  className="aegis-input text-sm flex-1 font-mono" placeholder="Value"
                />
                <button type="button" onClick={() => setCustomFields((f) => f.filter((_, idx) => idx !== i))}
                  className="text-aegis-muted hover:text-aegis-danger">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            ))}
          </div>
        )}

        <button type="button" onClick={addCustomField}
          className="flex items-center gap-1.5 text-xs text-aegis-muted hover:text-aegis-primary transition-colors">
          <Plus className="w-3.5 h-3.5" /> Add custom field
        </button>

        {/* Flags */}
        <div className="flex items-center gap-6 pt-2 border-t border-aegis-border">
          <label className="flex items-center gap-2 cursor-pointer text-sm text-aegis-subtle">
            <input type="checkbox" {...register('isFavorite')} className="rounded border-aegis-border" />
            Favorite
          </label>
          <label className="flex items-center gap-2 cursor-pointer text-sm">
            <input
              type="checkbox"
              checked={watchedHighRisk}
              onChange={(e) => handleHighRiskToggle(e.target.checked)}
              className="rounded border-aegis-border"
            />
            <span className={watchedHighRisk ? 'text-aegis-highrisk' : 'text-aegis-subtle'}>
              High-Risk Secret
            </span>
          </label>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-2">
          <button type="button" onClick={onCancel} className="aegis-btn-ghost flex-1">Cancel</button>
          <button type="submit" disabled={isSubmitting} className="aegis-btn-primary flex-1">
            {isSubmitting ? (
              <span className="flex items-center justify-center gap-2">
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Encrypting…
              </span>
            ) : isEditing ? 'Save Changes' : 'Add to Vault'}
          </button>
        </div>
      </form>

      {showHighRiskWarning && (
        <CryptoWarning
          action="store"
          onAcknowledge={handleWarningAcknowledge}
          onCancel={() => { setShowHighRiskWarning(false); setPendingHighRisk(false); }}
        />
      )}
    </>
  );
}
