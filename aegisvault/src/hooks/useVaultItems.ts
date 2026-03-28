'use client';

/**
 * AegisVault — Vault Items Hook
 *
 * Manages fetching, decrypting, caching, and searching vault items.
 * All decryption happens client-side in this hook.
 * The cached `items` array is decrypted data in memory — it is NOT persisted.
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { decryptVaultItem, encryptVaultItem } from '@/lib/crypto/vault-crypto';
import type {
  EncryptedVaultItem,
  DecryptedVaultItem,
  VaultItemData,
  ItemType,
  VaultFilter,
  VaultItemFormData,
} from '@/types/vault';

interface UseVaultItemsReturn {
  items:       DecryptedVaultItem[];
  isLoading:   boolean;
  error:       string | null;
  // CRUD
  fetchItems:  () => Promise<void>;
  createItem:  (formData: VaultItemFormData) => Promise<DecryptedVaultItem>;
  updateItem:  (id: string, formData: Partial<VaultItemFormData>) => Promise<void>;
  deleteItem:  (id: string) => Promise<void>;
  toggleFavorite: (id: string) => Promise<void>;
  archiveItem:    (id: string, archived: boolean) => Promise<void>;
  // Search (client-side, fully local)
  searchItems: (filter: VaultFilter) => DecryptedVaultItem[];
}

export function useVaultItems(): UseVaultItemsReturn {
  const { getVaultKey, isLocked } = useVault();
  const [encryptedItems, setEncryptedItems] = useState<EncryptedVaultItem[]>([]);
  const [decryptedItems, setDecryptedItems] = useState<DecryptedVaultItem[]>([]);
  const [isLoading, setIsLoading]           = useState(false);
  const [error, setError]                   = useState<string | null>(null);

  // ── Fetch ──────────────────────────────────────────────────────────────────

  const fetchItems = useCallback(async () => {
    if (isLocked) return;
    setIsLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/vault/items', { credentials: 'include' });
      if (!res.ok) throw new Error('Failed to fetch vault items');

      const data = await res.json();
      const encrypted: EncryptedVaultItem[] = data.data.items;

      // Decrypt all items client-side
      const vaultKey = getVaultKey();
      const decrypted = encrypted
        .map((item) => {
          try {
            return decryptVaultItem(vaultKey, item);
          } catch (decryptErr) {
            console.error('[Vault] Failed to decrypt item', item.id, decryptErr);
            return null;
          }
        })
        .filter((item): item is DecryptedVaultItem => item !== null);

      setEncryptedItems(encrypted);
      setDecryptedItems(decrypted);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load vault');
    } finally {
      setIsLoading(false);
    }
  }, [isLocked, getVaultKey]);

  // Auto-fetch when vault unlocks
  useEffect(() => {
    if (!isLocked) {
      fetchItems();
    } else {
      // Clear decrypted data when vault locks
      setDecryptedItems([]);
      setEncryptedItems([]);
    }
  }, [isLocked, fetchItems]);

  // ── Create ─────────────────────────────────────────────────────────────────

  const createItem = useCallback(async (formData: VaultItemFormData): Promise<DecryptedVaultItem> => {
    const vaultKey = getVaultKey();

    const fullData: VaultItemData = {
      title:       formData.data.title ?? 'Untitled',
      tags:        formData.data.tags ?? [],
      customFields: formData.data.customFields ?? [],
      riskLevel:   formData.data.riskLevel ?? 'normal',
      ...formData.data,
    };

    const payload = encryptVaultItem(
      vaultKey,
      formData.itemType,
      formData.isFavorite,
      formData.isHighRisk,
      fullData,
    );

    const res = await fetch('/api/vault/items', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      credentials: 'include',
    });

    if (!res.ok) throw new Error('Failed to create vault item');

    const { data } = await res.json();
    const decrypted = decryptVaultItem(vaultKey, data.item);

    setEncryptedItems((prev) => [data.item, ...prev]);
    setDecryptedItems((prev) => [decrypted, ...prev]);

    return decrypted;
  }, [getVaultKey]);

  // ── Update ─────────────────────────────────────────────────────────────────

  const updateItem = useCallback(async (id: string, formData: Partial<VaultItemFormData>) => {
    const vaultKey = getVaultKey();
    const existingDecrypted = decryptedItems.find((i) => i.id === id);
    if (!existingDecrypted) throw new Error('Item not found');

    const newData: VaultItemData = {
      ...existingDecrypted.data,
      ...formData.data,
    };

    const payload = encryptVaultItem(
      vaultKey,
      formData.itemType ?? existingDecrypted.itemType,
      formData.isFavorite ?? existingDecrypted.isFavorite,
      formData.isHighRisk ?? existingDecrypted.isHighRisk,
      newData,
    );

    const res = await fetch(`/api/vault/items/${id}`, {
      method:  'PUT',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
      credentials: 'include',
    });

    if (!res.ok) throw new Error('Failed to update item');

    const { data } = await res.json();
    const decrypted = decryptVaultItem(vaultKey, data.item);

    setEncryptedItems((prev) => prev.map((i) => (i.id === id ? data.item : i)));
    setDecryptedItems((prev) => prev.map((i) => (i.id === id ? decrypted : i)));
  }, [getVaultKey, decryptedItems]);

  // ── Delete ─────────────────────────────────────────────────────────────────

  const deleteItem = useCallback(async (id: string) => {
    const res = await fetch(`/api/vault/items/${id}`, {
      method: 'DELETE',
      credentials: 'include',
    });
    if (!res.ok) throw new Error('Failed to delete item');

    setEncryptedItems((prev) => prev.filter((i) => i.id !== id));
    setDecryptedItems((prev) => prev.filter((i) => i.id !== id));
  }, []);

  // ── Toggle favorite ────────────────────────────────────────────────────────

  const toggleFavorite = useCallback(async (id: string) => {
    const item = decryptedItems.find((i) => i.id === id);
    if (!item) return;

    await fetch(`/api/vault/items/${id}`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ isFavorite: !item.isFavorite }),
      credentials: 'include',
    });

    setDecryptedItems((prev) =>
      prev.map((i) => (i.id === id ? { ...i, isFavorite: !i.isFavorite } : i)),
    );
  }, [decryptedItems]);

  // ── Archive ────────────────────────────────────────────────────────────────

  const archiveItem = useCallback(async (id: string, archived: boolean) => {
    await fetch(`/api/vault/items/${id}`, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ isArchived: archived }),
      credentials: 'include',
    });
    setDecryptedItems((prev) =>
      prev.map((i) => (i.id === id ? { ...i, isArchived: archived } : i)),
    );
  }, []);

  // ── Client-side search ─────────────────────────────────────────────────────
  // All search happens on decrypted data in memory — the server is never queried
  // for secret values.

  const searchItems = useCallback((filter: VaultFilter): DecryptedVaultItem[] => {
    return decryptedItems.filter((item) => {
      if (filter.isArchived !== undefined && item.isArchived !== filter.isArchived) return false;
      if (filter.isFavorite !== undefined && item.isFavorite !== filter.isFavorite) return false;
      if (filter.isHighRisk !== undefined && item.isHighRisk !== filter.isHighRisk) return false;
      if (filter.itemType   !== undefined && item.itemType   !== filter.itemType)   return false;

      if (filter.tags?.length) {
        const hasTag = filter.tags.some((t) => item.data.tags?.includes(t));
        if (!hasTag) return false;
      }

      if (filter.query) {
        const q = filter.query.toLowerCase();
        const searchable = [
          item.data.title,
          item.data.website,
          item.data.username,
          item.data.email,
          item.data.url,
          ...(item.data.tags ?? []),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();

        if (!searchable.includes(q)) return false;
      }

      return true;
    });
  }, [decryptedItems]);

  return {
    items:       decryptedItems,
    isLoading,
    error,
    fetchItems,
    createItem,
    updateItem,
    deleteItem,
    toggleFavorite,
    archiveItem,
    searchItems,
  };
}
