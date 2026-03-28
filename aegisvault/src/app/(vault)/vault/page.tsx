'use client';

import { useState, useMemo } from 'react';
import { Plus, Search, SlidersHorizontal, RefreshCw } from 'lucide-react';
import { VaultList } from '@/components/vault/VaultList';
import { VaultItemForm } from '@/components/vault/VaultItemForm';
import { VaultItemDetail } from '@/components/vault/VaultItemDetail';
import { useVaultItems } from '@/hooks/useVaultItems';
import { useVault } from '@/contexts/VaultContext';
import { ITEM_TYPE_LABELS } from '@/lib/utils';
import type { DecryptedVaultItem, VaultItemFormData, ItemType } from '@/types/vault';

export default function VaultPage() {
  const { isLocked }  = useVault();
  const {
    items, isLoading, error, fetchItems,
    createItem, updateItem, deleteItem, toggleFavorite, archiveItem, searchItems,
  } = useVaultItems();

  const [searchQuery, setSearchQuery]       = useState('');
  const [typeFilter, setTypeFilter]         = useState<ItemType | ''>('');
  const [showArchived, setShowArchived]     = useState(false);
  const [showFavoritesOnly, setShowFavoritesOnly] = useState(false);
  const [showForm, setShowForm]             = useState(false);
  const [editingItem, setEditingItem]       = useState<DecryptedVaultItem | null>(null);
  const [selectedItem, setSelectedItem]     = useState<DecryptedVaultItem | null>(null);
  const [formError, setFormError]           = useState<string | null>(null);

  const filtered = useMemo(() => searchItems({
    query:      searchQuery,
    itemType:   typeFilter || undefined,
    isArchived: showArchived,
    isFavorite: showFavoritesOnly || undefined,
  }), [searchItems, searchQuery, typeFilter, showArchived, showFavoritesOnly]);

  const handleCreate = async (formData: VaultItemFormData) => {
    setFormError(null);
    try {
      await createItem(formData);
      setShowForm(false);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to create item');
    }
  };

  const handleEdit = async (formData: VaultItemFormData) => {
    if (!editingItem) return;
    setFormError(null);
    try {
      await updateItem(editingItem.id, formData);
      setEditingItem(null);
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Failed to update item');
    }
  };

  if (isLocked) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-aegis-muted text-sm">Unlock your vault to view secrets</p>
      </div>
    );
  }

  // Show form
  if (showForm || editingItem) {
    return (
      <div className="max-w-2xl">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold text-aegis-text">
            {editingItem ? 'Edit Secret' : 'Add New Secret'}
          </h1>
        </div>
        {formError && (
          <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
            {formError}
          </div>
        )}
        <div className="aegis-card">
          <VaultItemForm
            onSubmit={editingItem ? handleEdit : handleCreate}
            onCancel={() => { setShowForm(false); setEditingItem(null); }}
            isEditing={!!editingItem}
            initialValues={editingItem ? {
              title:    editingItem.data.title,
              itemType: editingItem.itemType,
              ...editingItem.data,
              tags:     editingItem.data.tags?.join(', '),
            } : undefined}
          />
        </div>
      </div>
    );
  }

  // Show item detail
  if (selectedItem) {
    return (
      <VaultItemDetail
        item={selectedItem}
        onClose={() => setSelectedItem(null)}
        onEdit={(item) => { setSelectedItem(null); setEditingItem(item); }}
        onDelete={async (id) => { await deleteItem(id); setSelectedItem(null); }}
      />
    );
  }

  // Vault list view
  return (
    <div className="max-w-3xl">
      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-aegis-text">Vault</h1>
          <p className="text-sm text-aegis-muted mt-0.5">
            {items.length} item{items.length !== 1 ? 's' : ''} · all encrypted
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={fetchItems} className="w-8 h-8 rounded-aegis bg-aegis-elevated border border-aegis-border flex items-center justify-center text-aegis-muted hover:text-aegis-primary">
            <RefreshCw className="w-4 h-4" />
          </button>
          <button onClick={() => setShowForm(true)} className="aegis-btn-primary flex items-center gap-2">
            <Plus className="w-4 h-4" />
            Add Secret
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by title, website, username, tags…"
            className="aegis-input pl-9 py-1.5 text-sm"
          />
        </div>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as ItemType | '')}
          className="aegis-input py-1.5 text-sm w-auto"
        >
          <option value="">All types</option>
          {Object.entries(ITEM_TYPE_LABELS).map(([v, l]) => (
            <option key={v} value={v}>{l}</option>
          ))}
        </select>
        <button
          onClick={() => setShowFavoritesOnly((v) => !v)}
          className={`aegis-btn-ghost py-1.5 text-sm ${showFavoritesOnly ? 'text-yellow-400' : ''}`}
        >
          ★ Favorites
        </button>
        <button
          onClick={() => setShowArchived((v) => !v)}
          className={`aegis-btn-ghost py-1.5 text-sm ${showArchived ? 'text-aegis-primary' : ''}`}
        >
          Archived
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-aegis-danger-muted border border-aegis-danger text-aegis-danger text-sm rounded-aegis px-3 py-2 mb-4">
          {error}
        </div>
      )}

      {/* Results count */}
      {searchQuery && (
        <p className="text-xs text-aegis-muted mb-2">
          {filtered.length} result{filtered.length !== 1 ? 's' : ''} for &quot;{searchQuery}&quot;
        </p>
      )}

      {/* List */}
      <VaultList
        items={filtered}
        isLoading={isLoading}
        onSelect={setSelectedItem}
        onEdit={setEditingItem}
        onDelete={deleteItem}
        onToggleFavorite={toggleFavorite}
        onArchive={archiveItem}
      />
    </div>
  );
}
