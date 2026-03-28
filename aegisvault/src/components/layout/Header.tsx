'use client';

import { useState } from 'react';
import { Search, Lock, Shield } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';

interface HeaderProps {
  onSearch?: (query: string) => void;
}

export function Header({ onSearch }: HeaderProps) {
  const { isLocked, lock, lastUnlockedAt } = useVault();
  const [query, setQuery] = useState('');

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    onSearch?.(e.target.value);
  };

  return (
    <header className="h-14 bg-aegis-surface border-b border-aegis-border flex items-center px-4 gap-4 shrink-0">
      {/* Search */}
      <div className="flex-1 max-w-sm relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-aegis-muted" />
        <input
          type="search"
          value={query}
          onChange={handleSearch}
          placeholder="Search vault…"
          className="aegis-input pl-9 py-1.5 text-sm h-8"
          disabled={isLocked}
        />
      </div>

      <div className="ml-auto flex items-center gap-3">
        {/* Vault status indicator */}
        <div className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-full border ${
          isLocked
            ? 'bg-aegis-elevated border-aegis-border text-aegis-muted'
            : 'bg-aegis-success-muted border-aegis-success text-aegis-success'
        }`}>
          {isLocked ? (
            <>
              <Lock className="w-3 h-3" />
              <span>Locked</span>
            </>
          ) : (
            <>
              <Shield className="w-3 h-3" />
              <span>Unlocked</span>
              {lastUnlockedAt && (
                <span className="text-aegis-muted ml-1">
                  · {lastUnlockedAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              )}
            </>
          )}
        </div>

        {/* Panic lock button */}
        {!isLocked && (
          <button
            onClick={lock}
            title="Immediately lock the vault"
            className="w-8 h-8 rounded-aegis bg-aegis-elevated hover:bg-aegis-danger-muted border border-aegis-border hover:border-aegis-danger flex items-center justify-center transition-colors group"
            aria-label="Lock vault now"
          >
            <Lock className="w-3.5 h-3.5 text-aegis-muted group-hover:text-aegis-danger" />
          </button>
        )}
      </div>
    </header>
  );
}
