'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard, Vault, Star, Archive, Settings,
  MonitorSmartphone, Shield, LogOut, Lock
} from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/vault',     icon: Vault,           label: 'Vault' },
  { href: '/vault?favorites=true', icon: Star,  label: 'Favorites' },
  { href: '/vault?archived=true',  icon: Archive, label: 'Archive' },
];

const bottomItems = [
  { href: '/audit',    icon: Shield,             label: 'Audit Log' },
  { href: '/sessions', icon: MonitorSmartphone, label: 'Sessions' },
  { href: '/settings', icon: Settings,          label: 'Settings' },
];

export function Sidebar() {
  const pathname = usePathname();
  const { lock, isLocked } = useVault();

  const handleLogout = async () => {
    lock();
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
    window.location.href = '/login';
  };

  return (
    <aside className="w-56 bg-aegis-surface border-r border-aegis-border flex flex-col h-full shrink-0">
      {/* Brand */}
      <div className="p-4 border-b border-aegis-border">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-aegis-primary" />
          <span className="font-semibold text-aegis-text text-sm">AegisVault</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
        {navItems.map(({ href, icon: Icon, label }) => {
          const isActive = pathname === href || (href !== '/' && pathname.startsWith(href.split('?')[0]));
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-2.5 px-3 py-2 rounded-aegis text-sm transition-colors',
                isActive
                  ? 'bg-aegis-primary-muted text-aegis-primary font-medium'
                  : 'text-aegis-subtle hover:text-aegis-text hover:bg-aegis-elevated',
              )}
            >
              <Icon className="w-4 h-4 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Bottom section */}
      <div className="p-2 space-y-0.5 border-t border-aegis-border">
        {bottomItems.map(({ href, icon: Icon, label }) => (
          <Link
            key={href}
            href={href}
            className={cn(
              'flex items-center gap-2.5 px-3 py-2 rounded-aegis text-sm transition-colors',
              pathname.startsWith(href)
                ? 'bg-aegis-primary-muted text-aegis-primary font-medium'
                : 'text-aegis-subtle hover:text-aegis-text hover:bg-aegis-elevated',
            )}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </Link>
        ))}

        {/* Lock vault */}
        {!isLocked && (
          <button
            onClick={lock}
            className="flex items-center gap-2.5 px-3 py-2 rounded-aegis text-sm w-full
                       text-aegis-subtle hover:text-aegis-warning hover:bg-aegis-elevated transition-colors"
          >
            <Lock className="w-4 h-4 shrink-0" />
            Lock Vault
          </button>
        )}

        {/* Logout */}
        <button
          onClick={handleLogout}
          className="flex items-center gap-2.5 px-3 py-2 rounded-aegis text-sm w-full
                     text-aegis-subtle hover:text-aegis-danger hover:bg-aegis-danger-muted transition-colors"
        >
          <LogOut className="w-4 h-4 shrink-0" />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
