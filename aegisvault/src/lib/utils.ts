import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: Date | string): string {
  return new Date(date).toLocaleDateString('en-US', {
    month: 'short',
    day:   'numeric',
    year:  'numeric',
  });
}

export function formatRelativeTime(date: Date | string): string {
  const now  = Date.now();
  const then = new Date(date).getTime();
  const diff = now - then;

  const seconds = Math.floor(diff / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours   = Math.floor(minutes / 60);
  const days    = Math.floor(hours / 24);

  if (seconds < 60)  return 'just now';
  if (minutes < 60)  return `${minutes}m ago`;
  if (hours < 24)    return `${hours}h ago`;
  if (days < 7)      return `${days}d ago`;
  return formatDate(date);
}

export const ITEM_TYPE_LABELS: Record<string, string> = {
  PASSWORD:      'Password',
  API_KEY:       'API Key',
  CRYPTO:        'Crypto',
  NOTE:          'Secure Note',
  DOCUMENT:      'Document',
  RECOVERY_CODE: 'Recovery Code',
  IMAGE:         'Image',
  OTHER:         'Other',
};

export const ITEM_TYPE_ICONS: Record<string, string> = {
  PASSWORD:      '🔑',
  API_KEY:       '🗝️',
  CRYPTO:        '₿',
  NOTE:          '📝',
  DOCUMENT:      '📄',
  RECOVERY_CODE: '🔐',
  IMAGE:         '🖼️',
  OTHER:         '📦',
};
