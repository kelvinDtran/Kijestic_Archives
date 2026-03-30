'use client';

import { ShieldCheck, ShieldAlert, ShieldQuestion, ShieldOff, Loader2 } from 'lucide-react';
import type { ScanStatus } from '@/types/vault';

interface ScanBadgeProps {
  status: ScanStatus;
  detections?: number;
  totalEngines?: number;
}

const CONFIG: Record<ScanStatus, {
  label: string;
  className: string;
  Icon: React.ComponentType<{ className?: string }>;
}> = {
  CLEAN: {
    label:     'Clean',
    className: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30',
    Icon:      ShieldCheck,
  },
  INFECTED: {
    label:     'Infected',
    className: 'text-red-400 bg-red-400/10 border-red-400/30',
    Icon:      ShieldAlert,
  },
  UNKNOWN: {
    label:     'Unknown',
    className: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
    Icon:      ShieldQuestion,
  },
  SKIPPED: {
    label:     'Not scanned',
    className: 'text-aegis-muted bg-aegis-surface border-aegis-border',
    Icon:      ShieldOff,
  },
  PENDING: {
    label:     'Scanning…',
    className: 'text-aegis-accent bg-aegis-accent/10 border-aegis-accent/30',
    Icon:      Loader2,
  },
};

export function ScanBadge({ status, detections, totalEngines }: ScanBadgeProps) {
  const { label, className, Icon } = CONFIG[status] ?? CONFIG.UNKNOWN;

  const tooltip =
    status === 'INFECTED' && detections !== undefined && totalEngines !== undefined
      ? `${detections} / ${totalEngines} engines detected malware`
      : status === 'CLEAN' && totalEngines
      ? `0 / ${totalEngines} engines detected malware`
      : undefined;

  return (
    <span
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${className}`}
      title={tooltip}
    >
      <Icon className={`w-3 h-3 flex-shrink-0 ${status === 'PENDING' ? 'animate-spin' : ''}`} />
      {label}
      {status === 'INFECTED' && detections !== undefined && (
        <span className="font-bold">({detections})</span>
      )}
    </span>
  );
}
