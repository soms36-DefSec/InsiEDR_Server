/**
 * InsiEDR Contextual Status Badge
 * ===============================
 *
 * Architectural Role:
 *   Standardized color-coded visual chip indicating risk severity, endpoint online/offline
 *   presence, telemetry collector daemon identities, or neutral metadata.
 */

import React from 'react';
import type { RiskLevel } from '../../types/telemetry';

export interface BadgeProps {
  level?: RiskLevel | string;
  children?: React.ReactNode;
  variant?: 'risk' | 'status' | 'neutral' | 'collector';
  className?: string;
  size?: 'sm' | 'md';
}

export const Badge: React.FC<BadgeProps> = ({
  level,
  children,
  variant = 'risk',
  className = '',
  size = 'md',
}) => {
  const norm = (level || '').toUpperCase();
  const sizeClasses = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  if (variant === 'status') {
    const isOnline = norm === 'ACTIVE' || norm === 'ONLINE' || norm === 'SUCCESS' || norm === 'READY';
    return (
      <span
        className={`inline-flex items-center gap-1.5 font-medium rounded-md border ${
          isOnline
            ? 'bg-[#F0FDF4] text-[#166534] border-[#DCFCE7]'
            : 'bg-[#F3F4F6] text-[#4B5563] border-[#E5E7EB]'
        } ${sizeClasses} ${className}`}
      >
        <span
          className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-[#16A34A]' : 'bg-[#9CA3AF]'}`}
        />
        {children || (isOnline ? 'Online' : 'Offline')}
      </span>
    );
  }

  if (variant === 'collector') {
    return (
      <span
        className={`inline-flex items-center font-mono font-medium rounded-md border bg-[#F8FAFC] text-[#475569] border-[#E2E8F0] ${sizeClasses} ${className}`}
      >
        {children || level}
      </span>
    );
  }

  if (variant === 'neutral') {
    return (
      <span
        className={`inline-flex items-center font-medium rounded-md border bg-[#F9FAFB] text-[#4B5563] border-[#E5E7EB] ${sizeClasses} ${className}`}
      >
        {children || level}
      </span>
    );
  }

  // Risk badges
  let colorClasses = 'bg-[#F0FDF4] text-[#166534] border-[#DCFCE7] font-medium';
  if (norm === 'CRITICAL') {
    colorClasses = 'bg-[#FEF2F2] text-[#991B1B] border-[#FEE2E2] font-semibold';
  } else if (norm === 'HIGH') {
    colorClasses = 'bg-[#FFF7ED] text-[#C2410C] border-[#FFEDD5] font-semibold';
  } else if (norm === 'MEDIUM') {
    colorClasses = 'bg-[#FEFCE8] text-[#854D0E] border-[#FEF08A] font-medium';
  }

  return (
    <span
      className={`inline-flex items-center tracking-normal font-sans rounded-md border ${colorClasses} ${sizeClasses} ${className}`}
    >
      {children || norm}
    </span>
  );
};
