/**
 * InsiEDR Surface Card Container
 * ==============================
 *
 * Architectural Role:
 *   Structural visual container providing consistent borders, subtle drop shadows,
 *   optional header title/subtitle/actions zones, and customizable padding for
 *   dashboard widgets and plugin viewports.
 */

import React from 'react';

export interface CardProps {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  action,
  children,
  className = '',
  bodyClassName = '',
  noPadding = false,
}) => {
  const hasHeader = title || action;

  return (
    <div className={`bg-white border border-slate-200/90 rounded-lg shadow-[0_1px_2px_rgba(0,0,0,0.03)] overflow-hidden ${className}`}>
      {hasHeader && (
        <div className="px-5 py-3.5 border-b border-slate-200/80 flex items-center justify-between gap-4 bg-white">
          <div>
            {title && <h3 className="text-sm font-semibold text-slate-900 tracking-tight">{title}</h3>}
            {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className={noPadding ? bodyClassName : `p-5 ${bodyClassName}`}>{children}</div>
    </div>
  );
};
