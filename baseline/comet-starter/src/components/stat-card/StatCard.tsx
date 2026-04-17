import React from 'react';

interface Props {
  value: number | string;
  label: string;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'default';
}

export const StatCard = ({ value, label, variant = 'default' }: Props): React.ReactElement => (
  <div className={`epyon-stat-card epyon-stat-card--${variant}`}>
    <div className="epyon-stat-card__value">{value}</div>
    <div className="epyon-stat-card__label">{label}</div>
  </div>
);
