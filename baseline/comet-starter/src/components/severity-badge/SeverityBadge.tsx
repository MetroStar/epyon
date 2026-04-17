import React from 'react';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'clean' | 'unknown';

interface Props {
  severity: string;
  label?: string;
  count?: number;
}

export const SeverityBadge = ({ severity, label, count }: Props): React.ReactElement => {
  const sev = (severity || 'unknown').toLowerCase() as Severity;
  const text = label ?? (count !== undefined ? `${count} ${capitalize(sev)}` : capitalize(sev));
  return (
    <span className={`epyon-badge epyon-badge--${sev}`}>
      {text}
    </span>
  );
};

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
