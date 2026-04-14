import clsx from 'clsx';

const badgeStyles: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  informational: 'badge-info',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx('badge', badgeStyles[severity] || 'badge-info')}>
      {severity.toUpperCase()}
    </span>
  );
}
