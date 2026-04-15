import clsx from 'clsx';

const statusStyles: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  validating: 'bg-blue-100 text-blue-700',
  fingerprinting: 'bg-blue-100 text-blue-700',
  planning: 'bg-blue-100 text-blue-700',
  running: 'bg-yellow-100 text-yellow-700',
  normalizing: 'bg-purple-100 text-purple-700',
  correlating: 'bg-purple-100 text-purple-700',
  reporting: 'bg-indigo-100 text-indigo-700',
  completed: 'bg-green-100 text-green-700',
  failed: 'bg-red-100 text-red-700',
  cancelled: 'bg-gray-100 text-gray-500',
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={clsx('badge', statusStyles[status] || 'bg-gray-100 text-gray-700')}>
      {status.replace(/_/g, ' ').toUpperCase()}
    </span>
  );
}
