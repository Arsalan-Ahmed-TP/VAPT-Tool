import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, FileText, Wrench, RefreshCw, Download } from 'lucide-react';
import { scansApi } from '../lib/api';
import { StatusBadge } from '../components/common/StatusBadge';
import { SeverityBadge } from '../components/common/SeverityBadge';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();

  const { data: scan, isLoading } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => scansApi.get(id!),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status && !['completed', 'failed', 'cancelled'].includes(status)) {
        return 3000; // Poll every 3s while running
      }
      return false;
    },
  });

  const { data: status } = useQuery({
    queryKey: ['scan-status', id],
    queryFn: () => scansApi.status(id!),
    refetchInterval: (query) => {
      const scanStatus = scan?.status;
      if (scanStatus && !['completed', 'failed', 'cancelled'].includes(scanStatus)) {
        return 2000;
      }
      return false;
    },
    enabled: !!scan,
  });

  if (isLoading) {
    return <div className="text-center py-12 text-gray-400">Loading scan...</div>;
  }

  if (!scan) {
    return <div className="text-center py-12 text-red-500">Scan not found</div>;
  }

  const summary = scan.summary;
  const isRunning = !['completed', 'failed', 'cancelled'].includes(scan.status);

  return (
    <div>
      <Link to="/" className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-6">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>

      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Scan {scan.id.slice(0, 8)}
          </h1>
          <div className="flex items-center gap-3 mt-2">
            <StatusBadge status={scan.status} />
            <span className="text-sm text-gray-500 capitalize">{scan.profile} profile</span>
          </div>
        </div>
        <div className="flex gap-3">
          {scan.status === 'completed' && (
            <>
              <Link to={`/scans/${id}/findings`} className="btn-secondary flex items-center gap-2">
                <FileText className="w-4 h-4" />
                Findings
              </Link>
              <Link to={`/scans/${id}/remediation`} className="btn-primary flex items-center gap-2">
                <Wrench className="w-4 h-4" />
                Remediation
              </Link>
            </>
          )}
        </div>
      </div>

      {/* Progress */}
      {isRunning && status && (
        <div className="card mb-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <RefreshCw className="w-5 h-5 animate-spin text-brand-600" />
            Scan in Progress
          </h2>
          <div className="mb-4">
            <div className="flex justify-between text-sm mb-1">
              <span className="capitalize">{status.progress?.phase}</span>
              <span>{status.progress?.percent}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div
                className="bg-brand-600 h-2 rounded-full transition-all duration-500"
                style={{ width: `${status.progress?.percent || 0}%` }}
              />
            </div>
            <p className="text-sm text-gray-500 mt-1">{status.progress?.message}</p>
          </div>

          {status.jobs?.length > 0 && (
            <div className="space-y-2">
              {status.jobs.map((job: any) => (
                <div key={job.job_id} className="flex items-center justify-between text-sm py-2 border-t border-gray-100">
                  <div className="flex items-center gap-3">
                    <StatusBadge status={job.status} />
                    <span className="font-medium">{job.scanner}</span>
                    <span className="text-gray-400">{job.category}</span>
                  </div>
                  <span className="text-gray-500">{job.percent}%</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Summary */}
      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4 mb-6">
          {[
            { label: 'Total', value: summary.total_findings, color: 'text-gray-900' },
            { label: 'Critical', value: summary.critical, color: 'text-red-600' },
            { label: 'High', value: summary.high, color: 'text-orange-600' },
            { label: 'Medium', value: summary.medium, color: 'text-yellow-600' },
            { label: 'Low', value: summary.low, color: 'text-blue-600' },
            { label: 'Info', value: summary.informational, color: 'text-gray-500' },
            { label: 'Fixable', value: summary.autofixable, color: 'text-green-600' },
          ].map((stat) => (
            <div key={stat.label} className="card text-center py-4">
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-gray-500 mt-1">{stat.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Target info */}
      <div className="card mb-6">
        <h2 className="text-lg font-semibold mb-4">Target Information</h2>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div><span className="text-gray-500">Name:</span> <strong>{scan.target?.name || '-'}</strong></div>
          <div><span className="text-gray-500">Type:</span> <strong>{scan.target?.source_type || '-'}</strong></div>
          <div className="col-span-2"><span className="text-gray-500">Location:</span> <strong className="break-all">{scan.target?.location || '-'}</strong></div>
          <div><span className="text-gray-500">Environment:</span> <strong className="capitalize">{scan.target?.environment || '-'}</strong></div>
          <div><span className="text-gray-500">Auto-fix Mode:</span> <strong>{scan.autofix_mode?.replace(/_/g, ' ') || '-'}</strong></div>
        </div>
      </div>

      {/* Scanner jobs */}
      {scan.jobs?.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold mb-4">Scanner Jobs</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-2 px-2 font-medium text-gray-500">Scanner</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-500">Category</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-500">Status</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-500">Findings</th>
                  <th className="text-left py-2 px-2 font-medium text-gray-500">Duration</th>
                </tr>
              </thead>
              <tbody>
                {scan.jobs.map((job: any) => (
                  <tr key={job.id} className="border-b border-gray-100">
                    <td className="py-2 px-2 font-medium">{job.scanner_name}</td>
                    <td className="py-2 px-2 text-gray-500">{job.category}</td>
                    <td className="py-2 px-2"><StatusBadge status={job.status} /></td>
                    <td className="py-2 px-2">{job.finding_count}</td>
                    <td className="py-2 px-2 text-gray-500">
                      {job.duration_ms ? `${(job.duration_ms / 1000).toFixed(1)}s` : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
