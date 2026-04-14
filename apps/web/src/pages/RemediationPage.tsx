import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, CheckCircle, Download, GitBranch, AlertTriangle } from 'lucide-react';
import { remediationApi } from '../lib/api';
import { SeverityBadge } from '../components/common/SeverityBadge';

export function RemediationPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const queryClient = useQueryClient();
  const [approvalScope, setApprovalScope] = useState('all_safe');
  const [selectedProposals, setSelectedProposals] = useState<string[]>([]);

  const { data, isLoading } = useQuery({
    queryKey: ['proposals', scanId],
    queryFn: () => remediationApi.proposals(scanId!),
  });

  const approveMutation = useMutation({
    mutationFn: (scope: string) => remediationApi.approve({
      scan_id: scanId,
      scope,
      proposal_ids: scope === 'by_finding' ? selectedProposals : undefined,
    }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proposals', scanId] });
    },
  });

  const applyMutation = useMutation({
    mutationFn: (approvalId: string) => remediationApi.apply({
      approval_id: approvalId,
      create_branch: true,
    }),
  });

  const exportMutation = useMutation({
    mutationFn: () => remediationApi.patch(scanId!),
  });

  const proposals = data?.data || [];
  const safeProposals = proposals.filter((p: any) => p.safe_to_auto_apply);
  const manualProposals = proposals.filter((p: any) => !p.safe_to_auto_apply);

  return (
    <div>
      <Link to={`/scans/${scanId}`} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-6">
        <ArrowLeft className="w-4 h-4" />
        Back to Scan
      </Link>

      <h1 className="text-2xl font-bold text-gray-900 mb-2">Remediation Center</h1>
      <p className="text-sm text-gray-500 mb-6">
        Review and approve security fixes for scan {scanId?.slice(0, 8)}
      </p>

      {isLoading ? (
        <div className="text-center py-8 text-gray-400">Loading proposals...</div>
      ) : proposals.length === 0 ? (
        <div className="card text-center py-12">
          <CheckCircle className="w-12 h-12 text-gray-300 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900">No remediation proposals</h3>
          <p className="text-sm text-gray-500 mt-1">No auto-fixable findings were detected in this scan</p>
        </div>
      ) : (
        <>
          {/* Stats */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            <div className="card text-center py-4">
              <div className="text-2xl font-bold">{proposals.length}</div>
              <div className="text-xs text-gray-500">Total Proposals</div>
            </div>
            <div className="card text-center py-4">
              <div className="text-2xl font-bold text-green-600">{safeProposals.length}</div>
              <div className="text-xs text-gray-500">Safe to Auto-Apply</div>
            </div>
            <div className="card text-center py-4">
              <div className="text-2xl font-bold text-yellow-600">{manualProposals.length}</div>
              <div className="text-xs text-gray-500">Manual Review Required</div>
            </div>
          </div>

          {/* Approval actions */}
          <div className="card mb-6">
            <h2 className="text-lg font-semibold mb-4">Approval Actions</h2>
            <div className="flex flex-wrap gap-3">
              <button
                className="btn-primary flex items-center gap-2"
                onClick={() => approveMutation.mutate('all_safe')}
                disabled={approveMutation.isPending || safeProposals.length === 0}
              >
                <CheckCircle className="w-4 h-4" />
                Approve All Safe ({safeProposals.length})
              </button>
              <button
                className="btn-secondary flex items-center gap-2"
                onClick={() => exportMutation.mutate()}
                disabled={exportMutation.isPending}
              >
                <Download className="w-4 h-4" />
                Export Patch
              </button>
              <button
                className="btn-secondary flex items-center gap-2"
                onClick={() => approveMutation.mutate('create_branch_only')}
                disabled={approveMutation.isPending}
              >
                <GitBranch className="w-4 h-4" />
                Create Branch Only
              </button>
            </div>

            {approveMutation.isSuccess && (
              <div className="mt-4 p-3 bg-green-50 rounded-lg text-sm text-green-700 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" />
                Remediation approved successfully
              </div>
            )}

            {exportMutation.isSuccess && (
              <div className="mt-4 p-3 bg-blue-50 rounded-lg text-sm text-blue-700">
                <p className="font-medium">Patch exported</p>
                <pre className="mt-2 text-xs bg-blue-100 p-2 rounded overflow-x-auto">
                  {JSON.stringify(exportMutation.data, null, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Safe proposals */}
          {safeProposals.length > 0 && (
            <div className="mb-6">
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-green-600" />
                Safe to Auto-Apply
              </h2>
              <div className="space-y-3">
                {safeProposals.map((proposal: any) => (
                  <div key={proposal.id} className="card py-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium">{proposal.title}</h3>
                        <p className="text-sm text-gray-600 mt-1">{proposal.description}</p>
                        <p className="text-xs text-gray-400 mt-1">{proposal.file_path}</p>
                      </div>
                      <span className="badge bg-green-100 text-green-700 capitalize">{proposal.status}</span>
                    </div>
                    {proposal.diff && (
                      <details className="mt-3">
                        <summary className="text-sm text-brand-600 cursor-pointer">View Diff</summary>
                        <pre className="mt-2 p-3 bg-gray-900 text-green-400 rounded-lg text-xs overflow-x-auto">{proposal.diff}</pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Manual proposals */}
          {manualProposals.length > 0 && (
            <div>
              <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-yellow-600" />
                Requires Manual Review
              </h2>
              <div className="space-y-3">
                {manualProposals.map((proposal: any) => (
                  <div key={proposal.id} className="card py-4 border-l-4 border-l-yellow-400">
                    <h3 className="font-medium">{proposal.title}</h3>
                    <p className="text-sm text-gray-600 mt-1">{proposal.description}</p>
                    {proposal.risk_notes && (
                      <p className="text-sm text-yellow-700 mt-2 bg-yellow-50 p-2 rounded">{proposal.risk_notes}</p>
                    )}
                    {proposal.manual_steps && (
                      <div className="mt-2">
                        <p className="text-xs font-medium text-gray-500">Manual Steps:</p>
                        <ul className="text-sm text-gray-600 mt-1 list-disc list-inside">
                          {proposal.manual_steps.map((step: string, i: number) => (
                            <li key={i}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
