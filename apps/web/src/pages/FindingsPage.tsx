import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, Filter, Search } from 'lucide-react';
import { findingsApi } from '../lib/api';
import { SeverityBadge } from '../components/common/SeverityBadge';

export function FindingsPage() {
  const { id: scanId } = useParams<{ id: string }>();
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

  const { data, isLoading } = useQuery({
    queryKey: ['findings', scanId, severity, category, search, page],
    queryFn: () => findingsApi.list({
      scan_id: scanId,
      ...(severity && { severity }),
      ...(category && { category }),
      ...(search && { search }),
      page: String(page),
      page_size: '25',
      sort_by: 'priority_score',
      sort_order: 'desc',
    }),
  });

  const { data: correlatedData } = useQuery({
    queryKey: ['correlated', scanId],
    queryFn: () => findingsApi.correlated(scanId!),
  });

  const findings = data?.data || [];
  const totalPages = data?.total_pages || 1;
  const correlatedGroups = correlatedData?.data || [];

  return (
    <div>
      <Link to={`/scans/${scanId}`} className="flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-6">
        <ArrowLeft className="w-4 h-4" />
        Back to Scan
      </Link>

      <h1 className="text-2xl font-bold text-gray-900 mb-2">Findings</h1>
      <p className="text-sm text-gray-500 mb-6">
        {data?.total || 0} findings for scan {scanId?.slice(0, 8)}
      </p>

      {/* Correlated groups */}
      {correlatedGroups.length > 0 && (
        <div className="mb-6">
          <h2 className="text-lg font-semibold mb-3">Correlated Risk Groups</h2>
          <div className="space-y-3">
            {correlatedGroups.map((group: any) => (
              <div key={group.id} className="card border-l-4 border-l-red-500 py-4">
                <div className="flex items-center gap-3 mb-2">
                  <SeverityBadge severity={group.combined_severity} />
                  <h3 className="font-medium">{group.title}</h3>
                </div>
                <p className="text-sm text-gray-600">{group.description}</p>
                <p className="text-xs text-gray-400 mt-2">{group.finding_ids.length} findings correlated</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card mb-6">
        <div className="flex flex-wrap gap-4 items-end">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-xs font-medium text-gray-500 mb-1">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                className="input pl-9"
                placeholder="Search findings..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Severity</label>
            <select className="select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-500 mb-1">Category</label>
            <select className="select" value={category} onChange={(e) => { setCategory(e.target.value); setPage(1); }}>
              <option value="">All</option>
              <option value="sast">SAST</option>
              <option value="dast">DAST</option>
              <option value="secret_scanning">Secrets</option>
              <option value="dependency_scanning">Dependencies</option>
              <option value="infra_scanning">Infrastructure</option>
              <option value="api_security">API Security</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings list */}
      {isLoading ? (
        <div className="text-center py-8 text-gray-400">Loading findings...</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-12 text-gray-400">No findings match your filters</div>
      ) : (
        <>
          <div className="space-y-3">
            {findings.map((finding: any) => (
              <div key={finding.finding_id} className="card py-4 hover:shadow-md transition-shadow">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <SeverityBadge severity={finding.severity} />
                      <span className="text-xs text-gray-400 uppercase">{finding.category}</span>
                      {finding.autofixable && (
                        <span className="badge bg-green-100 text-green-700">Auto-fixable</span>
                      )}
                    </div>
                    <h3 className="font-medium text-gray-900">{finding.title}</h3>
                    <p className="text-sm text-gray-600 mt-1 line-clamp-2">{finding.summary}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-gray-400">
                      <span>{finding.scanner}</span>
                      {finding.file_path && <span>{finding.file_path}{finding.line_start ? `:${finding.line_start}` : ''}</span>}
                      {finding.endpoint && <span>{finding.method} {finding.endpoint}</span>}
                      {finding.cwe && <span>{finding.cwe}</span>}
                    </div>
                  </div>
                  <div className="text-right ml-4">
                    <div className="text-lg font-bold text-gray-700">{finding.priority_score}</div>
                    <div className="text-xs text-gray-400">Priority</div>
                  </div>
                </div>

                {/* Remediation guidance */}
                <details className="mt-3">
                  <summary className="text-sm text-brand-600 cursor-pointer hover:text-brand-700">
                    View Remediation
                  </summary>
                  <div className="mt-2 p-3 bg-gray-50 rounded-lg text-sm">
                    <pre className="whitespace-pre-wrap text-gray-700">{finding.remediation}</pre>
                    {finding.redacted_evidence && (
                      <div className="mt-2 p-2 bg-gray-100 rounded font-mono text-xs">
                        <strong>Evidence:</strong> {finding.redacted_evidence}
                      </div>
                    )}
                  </div>
                </details>
              </div>
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center gap-2 mt-6">
              <button className="btn-secondary" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button>
              <span className="flex items-center px-4 text-sm text-gray-500">Page {page} of {totalPages}</span>
              <button className="btn-secondary" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
