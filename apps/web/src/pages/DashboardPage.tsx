import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { PlusCircle, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import { scansApi } from '../lib/api';
import { StatusBadge } from '../components/common/StatusBadge';

export function DashboardPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => scansApi.list(),
  });

  const scans = data?.data || [];

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">Overview of your security scans and findings</p>
        </div>
        <Link to="/scans/new" className="btn-primary flex items-center gap-2">
          <PlusCircle className="w-4 h-4" />
          New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div className="card flex items-center gap-4">
          <div className="p-3 bg-blue-100 rounded-lg">
            <Shield className="w-6 h-6 text-blue-600" />
          </div>
          <div>
            <div className="text-2xl font-bold">{scans.length}</div>
            <div className="text-sm text-gray-500">Total Scans</div>
          </div>
        </div>
        <div className="card flex items-center gap-4">
          <div className="p-3 bg-yellow-100 rounded-lg">
            <Clock className="w-6 h-6 text-yellow-600" />
          </div>
          <div>
            <div className="text-2xl font-bold">
              {scans.filter((s: any) => ['running', 'pending', 'planning'].includes(s.status)).length}
            </div>
            <div className="text-sm text-gray-500">In Progress</div>
          </div>
        </div>
        <div className="card flex items-center gap-4">
          <div className="p-3 bg-green-100 rounded-lg">
            <CheckCircle className="w-6 h-6 text-green-600" />
          </div>
          <div>
            <div className="text-2xl font-bold">
              {scans.filter((s: any) => s.status === 'completed').length}
            </div>
            <div className="text-sm text-gray-500">Completed</div>
          </div>
        </div>
        <div className="card flex items-center gap-4">
          <div className="p-3 bg-red-100 rounded-lg">
            <AlertTriangle className="w-6 h-6 text-red-600" />
          </div>
          <div>
            <div className="text-2xl font-bold">
              {scans.reduce((sum: number, s: any) => sum + (s.summary?.critical || 0) + (s.summary?.high || 0), 0)}
            </div>
            <div className="text-sm text-gray-500">Critical + High</div>
          </div>
        </div>
      </div>

      {/* Recent scans */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
        {isLoading ? (
          <div className="text-center py-8 text-gray-400">Loading scans...</div>
        ) : scans.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900">No scans yet</h3>
            <p className="text-sm text-gray-500 mt-1">Create your first scan to get started</p>
            <Link to="/scans/new" className="btn-primary inline-flex items-center gap-2 mt-4">
              <PlusCircle className="w-4 h-4" />
              New Scan
            </Link>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Scan ID</th>
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Status</th>
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Profile</th>
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Findings</th>
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Created</th>
                  <th className="text-left py-3 px-2 font-medium text-gray-500">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan: any) => (
                  <tr key={scan.id} className="border-b border-gray-100 hover:bg-gray-50">
                    <td className="py-3 px-2 font-mono text-xs">{scan.id.slice(0, 8)}</td>
                    <td className="py-3 px-2"><StatusBadge status={scan.status} /></td>
                    <td className="py-3 px-2 capitalize">{scan.profile}</td>
                    <td className="py-3 px-2">{scan.summary?.total_findings ?? '-'}</td>
                    <td className="py-3 px-2 text-gray-500">
                      {new Date(scan.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-2">
                      <Link to={`/scans/${scan.id}`} className="text-brand-600 hover:text-brand-700 font-medium">
                        View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
