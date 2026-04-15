import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/layout/Layout';
import { DashboardPage } from './pages/DashboardPage';
import { NewScanPage } from './pages/NewScanPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import { RemediationPage } from './pages/RemediationPage';
import { SettingsPage } from './pages/SettingsPage';

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/scans/new" element={<NewScanPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/scans/:id/findings" element={<FindingsPage />} />
        <Route path="/scans/:id/remediation" element={<RemediationPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
