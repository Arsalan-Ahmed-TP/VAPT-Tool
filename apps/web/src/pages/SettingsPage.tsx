import { useState } from 'react';
import { Settings, Key, Plug } from 'lucide-react';

export function SettingsPage() {
  const [activeTab, setActiveTab] = useState('general');

  const tabs = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'credentials', label: 'Credentials', icon: Key },
    { id: 'integrations', label: 'Integrations', icon: Plug },
  ];

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Settings</h1>

      <div className="flex gap-6">
        {/* Sidebar */}
        <nav className="w-48 space-y-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                activeTab === tab.id
                  ? 'bg-brand-50 text-brand-700 font-medium'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'general' && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">General Settings</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Default Scan Profile</label>
                  <select className="select max-w-xs">
                    <option value="safe">Safe</option>
                    <option value="balanced">Balanced</option>
                    <option value="aggressive">Aggressive</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Default Report Formats</label>
                  <div className="flex gap-3">
                    {['HTML', 'JSON', 'Markdown', 'CSV', 'SARIF'].map((fmt) => (
                      <label key={fmt} className="flex items-center gap-1.5 text-sm">
                        <input type="checkbox" className="rounded" defaultChecked={fmt === 'HTML' || fmt === 'JSON'} />
                        {fmt}
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Scanner Timeout (seconds)</label>
                  <input type="number" className="input max-w-xs" defaultValue={300} />
                </div>
                <button className="btn-primary mt-4">Save Settings</button>
              </div>
            </div>
          )}

          {activeTab === 'credentials' && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Credential Profiles</h2>
              <p className="text-sm text-gray-500 mb-4">
                Credentials are encrypted at rest and never displayed in raw form.
              </p>
              <button className="btn-primary mb-4">Add Credential</button>
              <div className="text-center py-8 text-gray-400">
                No credentials configured yet
              </div>
            </div>
          )}

          {activeTab === 'integrations' && (
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Integrations</h2>
              <p className="text-sm text-gray-500 mb-4">
                Connect external services for notifications and issue tracking.
              </p>
              <div className="grid grid-cols-2 gap-4">
                {['Jira', 'Slack', 'GitHub', 'GitLab', 'Webhook'].map((svc) => (
                  <div key={svc} className="p-4 border rounded-lg flex items-center justify-between">
                    <div>
                      <h3 className="font-medium">{svc}</h3>
                      <p className="text-xs text-gray-400">Not configured</p>
                    </div>
                    <button className="btn-secondary text-sm">Configure</button>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
