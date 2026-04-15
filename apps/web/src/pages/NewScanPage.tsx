import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation } from '@tanstack/react-query';
import { AlertTriangle, Shield } from 'lucide-react';
import { targetsApi, scansApi } from '../lib/api';

export function NewScanPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState(1);

  // Target fields
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState('git_repository');
  const [location, setLocation] = useState('');
  const [ref, setRef] = useState('');
  const [environment, setEnvironment] = useState('development');
  const [authConfirmed, setAuthConfirmed] = useState(false);

  // Scan fields
  const [profile, setProfile] = useState('safe');
  const [autofixMode, setAutofixMode] = useState('off');
  const [allowSecretVerification, setAllowSecretVerification] = useState(false);
  const [enabledScanners, setEnabledScanners] = useState<string[]>([]);

  const createScan = useMutation({
    mutationFn: async () => {
      const target = await targetsApi.create({
        name,
        source_type: sourceType,
        location,
        ref: ref || undefined,
        environment,
        authorization_confirmed: authConfirmed,
      });

      const scan = await scansApi.create({
        target_id: target.id,
        profile,
        autofix_mode: autofixMode,
        allow_secret_verification: allowSecretVerification,
        enabled_scanners: enabledScanners.length > 0 ? enabledScanners : undefined,
      });

      return scan;
    },
    onSuccess: (scan) => {
      navigate(`/scans/${scan.id}`);
    },
  });

  const scannerOptions = [
    { value: 'sast', label: 'SAST (Static Analysis)' },
    { value: 'dast', label: 'DAST (Dynamic Analysis)' },
    { value: 'secret_scanning', label: 'Secret Scanning' },
    { value: 'dependency_scanning', label: 'Dependency Scanning' },
    { value: 'infra_scanning', label: 'Infrastructure Scanning' },
    { value: 'api_security', label: 'API Security' },
    { value: 'container_scanning', label: 'Container Scanning' },
  ];

  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-bold text-gray-900 mb-2">New Security Scan</h1>
      <p className="text-sm text-gray-500 mb-8">Configure and launch a vulnerability assessment</p>

      {/* Step indicators */}
      <div className="flex items-center gap-4 mb-8">
        {[1, 2, 3].map((s) => (
          <div key={s} className="flex items-center gap-2">
            <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium ${
              step >= s ? 'bg-brand-600 text-white' : 'bg-gray-200 text-gray-500'
            }`}>{s}</div>
            <span className={`text-sm ${step >= s ? 'text-gray-900 font-medium' : 'text-gray-400'}`}>
              {s === 1 ? 'Target' : s === 2 ? 'Configuration' : 'Review'}
            </span>
            {s < 3 && <div className="w-12 h-px bg-gray-300 ml-2" />}
          </div>
        ))}
      </div>

      {/* Step 1: Target */}
      {step === 1 && (
        <div className="card space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Target Name</label>
            <input type="text" className="input" placeholder="My Application" value={name} onChange={(e) => setName(e.target.value)} />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Source Type</label>
            <select className="select" value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="git_repository">Git Repository</option>
              <option value="live_url">Live URL</option>
              <option value="uploaded_archive">Uploaded Archive</option>
              <option value="docker_image">Docker Image</option>
              <option value="kubernetes_manifest">Kubernetes Manifest</option>
              <option value="terraform_directory">Terraform Directory</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              {sourceType === 'git_repository' ? 'Repository URL' : sourceType === 'live_url' ? 'Target URL' : 'Location'}
            </label>
            <input type="text" className="input" placeholder={sourceType === 'git_repository' ? 'https://github.com/...' : 'https://...'} value={location} onChange={(e) => setLocation(e.target.value)} />
          </div>

          {sourceType === 'git_repository' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Branch / Tag (optional)</label>
              <input type="text" className="input" placeholder="main" value={ref} onChange={(e) => setRef(e.target.value)} />
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Environment</label>
            <select className="select" value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              <option value="development">Development</option>
              <option value="qa">QA</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
            {environment === 'production' && (
              <div className="flex items-center gap-2 mt-2 p-3 bg-red-50 rounded-lg text-sm text-red-700">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>Warning: Scanning production environments carries risk. Use safe mode and minimal scope.</span>
              </div>
            )}
          </div>

          <div className="flex items-start gap-3 p-4 bg-yellow-50 rounded-lg border border-yellow-200">
            <Shield className="w-5 h-5 text-yellow-600 flex-shrink-0 mt-0.5" />
            <div>
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={authConfirmed} onChange={(e) => setAuthConfirmed(e.target.checked)} className="rounded" />
                <span className="text-sm font-medium text-gray-700">
                  I confirm I am authorized to scan this target
                </span>
              </label>
              <p className="text-xs text-gray-500 mt-1">
                You must have explicit authorization to perform security testing on this target.
                Unauthorized scanning may violate laws and regulations.
              </p>
            </div>
          </div>

          <div className="flex justify-end">
            <button className="btn-primary" disabled={!name || !location || !authConfirmed} onClick={() => setStep(2)}>
              Next: Configuration
            </button>
          </div>
        </div>
      )}

      {/* Step 2: Configuration */}
      {step === 2 && (
        <div className="card space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Scan Profile</label>
            <select className="select" value={profile} onChange={(e) => setProfile(e.target.value)}>
              <option value="safe">Safe — Non-invasive passive checks only</option>
              <option value="balanced">Balanced — Moderate active testing</option>
              <option value="aggressive">Aggressive — Full active testing (non-production only)</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Auto-Fix Mode</label>
            <select className="select" value={autofixMode} onChange={(e) => setAutofixMode(e.target.value)}>
              <option value="off">Off — No auto-fix suggestions</option>
              <option value="recommend_only">Recommend Only — Show fixes but don't apply</option>
              <option value="approval_required">Approval Required — Suggest fixes, apply on approval</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Scanner Categories</label>
            <p className="text-xs text-gray-500 mb-3">Leave empty to auto-select based on target fingerprint</p>
            <div className="grid grid-cols-2 gap-2">
              {scannerOptions.map((opt) => (
                <label key={opt.value} className="flex items-center gap-2 p-2 rounded border hover:bg-gray-50 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enabledScanners.includes(opt.value)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setEnabledScanners([...enabledScanners, opt.value]);
                      } else {
                        setEnabledScanners(enabledScanners.filter((s) => s !== opt.value));
                      }
                    }}
                    className="rounded"
                  />
                  <span className="text-sm">{opt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <label className="flex items-center gap-2">
            <input type="checkbox" checked={allowSecretVerification} onChange={(e) => setAllowSecretVerification(e.target.checked)} className="rounded" />
            <span className="text-sm text-gray-700">Allow live secret verification (makes outbound calls to verify if secrets are active)</span>
          </label>

          <div className="flex justify-between">
            <button className="btn-secondary" onClick={() => setStep(1)}>Back</button>
            <button className="btn-primary" onClick={() => setStep(3)}>Next: Review</button>
          </div>
        </div>
      )}

      {/* Step 3: Review */}
      {step === 3 && (
        <div className="card space-y-6">
          <h3 className="text-lg font-medium">Review Scan Configuration</h3>

          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-500">Target:</span> <strong>{name}</strong></div>
            <div><span className="text-gray-500">Type:</span> <strong>{sourceType}</strong></div>
            <div><span className="text-gray-500">Location:</span> <strong className="break-all">{location}</strong></div>
            <div><span className="text-gray-500">Environment:</span> <strong className="capitalize">{environment}</strong></div>
            <div><span className="text-gray-500">Profile:</span> <strong className="capitalize">{profile}</strong></div>
            <div><span className="text-gray-500">Auto-fix:</span> <strong>{autofixMode.replace(/_/g, ' ')}</strong></div>
            <div><span className="text-gray-500">Scanners:</span> <strong>{enabledScanners.length > 0 ? enabledScanners.join(', ') : 'Auto-detect'}</strong></div>
            <div><span className="text-gray-500">Secret verification:</span> <strong>{allowSecretVerification ? 'Enabled' : 'Disabled'}</strong></div>
          </div>

          {createScan.isError && (
            <div className="p-4 bg-red-50 rounded-lg text-sm text-red-700">
              Error: {(createScan.error as Error).message}
            </div>
          )}

          <div className="flex justify-between">
            <button className="btn-secondary" onClick={() => setStep(2)}>Back</button>
            <button
              className="btn-primary"
              onClick={() => createScan.mutate()}
              disabled={createScan.isPending}
            >
              {createScan.isPending ? 'Starting Scan...' : 'Start Scan'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
