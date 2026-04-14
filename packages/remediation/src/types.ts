import type { NormalizedFinding, Severity, ScannerCategory } from '@securescope/shared-types';

export interface RemediationStep {
  finding_id: string;
  title: string;
  description: string;
  file_path: string;
  diff: string;
  safe_to_auto_apply: boolean;
  risk_notes?: string;
  suggested_tests?: string[];
  manual_steps?: string[];
  priority: number;
}

export interface RemediationPlan {
  scan_id: string;
  total_steps: number;
  auto_fixable: number;
  manual_only: number;
  steps: RemediationStep[];
  summary: string;
}
