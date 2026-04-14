// ---------------------------------------------------------------------------
// Remediation engine — generates fix proposals from findings
// ---------------------------------------------------------------------------

import type { NormalizedFinding } from '@securescope/shared-types';
import { ScannerCategory, Severity } from '@securescope/shared-types';
import type { RemediationPlan, RemediationStep } from './types.js';
import { DiffGenerator } from './diff-generator.js';

export class RemediationEngine {
  private diffGen = new DiffGenerator();

  /**
   * Analyze findings and produce a remediation plan.
   * Only findings marked autofixable get automated diff proposals.
   * All others get manual guidance.
   */
  generatePlan(scanId: string, findings: NormalizedFinding[]): RemediationPlan {
    const steps: RemediationStep[] = [];

    for (const finding of findings) {
      if (finding.autofixable && finding.file_path) {
        steps.push(this.generateAutoFixStep(finding));
      } else {
        steps.push(this.generateManualStep(finding));
      }
    }

    // Sort by priority (highest first)
    steps.sort((a, b) => b.priority - a.priority);

    const autoFixable = steps.filter((s) => s.safe_to_auto_apply).length;

    return {
      scan_id: scanId,
      total_steps: steps.length,
      auto_fixable: autoFixable,
      manual_only: steps.length - autoFixable,
      steps,
      summary: `${steps.length} remediation steps: ${autoFixable} auto-fixable, ${steps.length - autoFixable} require manual action`,
    };
  }

  private generateAutoFixStep(finding: NormalizedFinding): RemediationStep {
    const diff = this.diffGen.generateDiff(finding);

    return {
      finding_id: finding.finding_id,
      title: `Fix: ${finding.title}`,
      description: finding.remediation,
      file_path: finding.file_path!,
      diff,
      safe_to_auto_apply: this.isSafeToAutoApply(finding),
      risk_notes: this.assessRisk(finding),
      suggested_tests: this.suggestTests(finding),
      priority: finding.priority_score,
    };
  }

  private generateManualStep(finding: NormalizedFinding): RemediationStep {
    return {
      finding_id: finding.finding_id,
      title: `Manual Fix Required: ${finding.title}`,
      description: finding.remediation,
      file_path: finding.file_path || finding.endpoint || 'N/A',
      diff: '', // No automated diff
      safe_to_auto_apply: false,
      risk_notes: 'This finding requires manual review and remediation',
      manual_steps: this.generateManualSteps(finding),
      suggested_tests: this.suggestTests(finding),
      priority: finding.priority_score,
    };
  }

  private isSafeToAutoApply(finding: NormalizedFinding): boolean {
    // Conservative safety check
    if (finding.severity === Severity.Critical) return false; // Critical findings need human review
    if (finding.category === ScannerCategory.SecretScanning) return false; // Secrets need rotation
    if (finding.category === ScannerCategory.DAST) return false; // Runtime issues need manual fix
    if (finding.fix_strategy === 'dependency_update') return true; // Dep updates are generally safe
    if (finding.fix_strategy === 'auto_patch' && finding.confidence === 'high') return true;
    return false;
  }

  private assessRisk(finding: NormalizedFinding): string {
    if (finding.category === ScannerCategory.DependencyScanning) {
      return 'Dependency version update — review changelog for breaking changes before applying';
    }
    if (finding.category === ScannerCategory.SAST) {
      return 'Code patch — verify the fix does not alter business logic';
    }
    return 'Review the change carefully before applying';
  }

  private suggestTests(finding: NormalizedFinding): string[] {
    const tests: string[] = [];

    switch (finding.category) {
      case ScannerCategory.SAST:
        tests.push(`Add unit test verifying ${finding.scanner_rule_id} is no longer triggered`);
        tests.push(`Run existing test suite to check for regressions`);
        break;
      case ScannerCategory.DependencyScanning:
        tests.push(`Run full test suite after dependency update`);
        tests.push(`Verify no breaking API changes from the updated package`);
        break;
      case ScannerCategory.SecretScanning:
        tests.push(`Verify the rotated credential works in all environments`);
        tests.push(`Audit access logs for unauthorized use of the old credential`);
        break;
      case ScannerCategory.DAST:
        tests.push(`Manually verify the endpoint is no longer vulnerable`);
        tests.push(`Run a targeted DAST rescan against the specific endpoint`);
        break;
      default:
        tests.push(`Run relevant test suite to verify the fix`);
    }

    return tests;
  }

  private generateManualSteps(finding: NormalizedFinding): string[] {
    const steps: string[] = [];

    if (finding.category === ScannerCategory.SecretScanning) {
      steps.push('1. Immediately rotate/revoke the exposed credential');
      steps.push('2. Update all systems using this credential');
      steps.push('3. Remove the hardcoded secret from source code');
      steps.push('4. Use a secrets manager or environment variables instead');
      steps.push('5. Audit access logs for unauthorized use');
    } else if (finding.category === ScannerCategory.DAST) {
      steps.push(`1. Review the finding at ${finding.endpoint || 'the affected endpoint'}`);
      steps.push('2. Identify the root cause in the application code');
      steps.push('3. Implement the fix following the remediation guidance');
      steps.push('4. Test the fix locally');
      steps.push('5. Run a targeted DAST scan to verify');
    } else {
      steps.push('1. Review the finding details and evidence');
      steps.push(`2. ${finding.remediation}`);
      steps.push('3. Test the fix');
      steps.push('4. Rerun the scanner to verify');
    }

    return steps;
  }
}
