// ---------------------------------------------------------------------------
// Diff generator — creates unified diffs for auto-fixable findings
// ---------------------------------------------------------------------------

import type { NormalizedFinding } from '@securescope/shared-types';
import { ScannerCategory } from '@securescope/shared-types';

export class DiffGenerator {
  /**
   * Generate a unified diff string for a finding.
   * In a full implementation, this would read the actual file content
   * and produce a real diff. For the MVP, it generates a template diff
   * based on the finding metadata.
   */
  generateDiff(finding: NormalizedFinding): string {
    switch (finding.category) {
      case ScannerCategory.DependencyScanning:
        return this.generateDepUpdateDiff(finding);
      case ScannerCategory.SAST:
        return this.generateSastFixDiff(finding);
      default:
        return this.generateGenericDiff(finding);
    }
  }

  private generateDepUpdateDiff(finding: NormalizedFinding): string {
    // Parse package name and version from asset_name (format: "pkg@version")
    const match = finding.asset_name.match(/^(.+)@(.+)$/);
    if (!match) return '';

    const [, pkgName, currentVersion] = match;
    // Extract fix version from remediation text
    const fixMatch = finding.remediation.match(/to\s+([\d.]+)/);
    const fixVersion = fixMatch ? fixMatch[1] : 'latest';

    return [
      `--- a/${finding.file_path}`,
      `+++ b/${finding.file_path}`,
      `@@ -1,1 +1,1 @@`,
      `-    "${pkgName}": "${currentVersion}"`,
      `+    "${pkgName}": "^${fixVersion}"`,
    ].join('\n');
  }

  private generateSastFixDiff(finding: NormalizedFinding): string {
    if (!finding.file_path || !finding.line_start) return '';

    return [
      `--- a/${finding.file_path}`,
      `+++ b/${finding.file_path}`,
      `@@ -${finding.line_start},1 +${finding.line_start},1 @@`,
      `- // TODO: Fix ${finding.scanner_rule_id} at line ${finding.line_start}`,
      `+ // Fixed: ${finding.scanner_rule_id} — ${finding.remediation.slice(0, 100)}`,
    ].join('\n');
  }

  private generateGenericDiff(finding: NormalizedFinding): string {
    return [
      `--- a/${finding.file_path || 'unknown'}`,
      `+++ b/${finding.file_path || 'unknown'}`,
      `@@ -${finding.line_start || 1},1 +${finding.line_start || 1},1 @@`,
      `- // Vulnerability: ${finding.title}`,
      `+ // Remediated: ${finding.title}`,
    ].join('\n');
  }
}
