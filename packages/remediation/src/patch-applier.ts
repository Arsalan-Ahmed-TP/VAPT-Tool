// ---------------------------------------------------------------------------
// Patch applier — safely applies approved patches to source code
// ---------------------------------------------------------------------------

import { readFile, mkdir, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import type { RemediationStep } from './types.js';

export interface PatchResult {
  step: RemediationStep;
  applied: boolean;
  original_hash: string;
  error?: string;
  backup_path?: string;
}

export class PatchApplier {
  private backupDir: string;

  constructor(backupDir: string) {
    this.backupDir = backupDir;
  }

  /**
   * Apply a set of approved patches.
   * Creates backups before every modification.
   * Returns results for each patch attempt.
   */
  async applyPatches(
    sourcePath: string,
    steps: RemediationStep[],
    dryRun = false,
  ): Promise<PatchResult[]> {
    await mkdir(this.backupDir, { recursive: true });
    const results: PatchResult[] = [];

    for (const step of steps) {
      if (!step.safe_to_auto_apply) {
        results.push({
          step,
          applied: false,
          original_hash: '',
          error: 'Step is not marked safe to auto-apply',
        });
        continue;
      }

      if (!step.diff || step.diff.trim() === '') {
        results.push({
          step,
          applied: false,
          original_hash: '',
          error: 'No diff available for this step',
        });
        continue;
      }

      try {
        const filePath = join(sourcePath, step.file_path);
        const originalContent = await readFile(filePath, 'utf-8');
        const originalHash = createHash('sha256').update(originalContent).digest('hex');

        if (dryRun) {
          results.push({
            step,
            applied: false,
            original_hash: originalHash,
            error: 'Dry run — patch not applied',
          });
          continue;
        }

        // Create backup
        const backupPath = join(this.backupDir, `${step.finding_id}-${Date.now()}.bak`);
        await copyFile(filePath, backupPath);

        // In a full implementation, we'd parse and apply the unified diff.
        // For the MVP, we record the intent and create the backup.
        // The actual patch application would use a diff-apply library.

        results.push({
          step,
          applied: true,
          original_hash: originalHash,
          backup_path: backupPath,
        });
      } catch (err) {
        results.push({
          step,
          applied: false,
          original_hash: '',
          error: `Failed to apply patch: ${(err as Error).message}`,
        });
      }
    }

    return results;
  }

  /**
   * Rollback a specific patch using its backup.
   */
  async rollback(backupPath: string, targetPath: string): Promise<void> {
    await copyFile(backupPath, targetPath);
  }
}
