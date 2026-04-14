// ---------------------------------------------------------------------------
// Base adapter — shared logic for all scanner adapters
// ---------------------------------------------------------------------------

import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import type {
  ScannerAdapter,
  ScannerCapability,
  ScannerInput,
  ScannerRawResult,
  NormalizedFinding,
  TargetFingerprint,
  ScanProfile,
} from '@securescope/shared-types';

export abstract class BaseScannerAdapter implements ScannerAdapter {
  abstract getCapability(): ScannerCapability;
  abstract shouldRun(fingerprint: TargetFingerprint, profile: ScanProfile): boolean;
  abstract parseResults(rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]>;

  /**
   * Build the command-line arguments for the scanner.
   * Subclasses override this to customize invocation.
   */
  protected abstract buildCommand(input: ScannerInput): {
    command: string;
    args: string[];
    env?: Record<string, string>;
  };

  /**
   * Default execution: spawn a child process, capture output, enforce timeout.
   * Subclasses can override execute() entirely for non-CLI scanners.
   */
  async execute(input: ScannerInput): Promise<ScannerRawResult> {
    const startTime = Date.now();
    const { command, args, env } = this.buildCommand(input);

    // Ensure artifact output dir exists
    await mkdir(input.artifact_output_dir, { recursive: true });

    const stdoutPath = join(input.artifact_output_dir, `${this.getCapability().name}-stdout.txt`);
    const stderrPath = join(input.artifact_output_dir, `${this.getCapability().name}-stderr.txt`);

    return new Promise<ScannerRawResult>((resolve) => {
      let stdout = '';
      let stderr = '';
      let killed = false;

      const child = spawn(command, args, {
        env: { ...process.env, ...env },
        cwd: input.source_path,
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      const timer = setTimeout(() => {
        killed = true;
        child.kill('SIGTERM');
        // Give 5s for graceful shutdown, then SIGKILL
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }, input.timeout_ms);

      child.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      child.on('close', async (code) => {
        clearTimeout(timer);
        const duration_ms = Date.now() - startTime;

        // Write captured output to artifact dir
        const artifactPaths: string[] = [];
        try {
          await writeFile(stdoutPath, stdout);
          artifactPaths.push(stdoutPath);
          if (stderr) {
            await writeFile(stderrPath, stderr);
            artifactPaths.push(stderrPath);
          }
        } catch {
          // Best-effort artifact capture
        }

        if (killed) {
          resolve({
            exit_code: code ?? -1,
            artifact_paths: artifactPaths,
            summary: `Scanner timed out after ${input.timeout_ms}ms`,
            duration_ms,
            success: false,
            error: 'Scanner execution timed out',
          });
          return;
        }

        // Many security scanners use non-zero exit codes for "findings found"
        // rather than "error occurred". Each adapter can override this logic.
        const success = this.isSuccessExitCode(code ?? -1);

        resolve({
          exit_code: code ?? -1,
          artifact_paths: artifactPaths,
          summary: success
            ? `Scanner completed in ${duration_ms}ms`
            : `Scanner exited with code ${code}`,
          duration_ms,
          success,
          error: success ? undefined : stderr.slice(0, 2000) || undefined,
        });
      });

      child.on('error', (err) => {
        clearTimeout(timer);
        resolve({
          exit_code: -1,
          artifact_paths: [],
          summary: `Failed to start scanner: ${err.message}`,
          duration_ms: Date.now() - startTime,
          success: false,
          error: err.message,
        });
      });
    });
  }

  /**
   * Whether a given exit code indicates success. Override in subclasses
   * for scanners that use exit codes to signal findings.
   */
  protected isSuccessExitCode(code: number): boolean {
    return code === 0;
  }

  /** Generate a unique finding ID */
  protected generateFindingId(): string {
    return `finding-${randomUUID()}`;
  }
}
