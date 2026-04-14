// ---------------------------------------------------------------------------
// Scanner adapter interfaces — the contract every scanner must fulfill
// ---------------------------------------------------------------------------

import type { ScannerCategory, ScanProfile } from './enums.js';
import type { NormalizedFinding, ScannerJob, TargetFingerprint } from './models.js';

/**
 * Metadata that each scanner adapter must declare so the orchestrator
 * can plan which scanners to run for a given target.
 */
export interface ScannerCapability {
  /** Unique scanner name, e.g. "semgrep", "zap", "gitleaks" */
  name: string;
  /** Display name */
  displayName: string;
  category: ScannerCategory;
  /** What source types this scanner can handle */
  supported_source_types: string[];
  /** Languages or frameworks the scanner is relevant for (empty = all) */
  relevant_languages: string[];
  /** Minimum scan profile required (safe scanners work in all modes) */
  minimum_profile: ScanProfile;
  /** Whether this scanner needs network access to the target */
  requires_network: boolean;
  /** Whether this scanner operates on source code */
  requires_source: boolean;
  /** Default timeout in milliseconds */
  default_timeout_ms: number;
  /** Whether the scanner can run in a container sandbox */
  supports_container_isolation: boolean;
  /** Version of the underlying tool */
  version: string;
}

/**
 * Input provided to a scanner adapter at execution time.
 */
export interface ScannerInput {
  /** Job metadata */
  job: ScannerJob;
  /** Path to the cloned/extracted source on disk */
  source_path?: string;
  /** Live target URL */
  target_url?: string;
  /** Fingerprint results for the target */
  fingerprint: TargetFingerprint;
  /** Resolved credentials (decrypted, ephemeral) */
  credentials?: ResolvedCredentials;
  /** Active scan profile */
  profile: ScanProfile;
  /** Exclusion patterns */
  exclusions: string[];
  /** Path where raw artifacts should be written */
  artifact_output_dir: string;
  /** Timeout in milliseconds */
  timeout_ms: number;
  /** Whether live secret verification is allowed */
  allow_secret_verification: boolean;
}

export interface ResolvedCredentials {
  bearer_token?: string;
  cookies?: string;
  headers?: Record<string, string>;
  basic_auth?: { username: string; password: string };
  api_key?: string;
}

/**
 * Raw result from a scanner before normalization.
 */
export interface ScannerRawResult {
  /** Exit code of the scanner process */
  exit_code: number;
  /** Path to the raw output file(s) */
  artifact_paths: string[];
  /** Summary line from the scanner */
  summary: string;
  /** Duration in milliseconds */
  duration_ms: number;
  /** Whether the scanner completed successfully */
  success: boolean;
  /** Error message if failed */
  error?: string;
}

/**
 * The adapter interface every scanner must implement.
 * This is the pluggable contract that decouples scanner specifics
 * from the platform core.
 */
export interface ScannerAdapter {
  /** Declare capabilities */
  getCapability(): ScannerCapability;

  /**
   * Determine if this scanner should run for the given fingerprint
   * and scan profile. Allows dynamic opt-in/opt-out.
   */
  shouldRun(fingerprint: TargetFingerprint, profile: ScanProfile): boolean;

  /**
   * Execute the scan. Must write raw artifacts to artifact_output_dir.
   * Should respect timeout_ms and profile constraints.
   */
  execute(input: ScannerInput): Promise<ScannerRawResult>;

  /**
   * Parse raw scanner output into normalized findings.
   */
  parseResults(rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]>;

  /**
   * Optional: validate that the scanner binary/image is available.
   */
  healthCheck?(): Promise<{ healthy: boolean; message: string }>;
}

/**
 * Registry entry for scanner adapters.
 */
export interface ScannerRegistryEntry {
  capability: ScannerCapability;
  factory: () => ScannerAdapter;
}
