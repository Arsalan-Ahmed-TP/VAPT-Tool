export { ScannerRegistry, scannerRegistry } from './registry.js';
export { BaseScannerAdapter } from './base-adapter.js';
export * from './adapters/index.js';

// Re-export scanner interfaces from shared-types for convenience
export type {
  ScannerAdapter,
  ScannerCapability,
  ScannerInput,
  ScannerRawResult,
  ScannerRegistryEntry,
  ResolvedCredentials,
} from '@securescope/shared-types';
