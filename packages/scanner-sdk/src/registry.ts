// ---------------------------------------------------------------------------
// Scanner Registry — central catalog of all available scanner adapters
// ---------------------------------------------------------------------------

import type {
  ScannerAdapter,
  ScannerCapability,
  ScannerRegistryEntry,
  ScanProfile,
  TargetFingerprint,
  ScannerCategory,
} from '@securescope/shared-types';

export class ScannerRegistry {
  private entries = new Map<string, ScannerRegistryEntry>();

  /** Register a scanner adapter factory */
  register(capability: ScannerCapability, factory: () => ScannerAdapter): void {
    if (this.entries.has(capability.name)) {
      throw new Error(`Scanner "${capability.name}" is already registered`);
    }
    this.entries.set(capability.name, { capability, factory });
  }

  /** Unregister a scanner */
  unregister(name: string): boolean {
    return this.entries.delete(name);
  }

  /** Get all registered scanner capabilities */
  listCapabilities(): ScannerCapability[] {
    return Array.from(this.entries.values()).map((e) => e.capability);
  }

  /** Get a scanner adapter instance by name */
  getAdapter(name: string): ScannerAdapter {
    const entry = this.entries.get(name);
    if (!entry) {
      throw new Error(`Scanner "${name}" is not registered`);
    }
    return entry.factory();
  }

  /**
   * Select which scanners should run for a given target, profile, and
   * optional category filter.
   */
  selectScanners(
    fingerprint: TargetFingerprint,
    profile: ScanProfile,
    enabledCategories?: ScannerCategory[],
  ): ScannerAdapter[] {
    const selected: ScannerAdapter[] = [];

    for (const entry of this.entries.values()) {
      // Filter by category if specified
      if (enabledCategories && enabledCategories.length > 0) {
        if (!enabledCategories.includes(entry.capability.category)) {
          continue;
        }
      }

      const adapter = entry.factory();
      if (adapter.shouldRun(fingerprint, profile)) {
        selected.push(adapter);
      }
    }

    return selected;
  }

  /** Check health of all registered scanners */
  async healthCheckAll(): Promise<Map<string, { healthy: boolean; message: string }>> {
    const results = new Map<string, { healthy: boolean; message: string }>();

    for (const [name, entry] of this.entries) {
      const adapter = entry.factory();
      if (adapter.healthCheck) {
        try {
          results.set(name, await adapter.healthCheck());
        } catch (err) {
          results.set(name, {
            healthy: false,
            message: `Health check threw: ${err instanceof Error ? err.message : String(err)}`,
          });
        }
      } else {
        results.set(name, { healthy: true, message: 'No health check implemented' });
      }
    }

    return results;
  }
}

/** Singleton registry instance */
export const scannerRegistry = new ScannerRegistry();
