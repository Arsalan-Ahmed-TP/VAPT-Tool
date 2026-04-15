// ---------------------------------------------------------------------------
// Target fingerprinting — detect languages, frameworks, API styles, etc.
// ---------------------------------------------------------------------------

import { readdir, readFile, access } from 'node:fs/promises';
import { join, extname } from 'node:path';
import type { TargetFingerprint } from '@securescope/shared-types';
import { ApiStyle } from '@securescope/shared-types';

const LANGUAGE_EXTENSIONS: Record<string, string> = {
  '.ts': 'TypeScript', '.tsx': 'TypeScript', '.js': 'JavaScript', '.jsx': 'JavaScript',
  '.py': 'Python', '.go': 'Go', '.rs': 'Rust', '.java': 'Java',
  '.rb': 'Ruby', '.php': 'PHP', '.cs': 'C#', '.cpp': 'C++', '.c': 'C',
  '.swift': 'Swift', '.kt': 'Kotlin', '.scala': 'Scala',
};

const FRAMEWORK_INDICATORS: Record<string, string[]> = {
  'React': ['react', 'react-dom', 'next'],
  'Vue': ['vue', 'nuxt'],
  'Angular': ['@angular/core'],
  'Express': ['express'],
  'NestJS': ['@nestjs/core'],
  'FastAPI': ['fastapi'],
  'Django': ['django'],
  'Flask': ['flask'],
  'Spring': ['spring-boot'],
  'Rails': ['rails'],
};

const PACKAGE_MANAGERS: Record<string, string> = {
  'package.json': 'npm',
  'yarn.lock': 'yarn',
  'pnpm-lock.yaml': 'pnpm',
  'Pipfile': 'pipenv',
  'requirements.txt': 'pip',
  'pyproject.toml': 'poetry',
  'go.mod': 'go',
  'Cargo.toml': 'cargo',
  'Gemfile': 'bundler',
  'composer.json': 'composer',
  'build.gradle': 'gradle',
  'pom.xml': 'maven',
};

const DEPENDENCY_MANIFESTS = [
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'poetry.lock',
  'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
  'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
  'build.gradle', 'pom.xml',
];

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function collectFiles(dir: string, maxDepth = 3, depth = 0): Promise<string[]> {
  if (depth >= maxDepth) return [];
  const files: string[] = [];

  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'vendor') {
        continue;
      }
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...await collectFiles(fullPath, maxDepth, depth + 1));
      } else {
        files.push(fullPath);
      }
    }
  } catch {
    // Permission denied or read error
  }

  return files;
}

export async function fingerprintTarget(sourcePath: string): Promise<TargetFingerprint> {
  const files = await collectFiles(sourcePath);
  const fileNames = files.map((f) => f.replace(sourcePath + '/', ''));
  const basenames = fileNames.map((f) => f.split('/').pop() || '');

  // Detect languages
  const langSet = new Set<string>();
  for (const file of files) {
    const ext = extname(file);
    const lang = LANGUAGE_EXTENSIONS[ext];
    if (lang) langSet.add(lang);
  }

  // Detect package managers
  const packageManagers = new Set<string>();
  for (const [filename, pm] of Object.entries(PACKAGE_MANAGERS)) {
    if (basenames.includes(filename)) {
      packageManagers.add(pm);
    }
  }

  // Detect dependency manifests
  const depManifests = DEPENDENCY_MANIFESTS.filter((m) => basenames.includes(m));

  // Detect frameworks from package.json
  const frameworks = new Set<string>();
  const pkgJsonPath = join(sourcePath, 'package.json');
  if (await fileExists(pkgJsonPath)) {
    try {
      const content = await readFile(pkgJsonPath, 'utf-8');
      const pkg = JSON.parse(content);
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      for (const [framework, indicators] of Object.entries(FRAMEWORK_INDICATORS)) {
        if (indicators.some((i) => i in allDeps)) {
          frameworks.add(framework);
        }
      }
    } catch { /* ignore parse errors */ }
  }

  // Infrastructure detection
  const hasDockerfile = basenames.some((f) => f === 'Dockerfile' || f.startsWith('Dockerfile.'));
  const hasKubernetes = fileNames.some((f) =>
    f.includes('k8s/') || f.includes('kubernetes/') ||
    f.endsWith('.yaml') && basenames.some((b) => b.includes('deployment') || b.includes('service') || b.includes('ingress')),
  );
  const hasTerraform = fileNames.some((f) => f.endsWith('.tf') || f.endsWith('.tfvars'));
  const hasIac = hasDockerfile || hasKubernetes || hasTerraform;

  // API style detection
  const apiStyles: ApiStyle[] = [];
  const hasGraphQL = fileNames.some((f) => f.endsWith('.graphql') || f.endsWith('.gql')) ||
    basenames.includes('schema.graphql');
  if (hasGraphQL) apiStyles.push(ApiStyle.GraphQL);

  const hasOpenApi = basenames.some((f) => f.includes('swagger') || f.includes('openapi'));
  if (hasOpenApi || frameworks.has('Express') || frameworks.has('NestJS') || frameworks.has('FastAPI')) {
    apiStyles.push(ApiStyle.REST);
  }

  if (apiStyles.length === 0) apiStyles.push(ApiStyle.Unknown);

  // Frontend/backend detection
  const frontendDetected = frameworks.has('React') || frameworks.has('Vue') || frameworks.has('Angular') ||
    fileNames.some((f) => f.includes('src/components') || f.includes('src/pages') || f.includes('public/index.html'));
  const backendDetected = frameworks.has('Express') || frameworks.has('NestJS') || frameworks.has('FastAPI') ||
    frameworks.has('Django') || frameworks.has('Flask') ||
    fileNames.some((f) => f.includes('src/routes') || f.includes('src/controllers') || f.includes('src/api'));

  // Monorepo detection
  const monorepo = basenames.includes('lerna.json') ||
    basenames.includes('turbo.json') ||
    basenames.includes('pnpm-workspace.yaml') ||
    fileNames.some((f) => f.includes('packages/') || f.includes('apps/'));

  return {
    languages: Array.from(langSet),
    frameworks: Array.from(frameworks),
    package_managers: Array.from(packageManagers),
    dependency_manifests: depManifests,
    has_dockerfile: hasDockerfile,
    has_kubernetes: hasKubernetes,
    has_terraform: hasTerraform,
    has_iac: hasIac,
    api_styles: apiStyles,
    detected_endpoints: [], // Populated during DAST scanning
    auth_patterns: [],
    frontend_detected: frontendDetected,
    backend_detected: backendDetected,
    monorepo,
  };
}
