import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { LangScanResult, DepScanResult, MalwareScanResult, LicenseScanResult } from './api';

const CACHE_DIR = '.SASTO360';
const CACHE_FILE = 'lastScanResults.json';

export interface CachedScanData {
  timestamp: number;
  projectName: string;
  fileHashes: Record<string, string>; // relative path -> MD5 hash
  results: {
    lang: LangScanResult[];
    dep: DepScanResult[];
    malware: MalwareScanResult[];
    license: LicenseScanResult[];
  };
}

/**
 * Returns the workspace root path or null if none.
 */
function getWorkspaceRoot(): string | null {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) { return null; }
  return folders[0].uri.fsPath;
}

/**
 * Get the full path to the cache file for a given root directory.
 */
function getCachePath(rootDir: string): string {
  return path.join(rootDir, CACHE_DIR, CACHE_FILE);
}

/**
 * Ensure the .SASTO360 directory exists.
 */
function ensureCacheDir(rootDir: string): void {
  const dir = path.join(rootDir, CACHE_DIR);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

/**
 * Compute MD5 hash of a file's content.
 */
export function md5File(filePath: string): string {
  const content = fs.readFileSync(filePath);
  return crypto.createHash('md5').update(content).digest('hex');
}

/**
 * Excluded directories and extensions — must match scanner.ts constants.
 */
const EXCLUDED_DIRS = [
  'node_modules', '.git', '.svn', '.hg', '.bzr', 'cvs',
  'bin', 'obj', '.vs', '.idea', '.vscode', '.sasto360',
  '__pycache__', '.pytest_cache', '.tox',
  'vendor', 'packages', 'dist', 'build', 'out',
  '.next', '.nuxt', 'coverage', '.gradle', 'target'
];

const EXCLUDED_EXTENSIONS = [
  '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.jar', '.war', '.ear',
  '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv',
  '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pdb', '.nupkg', '.vsix'
];

/**
 * Recursively collect file hashes for all non-excluded files under a directory.
 * Returns a map of relative path -> MD5 hash.
 */
export function collectFileHashes(
  basePath: string,
  relativePath: string = '',
  progress?: vscode.Progress<{ message?: string; increment?: number }>
): { hashes: Record<string, string>; fileCount: number } {
  const hashes: Record<string, string> = {};
  let fileCount = 0;

  function walk(relPath: string): void {
    const fullPath = relPath ? path.join(basePath, relPath) : basePath;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(fullPath, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const entryRelPath = relPath ? path.join(relPath, entry.name) : entry.name;

      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.includes(entry.name.toLowerCase())) {
          continue;
        }
        walk(entryRelPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (EXCLUDED_EXTENSIONS.includes(ext)) {
          continue;
        }
        const filePath = path.join(basePath, entryRelPath);
        try {
          const stats = fs.statSync(filePath);
          if (stats.size > 50 * 1024 * 1024) {
            continue; // Skip files > 50MB
          }
          hashes[entryRelPath] = md5File(filePath);
          fileCount++;
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  walk(relativePath);
  return { hashes, fileCount };
}

/**
 * Save scan results to the cache file.
 */
export function saveScanCache(
  rootDir: string,
  projectName: string,
  fileHashes: Record<string, string>,
  results: CachedScanData['results']
): void {
  try {
    ensureCacheDir(rootDir);
    const data: CachedScanData = {
      timestamp: Date.now(),
      projectName,
      fileHashes,
      results
    };
    const cachePath = getCachePath(rootDir);
    fs.writeFileSync(cachePath, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    // Best-effort caching — don't crash if write fails
    console.error('Failed to save scan cache:', err);
  }
}

/**
 * Load cached scan results. Returns null if no cache or corrupt.
 */
export function loadScanCache(rootDir: string): CachedScanData | null {
  try {
    const cachePath = getCachePath(rootDir);
    if (!fs.existsSync(cachePath)) { return null; }
    const raw = fs.readFileSync(cachePath, 'utf-8');
    const data: CachedScanData = JSON.parse(raw);
    // Basic validation
    if (!data || !data.results || !data.fileHashes || typeof data.timestamp !== 'number') {
      return null;
    }
    return data;
  } catch {
    // Corrupt cache — ignore
    return null;
  }
}

/**
 * Load cache from the workspace root (convenience).
 */
export function loadWorkspaceCache(): CachedScanData | null {
  const root = getWorkspaceRoot();
  if (!root) { return null; }
  return loadScanCache(root);
}

/**
 * Compare current file hashes against cached hashes.
 * Returns true if any files changed, were added, or were removed.
 */
export function hasFilesChanged(currentHashes: Record<string, string>, cachedHashes: Record<string, string>): boolean {
  const currentKeys = Object.keys(currentHashes);
  const cachedKeys = Object.keys(cachedHashes);

  // Different number of files
  if (currentKeys.length !== cachedKeys.length) { return true; }

  // Check for changed or new files
  for (const key of currentKeys) {
    if (cachedHashes[key] !== currentHashes[key]) {
      return true;
    }
  }

  return false;
}

/**
 * Get list of files that changed between cached and current hashes.
 */
export function getChangedFiles(currentHashes: Record<string, string>, cachedHashes: Record<string, string>): string[] {
  const changed: string[] = [];

  for (const key of Object.keys(currentHashes)) {
    if (cachedHashes[key] !== currentHashes[key]) {
      changed.push(key);
    }
  }

  // Files that were deleted
  for (const key of Object.keys(cachedHashes)) {
    if (!(key in currentHashes)) {
      changed.push(key);
    }
  }

  return changed;
}
