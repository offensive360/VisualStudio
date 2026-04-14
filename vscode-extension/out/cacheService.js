"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.md5File = md5File;
exports.collectFileHashes = collectFileHashes;
exports.saveScanCache = saveScanCache;
exports.loadScanCache = loadScanCache;
exports.loadWorkspaceCache = loadWorkspaceCache;
exports.hasFilesChanged = hasFilesChanged;
exports.getChangedFiles = getChangedFiles;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const crypto = __importStar(require("crypto"));
const CACHE_DIR = '.SASTO360';
const CACHE_FILE = 'lastScanResults.json';
/**
 * Returns the workspace root path or null if none.
 */
function getWorkspaceRoot() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        return null;
    }
    return folders[0].uri.fsPath;
}
/**
 * Get the full path to the cache file for a given root directory.
 */
function getCachePath(rootDir) {
    return path.join(rootDir, CACHE_DIR, CACHE_FILE);
}
/**
 * Ensure the .SASTO360 directory exists.
 */
function ensureCacheDir(rootDir) {
    const dir = path.join(rootDir, CACHE_DIR);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}
/**
 * Compute MD5 hash of a file's content.
 */
function md5File(filePath) {
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
function collectFileHashes(basePath, relativePath = '', progress) {
    const hashes = {};
    let fileCount = 0;
    function walk(relPath) {
        const fullPath = relPath ? path.join(basePath, relPath) : basePath;
        let entries;
        try {
            entries = fs.readdirSync(fullPath, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const entry of entries) {
            const entryRelPath = relPath ? path.join(relPath, entry.name) : entry.name;
            if (entry.isDirectory()) {
                if (EXCLUDED_DIRS.includes(entry.name.toLowerCase())) {
                    continue;
                }
                walk(entryRelPath);
            }
            else if (entry.isFile()) {
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
                }
                catch {
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
function saveScanCache(rootDir, projectName, fileHashes, results) {
    try {
        ensureCacheDir(rootDir);
        const data = {
            timestamp: Date.now(),
            projectName,
            fileHashes,
            results
        };
        const cachePath = getCachePath(rootDir);
        fs.writeFileSync(cachePath, JSON.stringify(data, null, 2), 'utf-8');
    }
    catch (err) {
        // Best-effort caching — don't crash if write fails
        console.error('Failed to save scan cache:', err);
    }
}
/**
 * Load cached scan results. Returns null if no cache or corrupt.
 */
function loadScanCache(rootDir) {
    try {
        const cachePath = getCachePath(rootDir);
        if (!fs.existsSync(cachePath)) {
            return null;
        }
        const raw = fs.readFileSync(cachePath, 'utf-8');
        const data = JSON.parse(raw);
        // Basic validation
        if (!data || !data.results || !data.fileHashes || typeof data.timestamp !== 'number') {
            return null;
        }
        return data;
    }
    catch {
        // Corrupt cache — ignore
        return null;
    }
}
/**
 * Load cache from the workspace root (convenience).
 */
function loadWorkspaceCache() {
    const root = getWorkspaceRoot();
    if (!root) {
        return null;
    }
    return loadScanCache(root);
}
/**
 * Compare current file hashes against cached hashes.
 * Returns true if any files changed, were added, or were removed.
 */
function hasFilesChanged(currentHashes, cachedHashes) {
    const currentKeys = Object.keys(currentHashes);
    const cachedKeys = Object.keys(cachedHashes);
    // Different number of files
    if (currentKeys.length !== cachedKeys.length) {
        return true;
    }
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
function getChangedFiles(currentHashes, cachedHashes) {
    const changed = [];
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
//# sourceMappingURL=cacheService.js.map