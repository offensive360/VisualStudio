import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import * as archiver from 'archiver';
import { SastApi, SCAN_STATUS, LangScanResult, DepScanResult, MalwareScanResult, LicenseScanResult, ExternalScanResponse, ExternalScanVuln } from './api';
import { collectFileHashes, loadScanCache, saveScanCache, hasFilesChanged, getChangedFiles, CachedScanData } from './cacheService';

export interface ScanOutput {
  projectId: string;
  projectName: string;
  results: {
    lang: LangScanResult[];
    dep: DepScanResult[];
    malware: MalwareScanResult[];
    license: LicenseScanResult[];
  };
}

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

/** Maximum zip size in bytes before warning the user (100 MB). */
const MAX_ZIP_SIZE_BYTES = 100 * 1024 * 1024;

/** Maximum file count before warning the user. */
const MAX_FILE_COUNT = 5000;

export class Scanner {
  constructor(private api: SastApi) {}

  async scanFolder(folderPath: string, projectName: string, progress: vscode.Progress<{ message?: string; increment?: number }>): Promise<ScanOutput | null> {
    progress.report({ message: 'Zipping folder...', increment: 10 });

    const zipPath = path.join(require('os').tmpdir(), `offensive360_${Date.now()}.zip`);

    try {
      // --- Incremental scan: check if files changed ---
      const cachedData = loadScanCache(folderPath);
      progress.report({ message: 'Computing file hashes...' });
      const { hashes: currentHashes, fileCount } = collectFileHashes(folderPath);

      // Large codebase warning: file count
      if (fileCount > MAX_FILE_COUNT) {
        const choice = await vscode.window.showWarningMessage(
          `This folder contains ${fileCount} files (limit: ${MAX_FILE_COUNT}). Scanning may be slow. Consider scanning a subfolder instead.`,
          'Continue Anyway', 'Cancel'
        );
        if (choice !== 'Continue Anyway') {
          return null;
        }
      }

      if (cachedData && !hasFilesChanged(currentHashes, cachedData.fileHashes)) {
        vscode.window.showInformationMessage('Offensive360: No files changed since last scan. Showing cached results.');
        return {
          projectId: '',
          projectName: cachedData.projectName,
          results: cachedData.results
        };
      }

      if (cachedData) {
        const changedFiles = getChangedFiles(currentHashes, cachedData.fileHashes);
        if (changedFiles.length > 0) {
          vscode.window.showInformationMessage(
            `Offensive360: ${changedFiles.length} file(s) changed since last scan. Scanning full project.`
          );
        }
      }

      await this.zipFolder(folderPath, zipPath, progress);

      // Large codebase warning: zip size
      await this.checkZipSize(zipPath);

      progress.report({ message: 'Uploading to SAST server...', increment: 30 });

      const scanOutput = await this.tryExternalScanWithFallback(zipPath, projectName, progress);

      // Save results to cache
      if (scanOutput) {
        saveScanCache(folderPath, projectName, currentHashes, scanOutput.results);
      }

      return scanOutput;
    } catch (error: any) {
      const statusCode = error?.response?.status;
      const responseBody = error?.response?.data;
      let msg = error.message;
      if (statusCode) {
        msg = `Server returned ${statusCode}`;
        if (responseBody) {
          const bodyStr = typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody);
          if (bodyStr.length > 0 && bodyStr !== '""') {
            msg += `: ${bodyStr.substring(0, 200)}`;
          }
        }
      }
      vscode.window.showErrorMessage(`Offensive360: Scan failed — ${msg}`);
      return null;
    } finally {
      try { require('fs').unlinkSync(zipPath); } catch {}
    }
  }

  async scanWorkspace(progress: vscode.Progress<{ message?: string; increment?: number }>): Promise<ScanOutput | null> {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      vscode.window.showErrorMessage('No workspace folder open. Please open a folder first.');
      return null;
    }

    const workspacePath = folders[0].uri.fsPath;
    const projectName = path.basename(workspacePath);

    progress.report({ message: 'Computing file hashes...', increment: 5 });

    const zipPath = path.join(require('os').tmpdir(), `offensive360_${Date.now()}.zip`);

    try {
      // --- Incremental scan: check if files changed ---
      const cachedData = loadScanCache(workspacePath);
      const { hashes: currentHashes, fileCount } = collectFileHashes(workspacePath);

      // Large codebase warning: file count
      if (fileCount > MAX_FILE_COUNT) {
        const choice = await vscode.window.showWarningMessage(
          `This workspace contains ${fileCount} files (limit: ${MAX_FILE_COUNT}). Scanning may be slow. Consider scanning a subfolder instead.`,
          'Continue Anyway', 'Cancel'
        );
        if (choice !== 'Continue Anyway') {
          return null;
        }
      }

      if (cachedData && !hasFilesChanged(currentHashes, cachedData.fileHashes)) {
        vscode.window.showInformationMessage('Offensive360: No files changed since last scan. Showing cached results.');
        return {
          projectId: '',
          projectName: cachedData.projectName,
          results: cachedData.results
        };
      }

      if (cachedData) {
        const changedFiles = getChangedFiles(currentHashes, cachedData.fileHashes);
        if (changedFiles.length > 0) {
          vscode.window.showInformationMessage(
            `Offensive360: ${changedFiles.length} file(s) changed since last scan. Scanning full project.`
          );
        }
      }

      progress.report({ message: 'Zipping workspace...', increment: 5 });

      await this.zipFolder(workspacePath, zipPath, progress);

      // Large codebase warning: zip size
      await this.checkZipSize(zipPath);

      progress.report({ message: 'Uploading to SAST server...', increment: 30 });

      const scanOutput = await this.tryExternalScanWithFallback(zipPath, projectName, progress);

      // Save results to cache
      if (scanOutput) {
        saveScanCache(workspacePath, projectName, currentHashes, scanOutput.results);
      }

      return scanOutput;
    } catch (error: any) {
      const statusCode = error?.response?.status;
      const responseBody = error?.response?.data;
      let msg = error.message;
      if (statusCode) {
        msg = `Server returned ${statusCode}`;
        if (responseBody) {
          const bodyStr = typeof responseBody === 'string' ? responseBody : JSON.stringify(responseBody);
          if (bodyStr.length > 0 && bodyStr !== '""') {
            msg += `: ${bodyStr.substring(0, 200)}`;
          }
        }
      }
      vscode.window.showErrorMessage(`Offensive360: Scan failed — ${msg}`);
      return null;
    } finally {
      try { fs.unlinkSync(zipPath); } catch {}
    }
  }

  async scanGitRepo(repoUrl: string, projectName: string, branch?: string, progress?: vscode.Progress<{ message?: string; increment?: number }>): Promise<ScanOutput | null> {
    try {
      if (progress) {
        progress.report({ message: 'Submitting Git repo for scanning...', increment: 30 });
      }

      const result = await this.api.scanGitRepo(repoUrl, projectName, branch);
      const projectId = result?.id || result?.projectId || result;

      if (projectId && progress) {
        progress.report({ message: 'Scan queued, waiting for results...', increment: 20 });
        return await this.pollScanAndFetchResults(projectId, projectName, progress);
      }

      return null;
    } catch (error: any) {
      vscode.window.showErrorMessage(`Git scan failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Check zip file size and warn if it exceeds the limit.
   */
  private async checkZipSize(zipPath: string): Promise<void> {
    try {
      const stats = fs.statSync(zipPath);
      if (stats.size > MAX_ZIP_SIZE_BYTES) {
        const sizeMB = (stats.size / (1024 * 1024)).toFixed(1);
        const choice = await vscode.window.showWarningMessage(
          `The project archive is ${sizeMB} MB (limit: 100 MB). Upload may be slow or fail. Consider scanning a subfolder.`,
          'Continue Anyway', 'Cancel'
        );
        if (choice !== 'Continue Anyway') {
          throw new Error('Scan cancelled by user due to large file size.');
        }
      }
    } catch (err: any) {
      if (err.message?.includes('Scan cancelled')) {
        throw err;
      }
      // If we can't stat the file, continue anyway
    }
  }

  /**
   * Try ExternalScan (immediate results). If it fails (403/404), fall back to
   * scanProjectFile + polling. ExternalScan is the preferred path for External tokens.
   */
  private async tryExternalScanWithFallback(zipPath: string, projectName: string, progress: vscode.Progress<{ message?: string; increment?: number }>): Promise<ScanOutput | null> {
    // Always use upload + poll pattern — avoids timeout issues with large projects
    // ExternalScan is a single long request that times out; upload+poll is more reliable
    progress.report({ message: 'Uploading to server...' });

    let projectId: string | null = null;

    try {
      const result = await this.api.scanFileUpload(zipPath, projectName);
      projectId = result?.id || result?.projectId || (typeof result === 'string' ? result : null);
    } catch (uploadErr: any) {
      // If scanProjectFile fails (403), try ExternalScan as fallback for External tokens
      const status = uploadErr?.response?.status;
      if (status === 403) {
        const maxRetries = 2; // 1 initial + 1 retry
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
          try {
            progress.report({ message: attempt > 1 ? 'Retrying ExternalScan...' : 'Scanning (ExternalScan)...' });
            const resp = await this.api.externalScan(zipPath, projectName);
            const langResults = resp.vulnerabilities
              ? SastApi.convertExternalVulns(resp.vulnerabilities)
              : [];
            vscode.window.showInformationMessage(
              `Offensive360: Scan complete — ${langResults.length} vulnerability(ies) found.`
            );

            const externalProjectId = resp.projectId || '';

            const scanOutput: ScanOutput = {
              projectId: externalProjectId,
              projectName,
              results: {
                lang: langResults,
                dep: (resp.dependencyVulnerabilities as any[]) || [],
                malware: (resp.malwares as any[]) || [],
                license: (resp.licenses as any[]) || []
              }
            };

            // Server-side cleanup: delete project from ExternalScan if projectId returned
            if (externalProjectId) {
              await this.api.deleteProject(externalProjectId);
            }

            return scanOutput;
          } catch (extErr: any) {
            const errCode = extErr?.code || '';
            const isTransient = errCode === 'ECONNRESET' || errCode === 'ETIMEDOUT' || errCode === 'ECONNABORTED' || errCode === 'EPIPE';
            if (isTransient && attempt < maxRetries) {
              vscode.window.showWarningMessage(`Offensive360: ExternalScan timed out or connection reset. Retrying (attempt ${attempt + 1}/${maxRetries})...`);
              await new Promise(resolve => setTimeout(resolve, 3000));
              continue;
            }
            const timeoutHint = isTransient ? ' The server may be overloaded or the project is too large. Try scanning a smaller subfolder.' : '';
            throw new Error(`Scan failed: ${extErr.message || 'Server error'}${timeoutHint}`);
          }
        }
      }
      throw uploadErr;
    }

    if (!projectId) {
      throw new Error('No project ID returned from server');
    }

    progress.report({ message: 'Scan queued, waiting for results...', increment: 20 });
    const scanOutput = await this.pollScanAndFetchResults(projectId, projectName, progress);
    // Clean up: delete the project from server dashboard
    await this.api.deleteProject(projectId);
    return scanOutput;
  }

  /**
   * Polls until scan completes, then immediately fetches all results before
   * the server deletes the ephemeral project (KeepInvisibleAndDeletePostScan).
   */
  private async pollScanAndFetchResults(projectId: string, projectName: string, progress: vscode.Progress<{ message?: string; increment?: number }>): Promise<ScanOutput> {
    const maxWait = 60 * 60 * 1000; // 60 minutes max
    const interval = 10000; // 10 seconds
    const startTime = Date.now();
    let firstPoll = true;

    while (Date.now() - startTime < maxWait) {
      try {
        const project = await this.api.getProject(projectId);
        const status = project.status;
        const statusText = SCAN_STATUS[status] || 'Unknown';

        progress.report({ message: `Scan status: ${statusText}...` });

        if (status === 2 || status === 4) { // Succeeded or Partial Failed
          progress.report({ message: 'Retrieving scan results...' });

          // Wait for server to populate vulnerability results
          let waitAttempts = 0;
          while (waitAttempts < 12) {
            const proj = await this.api.getProject(projectId);
            if ((proj as any).vulnerabilitiesCount > 0) break;
            await new Promise(r => setTimeout(r, 5000));
            waitAttempts++;
          }

          const results = await this.api.getAllResults(projectId);

          if (status === 2) {
            vscode.window.showInformationMessage(`Offensive360: Scan completed successfully!`);
          } else {
            vscode.window.showWarningMessage('Offensive360: Scan partially failed. Some results may be available.');
          }

          return { projectId, projectName, results };
        }

        if (status === 3) { // Failed
          throw new Error('Scan failed on server.');
        }

        if (status === 5) { // Skipped
          throw new Error('Scan was skipped by server.');
        }
      } catch (error: any) {
        const statusCode = error?.response?.status;
        if (statusCode === 404) {
          throw new Error('Project not found (404). The scan may have been deleted by the server.');
        }
        if (error.message?.includes('Scan failed') || error.message?.includes('Scan was skipped')) {
          throw error;
        }
        // Other errors: continue polling
      }

      // Short initial delay (3s), then standard interval — avoids missing fast scans
      await new Promise(resolve => setTimeout(resolve, firstPoll ? 3000 : interval));
      firstPoll = false;
    }

    throw new Error('Scan timed out after 60 minutes.');
  }

  private zipFolder(folderPath: string, outputPath: string, progress?: vscode.Progress<{ message?: string; increment?: number }>): Promise<void> {
    return new Promise((resolve, reject) => {
      const output = fs.createWriteStream(outputPath);
      const archive = archiver.default('zip', { zlib: { level: 6 } });

      let fileCounter = 0;

      output.on('close', () => resolve());
      archive.on('error', (err: Error) => reject(err));
      archive.on('entry', () => {
        fileCounter++;
        if (progress && fileCounter % 100 === 0) {
          progress.report({ message: `Zipping files... (${fileCounter} files added)` });
        }
      });

      archive.pipe(output);

      this.addFilesToArchive(archive, folderPath, '');

      archive.finalize();
    });
  }

  private addFilesToArchive(archive: archiver.Archiver, basePath: string, relativePath: string): void {
    const fullPath = relativePath ? path.join(basePath, relativePath) : basePath;
    const entries = fs.readdirSync(fullPath, { withFileTypes: true });

    for (const entry of entries) {
      const entryRelPath = relativePath ? path.join(relativePath, entry.name) : entry.name;

      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.includes(entry.name.toLowerCase())) {
          continue;
        }
        this.addFilesToArchive(archive, basePath, entryRelPath);
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
          archive.file(filePath, { name: entryRelPath });
        } catch {
          // Skip unreadable files
        }
      }
    }
  }
}
