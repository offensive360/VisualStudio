import * as vscode from 'vscode';
import { SastApi, AuthValidationResult } from './api';
import { ProjectTreeProvider } from './treeProvider';
import { Scanner } from './scanner';
import { DiagnosticsManager } from './diagnostics';
import { O360CodeActionProvider, showFixGuidancePanel } from './codeActionProvider';
import { loadWorkspaceCache, collectFileHashes, hasFilesChanged } from './cacheService';

// Apply SSL override early if configured
const earlyConfig = vscode.workspace.getConfiguration('o360');
if (earlyConfig.get<boolean>('allowSelfSignedCerts')) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

let api: SastApi;
let projectTree: ProjectTreeProvider;
let scanner: Scanner;
let diagnostics: DiagnosticsManager;
let statusBarItem: vscode.StatusBarItem;

/** Concurrent scan prevention flag */
let scanInProgress = false;

/**
 * Checks auth status and shows appropriate error message.
 * Returns true if authenticated, false otherwise.
 */
async function checkAuthAndNotify(): Promise<boolean> {
  const status = api.getTokenStatus();
  if (status.ok) { return true; }

  let actionLabel = 'Configure Now';
  if (status.errorType === 'expired') {
    actionLabel = 'Update Token';
  }

  const action = await vscode.window.showWarningMessage(
    `Offensive360: ${status.message}`,
    actionLabel
  );
  if (action) {
    vscode.commands.executeCommand('offensive360.configure');
  }
  return false;
}

/**
 * Guard against concurrent scans. Returns true if scan can proceed.
 */
function acquireScanLock(): boolean {
  if (scanInProgress) {
    vscode.window.showWarningMessage('Offensive360: A scan is already in progress. Please wait for it to finish.');
    return false;
  }
  scanInProgress = true;
  return true;
}

function releaseScanLock(): void {
  scanInProgress = false;
}

function updateStatusBar(): void {
  if (!statusBarItem) { return; }

  const status = api.getTokenStatus();

  if (status.errorType === 'not_configured') {
    statusBarItem.text = '$(shield) O360: Not Configured';
    statusBarItem.tooltip = 'Click to configure Offensive360 SAST';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
  } else if (status.errorType === 'expired') {
    statusBarItem.text = '$(shield) O360: Token Expired';
    statusBarItem.tooltip = 'Your API token has expired. Click to update.';
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  } else if (status.ok) {
    const daysText = status.remainingDays !== undefined && status.remainingDays !== Infinity && status.remainingDays <= 7
      ? ` (expires in ${status.remainingDays}d)`
      : '';
    statusBarItem.text = `$(shield) O360: Connected${daysText}`;
    statusBarItem.tooltip = status.expiresAt
      ? `Connected to O360 server. Token expires: ${status.expiresAt.toLocaleDateString()}`
      : 'Connected to O360 server';
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = '$(shield) O360: Error';
    statusBarItem.tooltip = status.message;
    statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
  }

  statusBarItem.show();
}

const CURRENT_VERSION = '1.1.0';
const UPDATE_MANIFEST_URL = 'https://raw.githubusercontent.com/offensive360/intellij/main/update-manifest.json';

function checkForUpdate() {
  const https = require('https');
  const http = require('http');
  const get = UPDATE_MANIFEST_URL.startsWith('https') ? https.get : http.get;

  get(UPDATE_MANIFEST_URL, { timeout: 10000 }, (res: any) => {
    let data = '';
    res.on('data', (chunk: string) => data += chunk);
    res.on('end', () => {
      try {
        const manifest = JSON.parse(data);
        const latest = manifest?.vscode?.version;
        const downloadUrl = manifest?.vscode?.downloadUrl;
        const notes = manifest?.vscode?.releaseNotes;

        if (latest && latest !== CURRENT_VERSION) {
          const parts = (v: string) => v.split('.').map(Number);
          const l = parts(latest), c = parts(CURRENT_VERSION);
          const isNewer = l[0] > c[0] || (l[0] === c[0] && l[1] > c[1]) || (l[0] === c[0] && l[1] === c[1] && l[2] > c[2]);

          if (isNewer) {
            vscode.window.showInformationMessage(
              `O360 SAST: Version ${latest} is available. ${notes || ''}`,
              'Download Update'
            ).then(choice => {
              if (choice === 'Download Update' && downloadUrl) {
                vscode.env.openExternal(vscode.Uri.parse(downloadUrl));
              }
            });
          }
        }
      } catch {}
    });
  }).on('error', () => {});
}

/**
 * Try to load cached scan results from .SASTO360/lastScanResults.json
 * and populate the tree view and diagnostics.
 */
function loadCachedResultsOnActivation(): void {
  try {
    const cached = loadWorkspaceCache();
    if (cached && cached.results) {
      // Check if files have changed since the cache was saved
      const folders = vscode.workspace.workspaceFolders;
      if (folders && folders.length > 0) {
        const workspacePath = folders[0].uri.fsPath;
        const { hashes: currentHashes } = collectFileHashes(workspacePath);
        if (hasFilesChanged(currentHashes, cached.fileHashes)) {
          vscode.window.showInformationMessage(
            'Offensive360: Code has changed since last scan. Run a new scan for updated results.'
          );
          return;
        }
      }

      projectTree.setScanResults(cached.projectName, cached.results);
      diagnostics.loadFromResults(cached.results.lang);
      const totalVulns = cached.results.lang.length + cached.results.dep.length
        + cached.results.malware.length + cached.results.license.length;
      if (totalVulns > 0) {
        const age = Date.now() - cached.timestamp;
        const ageHours = Math.floor(age / (1000 * 60 * 60));
        const ageText = ageHours < 1 ? 'less than an hour' : `${ageHours} hour(s)`;
        vscode.window.showInformationMessage(
          `Offensive360: Loaded ${totalVulns} cached result(s) from ${ageText} ago.`
        );
      }
    }
  } catch {
    // Ignore errors loading cache — don't block activation
  }
}

export function activate(context: vscode.ExtensionContext) {
  api = new SastApi();
  projectTree = new ProjectTreeProvider(api);
  scanner = new Scanner(api);
  diagnostics = new DiagnosticsManager();

  // Check for updates in background
  checkForUpdate();

  // Status bar item
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = 'offensive360.configure';
  updateStatusBar();
  context.subscriptions.push(statusBarItem);

  // Register scan results tree view
  const treeView = vscode.window.createTreeView('offensive360.results', {
    treeDataProvider: projectTree,
    showCollapseAll: true
  });

  // Register Code Action Provider for Quick Fix guidance
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider('*', new O360CodeActionProvider(), {
      providedCodeActionKinds: O360CodeActionProvider.providedCodeActionKinds
    })
  );

  // Show Fix Guidance command (opens webview panel)
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.showFixGuidance', (vulnType: string) => {
      showFixGuidancePanel(vulnType);
    })
  );

  // Open References command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.openReferences', (urls: string[]) => {
      for (const url of urls) {
        vscode.env.openExternal(vscode.Uri.parse(url));
      }
    })
  );

  // Configure settings command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.configure', async () => {
      const currentConfig = vscode.workspace.getConfiguration('o360');
      const endpoint = await vscode.window.showInputBox({
        prompt: 'Enter O360 Server URL',
        value: currentConfig.get('endpoint') || 'https://sast.offensive360.com',
        placeHolder: 'https://sast.offensive360.com:1800'
      });

      if (!endpoint) { return; }

      await vscode.workspace.getConfiguration('o360').update('endpoint', endpoint, vscode.ConfigurationTarget.Global);

      const token = await vscode.window.showInputBox({
        prompt: 'Enter API Access Token (from O360 Dashboard > Settings > Tokens)',
        password: true,
        placeHolder: 'Paste your API token here'
      });

      if (!token) { return; }

      if (!token.startsWith('ey')) {
        vscode.window.showErrorMessage('Offensive360: Invalid token format. The token should be a JWT starting with "ey". Please check with your administrator.');
        return;
      }

      await vscode.workspace.getConfiguration('o360').update('accessToken', token, vscode.ConfigurationTarget.Global);
      api.loadConfig();
      updateStatusBar();

      vscode.window.showInformationMessage('Offensive360: Configuration saved successfully!');
      projectTree.refresh();
    })
  );

  // Scan workspace command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.scan', async () => {
      if (!(await checkAuthAndNotify())) { return; }
      if (!acquireScanLock()) { return; }

      try {
        await vscode.window.withProgress({
          location: vscode.ProgressLocation.Notification,
          title: 'Offensive360 SAST Scan',
          cancellable: false
        }, async (progress) => {
          try {
            const scanOutput = await scanner.scanWorkspace(progress);
            if (scanOutput) {
              projectTree.setScanResults(scanOutput.projectName, scanOutput.results);
              diagnostics.loadFromResults(scanOutput.results.lang);
            }
          } catch (error: any) {
            vscode.window.showErrorMessage(`Offensive360: Scan failed — ${error.message}`);
          }
        });
      } finally {
        releaseScanLock();
      }
    })
  );

  // Scan folder command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.scanFolder', async (folderUri: vscode.Uri) => {
      if (!(await checkAuthAndNotify())) { return; }
      if (!acquireScanLock()) { return; }

      const folderPath = folderUri?.fsPath;
      if (!folderPath) {
        vscode.window.showErrorMessage('Offensive360: No folder selected. Right-click a folder in the Explorer to scan it.');
        releaseScanLock();
        return;
      }

      const folderName = require('path').basename(folderPath);

      try {
        await vscode.window.withProgress({
          location: vscode.ProgressLocation.Notification,
          title: `Offensive360 SAST Scan: ${folderName}`,
          cancellable: false
        }, async (progress) => {
          try {
            const scanOutput = await scanner.scanFolder(folderPath, folderName, progress);
            if (scanOutput) {
              projectTree.setScanResults(scanOutput.projectName, scanOutput.results);
              diagnostics.loadFromResults(scanOutput.results.lang);
              vscode.window.showInformationMessage(`Offensive360: Scan completed for "${folderName}".`);
            }
          } catch (error: any) {
            vscode.window.showErrorMessage(`Offensive360: Scan failed for "${folderName}" — ${error.message}`);
          }
        });
      } finally {
        releaseScanLock();
      }
    })
  );

  // Scan file command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.scanFile', async (fileUri: vscode.Uri) => {
      if (!(await checkAuthAndNotify())) { return; }
      if (!acquireScanLock()) { return; }

      const filePath = fileUri?.fsPath;
      if (!filePath) {
        vscode.window.showErrorMessage('Offensive360: No file selected. Right-click a file in the Explorer to scan it.');
        releaseScanLock();
        return;
      }

      const fileName = require('path').basename(filePath);
      const folderPath = require('path').dirname(filePath);

      try {
        await vscode.window.withProgress({
          location: vscode.ProgressLocation.Notification,
          title: `Offensive360 SAST Scan: ${fileName}`,
          cancellable: false
        }, async (progress) => {
          try {
            const scanOutput = await scanner.scanFolder(folderPath, fileName, progress);
            if (scanOutput) {
              projectTree.setScanResults(scanOutput.projectName, scanOutput.results);
              diagnostics.loadFromResults(scanOutput.results.lang);
              vscode.window.showInformationMessage(`Offensive360: Scan completed for "${fileName}".`);
            }
          } catch (error: any) {
            vscode.window.showErrorMessage(`Offensive360: Scan failed for "${fileName}" — ${error.message}`);
          }
        });
      } finally {
        releaseScanLock();
      }
    })
  );

  // Scan Git repo command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.scanGitRepo', async () => {
      if (!(await checkAuthAndNotify())) { return; }
      if (!acquireScanLock()) { return; }

      const repoUrl = await vscode.window.showInputBox({
        prompt: 'Enter Git Repository URL',
        placeHolder: 'https://github.com/user/repo'
      });
      if (!repoUrl) {
        releaseScanLock();
        return;
      }

      const projectName = await vscode.window.showInputBox({
        prompt: 'Enter Project Name',
        value: repoUrl.split('/').pop()?.replace('.git', '') || 'project'
      });
      if (!projectName) {
        releaseScanLock();
        return;
      }

      const branch = await vscode.window.showInputBox({
        prompt: 'Enter Branch (leave empty for default)',
        placeHolder: 'main'
      });

      try {
        await vscode.window.withProgress({
          location: vscode.ProgressLocation.Notification,
          title: 'Offensive360 SAST Git Scan',
          cancellable: false
        }, async (progress) => {
          try {
            const scanOutput = await scanner.scanGitRepo(repoUrl, projectName, branch || undefined, progress);
            if (scanOutput) {
              projectTree.setScanResults(scanOutput.projectName, scanOutput.results);
              diagnostics.loadFromResults(scanOutput.results.lang);
            }
          } catch (error: any) {
            vscode.window.showErrorMessage(`Offensive360: Git scan failed — ${error.message}`);
          }
        });
      } finally {
        releaseScanLock();
      }
    })
  );

  // View results command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.viewResults', async () => {
      if (!(await checkAuthAndNotify())) { return; }
      projectTree.refresh();
      vscode.commands.executeCommand('offensive360.results.focus');
    })
  );

  // Open vulnerability file command
  context.subscriptions.push(
    vscode.commands.registerCommand('offensive360.openVulnFile', async (filePath: string, lineNumber: string) => {
      if (!filePath) { return; }

      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders) { return; }

      const fullPath = require('path').isAbsolute(filePath)
        ? filePath
        : require('path').join(workspaceFolders[0].uri.fsPath, filePath);

      try {
        const uri = vscode.Uri.file(fullPath);
        const doc = await vscode.workspace.openTextDocument(uri);
        let line = 0;
        if (lineNumber) {
          const parts = lineNumber.split(',');
          line = Math.max(0, parseInt(parts[0] || '0') - 1);
        }
        const editor = await vscode.window.showTextDocument(doc);
        const pos = new vscode.Position(line, 0);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
      } catch {
        vscode.window.showWarningMessage(`Offensive360: Cannot open file "${fullPath}". It may have been moved or deleted.`);
      }
    })
  );

  // Listen for config changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('o360')) {
        api.loadConfig();
        updateStatusBar();
        projectTree.refresh();
      }
    })
  );

  // Load cached results on activation (before auth check — cache is local)
  loadCachedResultsOnActivation();

  // Auto-refresh if already authenticated
  if (api.isAuthenticated()) {
    projectTree.refresh();
  }

  context.subscriptions.push(treeView);
  context.subscriptions.push(diagnostics);
}

export function deactivate() {
  if (diagnostics) {
    diagnostics.dispose();
  }
}
