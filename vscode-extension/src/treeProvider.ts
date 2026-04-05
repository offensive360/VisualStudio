import * as vscode from 'vscode';
import { SastApi, RISK_LEVEL, LangScanResult, DepScanResult, MalwareScanResult, LicenseScanResult } from './api';
import { lookupVuln } from './vulnKnowledgeBase';

export interface CachedScanResults {
  projectName: string;
  lang: LangScanResult[];
  dep: DepScanResult[];
  malware: MalwareScanResult[];
  license: LicenseScanResult[];
}

export class ProjectTreeProvider implements vscode.TreeDataProvider<ProjectItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<ProjectItem | undefined | null>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
  private cachedResults: CachedScanResults | null = null;

  constructor(private api: SastApi) {}

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  /**
   * Store scan results locally so the tree can display them
   * even after the project is deleted from the server.
   */
  setScanResults(projectName: string, results: { lang: LangScanResult[]; dep: DepScanResult[]; malware: MalwareScanResult[]; license: LicenseScanResult[] }): void {
    this.cachedResults = { projectName, ...results };
    this.refresh();
  }

  async getChildren(element?: ProjectItem): Promise<ProjectItem[]> {
    if (!this.api.isAuthenticated()) {
      return [new ProjectItem('Configure token and endpoint in settings', '', vscode.TreeItemCollapsibleState.None, 'info')];
    }

    if (!element) {
      if (!this.cachedResults) {
        return [new ProjectItem('Scan a workspace to see results', '', vscode.TreeItemCollapsibleState.None, 'info')];
      }

      const r = this.cachedResults;
      const totalVulns = r.lang.length;

      // Determine highest risk level from lang results
      let maxRisk = 0;
      for (const v of r.lang) {
        const rl = typeof v.riskLevel === 'number' ? v.riskLevel : parseInt(String(v.riskLevel)) || 0;
        if (rl > maxRisk) { maxRisk = rl; }
      }
      const riskText = RISK_LEVEL[maxRisk] || 'Safe';

      const item = new ProjectItem(
        `Last Scan - ${r.projectName}`,
        '',
        vscode.TreeItemCollapsibleState.Collapsed,
        'scan'
      );
      item.description = `Succeeded | Risk: ${riskText} | Vulns: ${totalVulns}`;
      item.tooltip = `Status: Succeeded\nRisk: ${riskText}\nVulnerabilities: ${r.lang.length}`;
      item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));

      return [item];
    }

    if (element.contextValue === 'scan') {
      // Show vulnerabilities directly under the scan node
      const results = this.cachedResults?.lang || [];
      if (results.length === 0) {
        return [new ProjectItem('No vulnerabilities found', '', vscode.TreeItemCollapsibleState.None, 'info')];
      }
      return results.map(r => {
        const item = new ProjectItem(
          r.type || r.fileName,
          '',
          vscode.TreeItemCollapsibleState.None,
          'vulnerability'
        );
        item.description = `${r.fileName} : Line ${r.lineNo}`;

        // Rich tooltip with knowledge base fix guidance
        const kb = lookupVuln(r.type);
        const md = new vscode.MarkdownString();
        md.isTrusted = true;
        md.appendMarkdown(`**${r.type}** — ${RISK_LEVEL[r.riskLevel] || 'Unknown'} Risk\n\n`);
        md.appendMarkdown(`${r.vulnerability}\n\n`);
        md.appendMarkdown(`**File:** ${r.filePath} (Line ${r.lineNo}, Col ${r.columnNo})\n\n`);
        if (r.codeSnippet) {
          md.appendMarkdown(`**Code:** \`${r.codeSnippet.trim()}\`\n\n`);
        }
        if (kb) {
          md.appendMarkdown(`---\n\n`);
          md.appendMarkdown(`**How to Fix:** ${kb.howToFix}\n\n`);
          md.appendMarkdown(`**Secure Pattern:** \`${kb.codePatternGood}\`\n\n`);
          md.appendMarkdown(`*${kb.cwes.join(', ')}*`);
        }
        item.tooltip = md;
        item.command = {
          command: 'offensive360.openVulnFile',
          title: 'Open File',
          arguments: [r.filePath, String(r.lineNo)]
        };

        const rl = typeof r.riskLevel === 'number' ? r.riskLevel : parseInt(String(r.riskLevel));
        if (rl >= 4) {
          item.iconPath = new vscode.ThemeIcon('flame', new vscode.ThemeColor('charts.red'));
        } else if (rl >= 3) {
          item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.orange'));
        } else if (rl >= 2) {
          item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('charts.blue'));
        } else {
          item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('charts.green'));
        }

        return item;
      });
    }

    return [];
  }

  getTreeItem(element: ProjectItem): vscode.TreeItem {
    return element;
  }
}

export class ProjectItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly projectId: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly contextValue: string
  ) {
    super(label, collapsibleState);
  }
}
