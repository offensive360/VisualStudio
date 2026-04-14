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
exports.ProjectItem = exports.ProjectTreeProvider = void 0;
const vscode = __importStar(require("vscode"));
const api_1 = require("./api");
const vulnKnowledgeBase_1 = require("./vulnKnowledgeBase");
class ProjectTreeProvider {
    constructor(api) {
        this.api = api;
        this._onDidChangeTreeData = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChangeTreeData.event;
        this.cachedResults = null;
    }
    refresh() {
        this._onDidChangeTreeData.fire(undefined);
    }
    /**
     * Store scan results locally so the tree can display them
     * even after the project is deleted from the server.
     */
    setScanResults(projectName, results) {
        this.cachedResults = { projectName, ...results };
        this.refresh();
    }
    async getChildren(element) {
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
                if (rl > maxRisk) {
                    maxRisk = rl;
                }
            }
            const riskText = api_1.RISK_LEVEL[maxRisk] || 'Safe';
            const item = new ProjectItem(`Last Scan - ${r.projectName}`, '', vscode.TreeItemCollapsibleState.Collapsed, 'scan');
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
                const item = new ProjectItem(r.type || r.fileName, '', vscode.TreeItemCollapsibleState.None, 'vulnerability');
                item.description = `${r.fileName} : Line ${r.lineNo}`;
                // Rich tooltip with knowledge base fix guidance
                const kb = (0, vulnKnowledgeBase_1.lookupVuln)(r.type);
                const md = new vscode.MarkdownString();
                md.isTrusted = true;
                md.appendMarkdown(`**${r.type}** — ${api_1.RISK_LEVEL[r.riskLevel] || 'Unknown'} Risk\n\n`);
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
                }
                else if (rl >= 3) {
                    item.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('charts.orange'));
                }
                else if (rl >= 2) {
                    item.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('charts.blue'));
                }
                else {
                    item.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('charts.green'));
                }
                return item;
            });
        }
        return [];
    }
    getTreeItem(element) {
        return element;
    }
}
exports.ProjectTreeProvider = ProjectTreeProvider;
class ProjectItem extends vscode.TreeItem {
    constructor(label, projectId, collapsibleState, contextValue) {
        super(label, collapsibleState);
        this.label = label;
        this.projectId = projectId;
        this.collapsibleState = collapsibleState;
        this.contextValue = contextValue;
    }
}
exports.ProjectItem = ProjectItem;
//# sourceMappingURL=treeProvider.js.map