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
exports.O360CodeActionProvider = void 0;
exports.showFixGuidancePanel = showFixGuidancePanel;
const vscode = __importStar(require("vscode"));
const vulnKnowledgeBase_1 = require("./vulnKnowledgeBase");
/**
 * Provides Quick Fix code actions for Offensive360 SAST diagnostics.
 * Shows "View Fix Guidance" and "Open References" actions in the lightbulb menu.
 */
class O360CodeActionProvider {
    provideCodeActions(document, range, context, _token) {
        const actions = [];
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source !== 'Offensive360 SAST') {
                continue;
            }
            // Extract vulnerability type from diagnostic message "[type] description"
            const match = diagnostic.message.match(/^\[([^\]]+)\]/);
            if (!match) {
                continue;
            }
            const vulnType = match[1];
            const kbEntry = (0, vulnKnowledgeBase_1.lookupVuln)(vulnType);
            if (kbEntry) {
                // Action: View Fix Guidance
                const viewFixAction = new vscode.CodeAction(`Offensive360: View fix guidance for ${kbEntry.title}`, vscode.CodeActionKind.QuickFix);
                viewFixAction.command = {
                    command: 'offensive360.showFixGuidance',
                    title: 'View Fix Guidance',
                    arguments: [vulnType]
                };
                viewFixAction.diagnostics = [diagnostic];
                viewFixAction.isPreferred = true;
                actions.push(viewFixAction);
            }
            // Action: Open References (if available, filtered)
            if (diagnostic.relatedInformation && diagnostic.relatedInformation.length > 0) {
                const openRefAction = new vscode.CodeAction(`Offensive360: Open reference links`, vscode.CodeActionKind.QuickFix);
                openRefAction.command = {
                    command: 'offensive360.openReferences',
                    title: 'Open References',
                    arguments: [diagnostic.relatedInformation.map(ri => ri.location.uri.toString())]
                };
                openRefAction.diagnostics = [diagnostic];
                actions.push(openRefAction);
            }
        }
        return actions;
    }
}
exports.O360CodeActionProvider = O360CodeActionProvider;
O360CodeActionProvider.providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
];
/**
 * Creates a webview panel showing fix guidance for a vulnerability.
 */
function showFixGuidancePanel(vulnType) {
    const helpText = (0, vulnKnowledgeBase_1.getFullHelp)(vulnType);
    const kbEntry = (0, vulnKnowledgeBase_1.lookupVuln)(vulnType);
    const title = kbEntry ? `Fix: ${kbEntry.title}` : `Fix Guidance`;
    const panel = vscode.window.createWebviewPanel('offensive360FixGuidance', title, vscode.ViewColumn.Beside, { enableScripts: false });
    panel.webview.html = getWebviewContent(helpText, kbEntry);
}
function getWebviewContent(helpText, kbEntry) {
    if (!kbEntry) {
        return `<!DOCTYPE html>
<html><body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; color: #d4d4d4; background: #1e1e1e;">
<h2>No fix guidance available</h2>
<p>Check the O360 dashboard for more details about this vulnerability.</p>
</body></html>`;
    }
    return `<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; padding: 20px; color: #d4d4d4; background: #1e1e1e; line-height: 1.6; }
  h1 { color: #569cd6; border-bottom: 1px solid #333; padding-bottom: 10px; }
  h2 { color: #4ec9b0; margin-top: 20px; }
  .risk { padding: 8px 12px; border-radius: 4px; margin: 10px 0; }
  .risk-critical { background: #4d1f1f; border-left: 4px solid #f44; }
  .risk-high { background: #4d3a1f; border-left: 4px solid #f90; }
  .risk-medium { background: #4d4d1f; border-left: 4px solid #ff0; }
  .risk-low { background: #1f4d1f; border-left: 4px solid #4f4; }
  code { background: #2d2d2d; padding: 2px 6px; border-radius: 3px; font-family: 'Consolas', monospace; }
  pre { background: #2d2d2d; padding: 12px; border-radius: 6px; overflow-x: auto; }
  .bad { border-left: 4px solid #f44; }
  .good { border-left: 4px solid #4f4; }
  .cwe { color: #888; font-size: 0.9em; }
  .logo { font-size: 24px; margin-bottom: 5px; }
</style>
</head>
<body>
<div class="logo">&#x1F6E1; Offensive360 SAST - Fix Guidance</div>
<h1>${kbEntry.title}</h1>

<h2>Description</h2>
<p>${kbEntry.shortDescription}</p>

<h2>Risk Level</h2>
<div class="risk ${kbEntry.riskExplanation.toLowerCase().includes('critical') ? 'risk-critical' : kbEntry.riskExplanation.toLowerCase().includes('high') ? 'risk-high' : 'risk-medium'}">
${kbEntry.riskExplanation}
</div>

<h2>How to Fix</h2>
<p>${kbEntry.howToFix}</p>

<h2>Vulnerable Code Pattern</h2>
<pre class="bad"><code>${escapeHtml(kbEntry.codePatternBad)}</code></pre>

<h2>Secure Code Pattern</h2>
<pre class="good"><code>${escapeHtml(kbEntry.codePatternGood)}</code></pre>

<p class="cwe">Reference: ${kbEntry.cwes.join(', ')}</p>

<hr style="border-color: #333; margin-top: 30px;">
<p style="color: #666; font-size: 0.85em;">Generated by Offensive360 SAST. For more details, check your O360 dashboard.</p>
</body>
</html>`;
}
function escapeHtml(text) {
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
//# sourceMappingURL=codeActionProvider.js.map