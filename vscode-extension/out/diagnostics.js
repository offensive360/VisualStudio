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
exports.DiagnosticsManager = void 0;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const api_1 = require("./api");
const vulnKnowledgeBase_1 = require("./vulnKnowledgeBase");
class DiagnosticsManager {
    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('offensive360');
    }
    clear() {
        this.diagnosticCollection.clear();
    }
    /**
     * Load diagnostics from pre-fetched results (no API call needed).
     * Used when results were already fetched immediately after scan completion.
     */
    loadFromResults(langResults) {
        this.clear();
        this.populateDiagnostics(langResults);
    }
    async loadDiagnostics(api, projectId) {
        this.clear();
        const langResults = await api.getLanguageResults(projectId);
        this.populateDiagnostics(langResults);
    }
    populateDiagnostics(langResults) {
        if (!langResults || langResults.length === 0) {
            return;
        }
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            return;
        }
        const workspacePath = workspaceFolders[0].uri.fsPath;
        const diagnosticsMap = new Map();
        for (const vuln of langResults) {
            const filePath = vuln.filePath || vuln.fileName;
            if (!filePath) {
                continue;
            }
            const fullPath = path.isAbsolute(filePath) ? filePath : path.join(workspacePath, filePath);
            const uri = vscode.Uri.file(fullPath);
            const line = Math.max(0, (vuln.lineNo || 1) - 1);
            const col = Math.max(0, vuln.columnNo || 0);
            // Improved range: try to use code snippet length or line length, fallback to 50
            let endCol = col + 50;
            if (vuln.codeSnippet) {
                endCol = col + Math.max(vuln.codeSnippet.trim().length, 10);
            }
            const range = new vscode.Range(line, col, line, endCol);
            const riskLevel = typeof vuln.riskLevel === 'number' ? vuln.riskLevel : api_1.RISK_LEVEL_FROM_STRING[String(vuln.riskLevel).toUpperCase()] || 2;
            let severity;
            if (riskLevel >= 3) {
                severity = vscode.DiagnosticSeverity.Error; // Critical & High → red
            }
            else if (riskLevel >= 2) {
                severity = vscode.DiagnosticSeverity.Warning; // Medium → amber
            }
            else {
                severity = vscode.DiagnosticSeverity.Information; // Low & Safe → blue
            }
            // Use server-provided recommendation if available, otherwise KB hint
            const recommendation = vuln.recommendation;
            const fixHint = recommendation || (0, vulnKnowledgeBase_1.getFixHint)(vuln.type);
            const effect = vuln.effect;
            let message = `[${vuln.type}] ${vuln.vulnerability}`;
            if (effect) {
                message += `\nImpact: ${effect}`;
            }
            if (fixHint) {
                message += `\nFix: ${fixHint}`;
            }
            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'Offensive360 SAST';
            diagnostic.code = vuln.id;
            // Add filtered references as related information
            if (vuln.references) {
                const safeRefs = (0, vulnKnowledgeBase_1.filterReferences)(vuln.references);
                if (safeRefs.length > 0) {
                    diagnostic.relatedInformation = safeRefs.map(url => new vscode.DiagnosticRelatedInformation(new vscode.Location(vscode.Uri.parse(url), new vscode.Position(0, 0)), `Reference: ${url}`));
                }
            }
            const key = uri.toString();
            if (!diagnosticsMap.has(key)) {
                diagnosticsMap.set(key, []);
            }
            diagnosticsMap.get(key).push(diagnostic);
        }
        for (const [uriStr, diagnostics] of diagnosticsMap) {
            this.diagnosticCollection.set(vscode.Uri.parse(uriStr), diagnostics);
        }
    }
    dispose() {
        this.diagnosticCollection.dispose();
    }
}
exports.DiagnosticsManager = DiagnosticsManager;
//# sourceMappingURL=diagnostics.js.map