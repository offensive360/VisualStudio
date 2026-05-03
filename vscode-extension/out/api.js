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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SastApi = exports.RISK_LEVEL_FROM_STRING = exports.RISK_LEVEL = exports.SCAN_STATUS = void 0;
const axios_1 = __importDefault(require("axios"));
const https = __importStar(require("https"));
const vscode = __importStar(require("vscode"));
const form_data_1 = __importDefault(require("form-data"));
const fs = __importStar(require("fs"));
const vulnKnowledgeBase_1 = require("./vulnKnowledgeBase");
// Output channel for logging (created lazily)
let outputChannel = null;
function getOutputChannel() {
    if (!outputChannel) {
        outputChannel = vscode.window.createOutputChannel('Offensive360 SAST');
    }
    return outputChannel;
}
function logError(context, error) {
    const ch = getOutputChannel();
    const msg = error instanceof Error ? error.message : String(error);
    const status = error?.response?.status;
    ch.appendLine(`[${new Date().toISOString()}] ERROR in ${context}: ${msg}${status ? ` (HTTP ${status})` : ''}`);
}
function logInfo(context, message) {
    getOutputChannel().appendLine(`[${new Date().toISOString()}] INFO ${context}: ${message}`);
}
exports.SCAN_STATUS = {
    0: 'Queued',
    1: 'Running',
    2: 'Succeeded',
    3: 'Failed',
    4: 'Partial Failed',
    5: 'Skipped'
};
exports.RISK_LEVEL = {
    0: 'Safe',
    1: 'Low',
    2: 'Medium',
    3: 'High',
    4: 'Critical'
};
exports.RISK_LEVEL_FROM_STRING = {
    'SAFE': 0,
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4
};
class SastApi {
    constructor() {
        this.token = '';
        this.baseUrl = '';
        this.client = axios_1.default.create({ timeout: 600000 });
        this.loadConfig();
    }
    loadConfig() {
        const config = vscode.workspace.getConfiguration('o360');
        this.baseUrl = (config.get('endpoint') || 'https://sast.offensive360.com').replace(/\/+$/, '');
        this.token = config.get('accessToken') || '';
        const allowSelfSigned = config.get('allowSelfSignedCerts') || false;
        // Load corporate root CA if NODE_EXTRA_CA_CERTS env var is set, OR from o360.extraCaCerts setting.
        // This is needed on Windows behind TLS-intercepting proxies (Zscaler, Netskope, etc).
        let extraCa;
        const extraCaPath = config.get('extraCaCerts') || process.env.NODE_EXTRA_CA_CERTS;
        if (extraCaPath) {
            try {
                extraCa = fs.readFileSync(extraCaPath);
            }
            catch (e) {
                logError('loadConfig.extraCaCerts', e);
            }
        }
        // Always use a keep-alive agent. Default Node.js global agent on Windows
        // can drop sockets aggressively under TLS-intercepting proxies → "socket hang up".
        const agentOpts = {
            keepAlive: true,
            keepAliveMsecs: 30000,
            rejectUnauthorized: !allowSelfSigned,
        };
        if (extraCa) {
            agentOpts.ca = extraCa;
        }
        this.httpsAgent = new https.Agent(agentOpts);
        if (allowSelfSigned) {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
        }
        else {
            delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        }
        this.client = axios_1.default.create({
            baseURL: this.baseUrl,
            timeout: 600000,
            httpsAgent: this.httpsAgent,
            headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
            // Surface socket-level failures clearly instead of swallowing them
            validateStatus: (s) => s >= 200 && s < 300,
        });
    }
    isAuthenticated() {
        if (!this.token || !this.token.startsWith('ey')) {
            return false;
        }
        // Client-side JWT expiry pre-check
        const expiry = (0, vulnKnowledgeBase_1.checkTokenExpiry)(this.token);
        return expiry.valid;
    }
    getTokenStatus() {
        if (!this.token || !this.token.startsWith('ey')) {
            return {
                ok: false,
                errorType: 'not_configured',
                message: 'Offensive360 is not configured. Please set your server endpoint and API token in settings.'
            };
        }
        const expiry = (0, vulnKnowledgeBase_1.checkTokenExpiry)(this.token);
        if (expiry.expired) {
            return {
                ok: false,
                errorType: 'expired',
                message: 'Your API token has expired. Please ask your O360 administrator to generate a new token from Dashboard > Settings > Tokens.',
                expiresAt: expiry.expiresAt,
                remainingDays: 0
            };
        }
        if (expiry.remainingDays <= 3 && expiry.remainingDays > 0) {
            logInfo('tokenStatus', `Token expires in ${expiry.remainingDays} day(s)`);
        }
        return {
            ok: true,
            errorType: 'none',
            message: '',
            expiresAt: expiry.expiresAt,
            remainingDays: expiry.remainingDays
        };
    }
    async validateConnection() {
        const tokenStatus = this.getTokenStatus();
        if (!tokenStatus.ok) {
            return tokenStatus;
        }
        try {
            const response = await this.client.get('/app/api/HealthCheck');
            if (response.status === 200) {
                return { ok: true, errorType: 'none', message: '', expiresAt: tokenStatus.expiresAt, remainingDays: tokenStatus.remainingDays };
            }
            return { ok: false, errorType: 'server_error', message: (0, vulnKnowledgeBase_1.getAuthErrorMessage)(response.status, false) };
        }
        catch (error) {
            const status = error?.response?.status;
            if (status) {
                const errorType = status === 401 ? 'expired' : status === 403 ? 'forbidden' : 'server_error';
                return { ok: false, errorType, message: (0, vulnKnowledgeBase_1.getAuthErrorMessage)(status, false) };
            }
            // Network error (no response)
            logError('validateConnection', error);
            return { ok: false, errorType: 'network', message: (0, vulnKnowledgeBase_1.getAuthErrorMessage)(null, true) };
        }
    }
    async healthCheck() {
        try {
            const response = await this.client.get('/app/api/HealthCheck');
            return response.status === 200;
        }
        catch (error) {
            logError('healthCheck', error);
            return false;
        }
    }
    async listProjects() {
        const response = await this.client.get('/app/api/Project');
        const data = response.data;
        if (Array.isArray(data)) {
            return data;
        }
        if (data && data.pageItems) {
            return data.pageItems;
        }
        return [];
    }
    async getProject(id) {
        const response = await this.client.get(`/app/api/Project/${id}`);
        return response.data;
    }
    /**
     * Deletes a project from the server to avoid leaving scan artifacts in the dashboard.
     */
    async deleteProject(projectId) {
        try {
            await this.client.delete(`/app/api/Project/${projectId}`);
        }
        catch {
            // best-effort cleanup
        }
    }
    async scanFileUpload(zipPath, projectName) {
        return this.uploadWithRetry('/app/api/Project/scanProjectFile', zipPath, projectName, 'VsCodeExtension', 'FileSource');
    }
    /**
     * Wraps a multipart upload with bounded retries on transient socket-level failures.
     * Re-creates the FormData and read stream on every attempt — streams are not reusable.
     */
    async uploadWithRetry(urlPath, zipPath, projectName, sourceType, fileFieldName, extraFields) {
        const transientCodes = new Set([
            'ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'EPIPE',
            'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED'
        ]);
        // axios surfaces "socket hang up" with code undefined; match by message too
        const isSocketHangup = (err) => typeof err?.message === 'string' && err.message.toLowerCase().includes('socket hang up');
        const maxAttempts = 3;
        let lastErr;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const form = new form_data_1.default();
            form.append(fileFieldName, fs.createReadStream(zipPath));
            form.append('Name', projectName);
            form.append('ExternalScanSourceType', sourceType);
            if (extraFields) {
                for (const [k, v] of Object.entries(extraFields)) {
                    form.append(k, v);
                }
            }
            try {
                logInfo('uploadWithRetry', `attempt ${attempt}/${maxAttempts} → ${urlPath}`);
                const response = await this.client.post(urlPath, form, {
                    headers: {
                        ...form.getHeaders(),
                        'Authorization': `Bearer ${this.token}`,
                    },
                    maxContentLength: Infinity,
                    maxBodyLength: Infinity,
                    timeout: 600000,
                    httpsAgent: this.httpsAgent,
                });
                return response.data;
            }
            catch (err) {
                lastErr = err;
                const code = err?.code;
                const transient = (code && transientCodes.has(code)) || isSocketHangup(err);
                const status = err?.response?.status;
                // Don't retry on auth/permission/client errors — they won't get better
                if (status && status < 500 && status !== 408 && status !== 429) {
                    throw err;
                }
                if (!transient && !status) {
                    // Unknown non-HTTP error — log and surface
                    logError('uploadWithRetry', err);
                    throw err;
                }
                if (attempt < maxAttempts) {
                    const backoffMs = 2000 * attempt;
                    logInfo('uploadWithRetry', `transient error (${code || err.message}); retrying in ${backoffMs}ms`);
                    await new Promise(r => setTimeout(r, backoffMs));
                    continue;
                }
            }
        }
        throw lastErr;
    }
    /**
     * Upload files to /app/api/ExternalScan.
     * Returns all results immediately — no polling needed.
     * The project is ephemeral and auto-deleted by the server.
     */
    async externalScan(zipPath, projectName, sourceType = 'VsCodeExtension') {
        const form = new form_data_1.default();
        form.append('fileSource', fs.createReadStream(zipPath));
        form.append('Name', projectName);
        form.append('KeepInvisibleAndDeletePostScan', 'True');
        form.append('ExternalScanSourceType', sourceType);
        const response = await this.client.post('/app/api/ExternalScan', form, {
            headers: {
                ...form.getHeaders(),
                'Authorization': `Bearer ${this.token}`
            },
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
            timeout: 600000,
            httpsAgent: this.httpsAgent
        });
        return response.data;
    }
    /**
     * Convert ExternalScan vulnerabilities to LangScanResult format
     * for compatibility with diagnostics and tree views.
     */
    static convertExternalVulns(vulns) {
        return vulns.map(v => {
            const parts = (v.lineNumber || '0,0').split(',');
            const lineNo = parseInt(parts[0]) || 0;
            const columnNo = parseInt(parts[1]) || 0;
            let snippet = '';
            if (v.codeSnippet) {
                try {
                    snippet = Buffer.from(v.codeSnippet, 'base64').toString('utf8');
                }
                catch {
                    snippet = v.codeSnippet;
                }
            }
            return {
                id: v.id,
                fileName: v.fileName,
                filePath: v.filePath,
                lineNo,
                columnNo,
                codeSnippet: snippet,
                type: v.type,
                riskLevel: v.riskLevel,
                vulnerability: v.vulnerability || v.title,
                references: v.references || '',
                isTagged: false,
                // Preserve extra fields for richer display
                effect: v.effect,
                recommendation: v.recommendation
            };
        });
    }
    async scanGitRepo(repoUrl, projectName, branch) {
        const body = {
            Name: projectName,
            GitUrl: repoUrl
        };
        if (branch) {
            body.Branch = branch;
        }
        const response = await this.client.post('/app/api/Project/scanGitRepo', body);
        return response.data;
    }
    async reScanFile(projectId) {
        const response = await this.client.put(`/app/api/Project/${projectId}/reScanProjectFile`);
        return response.data;
    }
    async reScanGitRepo(projectId) {
        const response = await this.client.put(`/app/api/Project/${projectId}/reScanGitRepo`);
        return response.data;
    }
    async getLanguageResults(projectId) {
        try {
            const response = await this.client.get(`/app/api/Project/${projectId}/LangaugeScanResult`);
            const data = response.data;
            if (Array.isArray(data)) {
                return data;
            }
            if (data && data.pageItems) {
                return data.pageItems;
            }
            return [];
        }
        catch (error) {
            logError('getLanguageResults', error);
            return [];
        }
    }
    async getDependencyResults(projectId) {
        try {
            const response = await this.client.get(`/app/api/Project/${projectId}/DependencyScanResult`);
            const data = response.data;
            if (Array.isArray(data)) {
                return data;
            }
            if (data && data.pageItems) {
                return data.pageItems;
            }
            return [];
        }
        catch (error) {
            logError('getDependencyResults', error);
            return [];
        }
    }
    async getMalwareResults(projectId) {
        try {
            const response = await this.client.get(`/app/api/Project/${projectId}/MalwareScanResult`);
            const data = response.data;
            if (Array.isArray(data)) {
                return data;
            }
            if (data && data.pageItems) {
                return data.pageItems;
            }
            return [];
        }
        catch (error) {
            logError('getMalwareResults', error);
            return [];
        }
    }
    async getLicenseResults(projectId) {
        try {
            const response = await this.client.get(`/app/api/Project/${projectId}/LicenseScanResult`);
            const data = response.data;
            if (Array.isArray(data)) {
                return data;
            }
            if (data && data.pageItems) {
                return data.pageItems;
            }
            return [];
        }
        catch (error) {
            logError('getLicenseResults', error);
            return [];
        }
    }
    /**
     * Fetch all result types at once. Called immediately after scan completes,
     * before the server deletes the ephemeral project.
     */
    async getAllResults(projectId) {
        // Retry up to 3 times with 5s delay — some servers need time to populate results after scan completes
        for (let attempt = 0; attempt < 3; attempt++) {
            const [lang, dep, malware, license] = await Promise.all([
                this.getLanguageResults(projectId),
                this.getDependencyResults(projectId),
                this.getMalwareResults(projectId),
                this.getLicenseResults(projectId),
            ]);
            const total = lang.length + dep.length + malware.length + license.length;
            if (total > 0) {
                return { lang, dep, malware, license };
            }
            if (attempt < 2) {
                await new Promise(resolve => setTimeout(resolve, 5000));
            }
        }
        // Final attempt
        const [lang, dep, malware, license] = await Promise.all([
            this.getLanguageResults(projectId),
            this.getDependencyResults(projectId),
            this.getMalwareResults(projectId),
            this.getLicenseResults(projectId),
        ]);
        return { lang, dep, malware, license };
    }
    async getQueueStatus(projectId) {
        try {
            const response = await this.client.get(`/app/api/Project/${projectId}/GetTotalQueuedScans`);
            return response.data;
        }
        catch (error) {
            logError('getQueueStatus', error);
            return 0;
        }
    }
    async getVulnerabilityDetail(projectId, vulnId) {
        const response = await this.client.get(`/app/api/project/${projectId}/Vulnerability/${vulnId}`);
        return response.data;
    }
    async tagVulnerability(projectId, vulnIds) {
        await this.client.patch(`/app/api/project/${projectId}/Vulnerability/tagLanguage`, {
            ids: vulnIds
        });
    }
    async untagVulnerability(projectId, vulnIds) {
        await this.client.patch(`/app/api/project/${projectId}/Vulnerability/untagLanguage`, {
            ids: vulnIds
        });
    }
    async getScanStats(projectId) {
        try {
            const response = await this.client.get(`/app/api/ScanHistory/${projectId}/stats`);
            return response.data;
        }
        catch {
            return null;
        }
    }
}
exports.SastApi = SastApi;
//# sourceMappingURL=api.js.map