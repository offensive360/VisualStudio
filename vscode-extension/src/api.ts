import axios, { AxiosInstance, AxiosError } from 'axios';
import * as https from 'https';
import * as vscode from 'vscode';
import FormData from 'form-data';
import * as fs from 'fs';
import { checkTokenExpiry, getAuthErrorMessage } from './vulnKnowledgeBase';

// Output channel for logging (created lazily)
let outputChannel: vscode.OutputChannel | null = null;
function getOutputChannel(): vscode.OutputChannel {
  if (!outputChannel) {
    outputChannel = vscode.window.createOutputChannel('Offensive360 SAST');
  }
  return outputChannel;
}

function logError(context: string, error: unknown): void {
  const ch = getOutputChannel();
  const msg = error instanceof Error ? error.message : String(error);
  const status = (error as any)?.response?.status;
  ch.appendLine(`[${new Date().toISOString()}] ERROR in ${context}: ${msg}${status ? ` (HTTP ${status})` : ''}`);
}

function logInfo(context: string, message: string): void {
  getOutputChannel().appendLine(`[${new Date().toISOString()}] INFO ${context}: ${message}`);
}

export type AuthValidationResult = {
  ok: boolean;
  errorType: 'none' | 'not_configured' | 'expired' | 'invalid' | 'forbidden' | 'network' | 'server_error';
  message: string;
  expiresAt?: Date | null;
  remainingDays?: number;
};


export interface Project {
  id: string;
  name: string;
  status: number;
  riskLevel: number;
  sourceType: number;
  lastModifiedDate: string;
  lastModifiedBy: string;
  vulnerabilitiesCount: number;
  dependencyVulnerabilitiesCount: number;
  malwaresCount: number;
  licencesCount: number;
  totalLastScannedCodeFiles: number;
  totalLastScannedCodeLines: number;
  noOfScans: number;
}

export interface Vulnerability {
  id: string;
  title: string;
  lineNumber: string;
  riskLevel: string;
  vulnerability: string;
  fileName: string;
  filePath: string;
  references: string;
  isTagged: boolean;
  scanType?: string;
}

export interface ScanResult {
  vulnerabilities: Vulnerability[];
}

export interface LangScanResult {
  id: string;
  fileName: string;
  filePath: string;
  lineNo: number;
  columnNo: number;
  codeSnippet: string;
  type: string;
  riskLevel: number;
  vulnerability: string;
  references: string;
  isTagged: boolean;
}

export interface DepScanResult {
  id: string;
  fileName: string;
  vulnerabilities: string;
  severity: string;
  cveId: string;
  description: string;
}

export interface MalwareScanResult {
  id: string;
  fileName: string;
  ruleName: string;
  description: string;
  severity: string;
}

export interface LicenseScanResult {
  id: string;
  fileName: string;
  licenseName: string;
  licenseType: string;
  riskLevel: string;
}

/**
 * Response from /app/api/ExternalScan — returns all results immediately.
 * The project is ephemeral (auto-deleted), so no polling is needed.
 */
export interface ExternalScanResponse {
  projectId: string;
  status: number;
  vulnerabilities: ExternalScanVuln[] | null;
  malwares: any[] | null;
  licenses: any[] | null;
  dependencyVulnerabilities: any[] | null;
}

export interface ExternalScanVuln {
  id: string;
  fileName: string;
  filePath: string;
  lineNumber: string;   // "line,column" format e.g. "2,1"
  codeSnippet: string;  // base64-encoded
  type: string;
  riskLevel: number;
  vulnerability: string;
  title: string;
  effect: string;
  references: string;
  recommendation: string;
}

export const SCAN_STATUS: Record<number, string> = {
  0: 'Queued',
  1: 'Running',
  2: 'Succeeded',
  3: 'Failed',
  4: 'Partial Failed',
  5: 'Skipped'
};

export const RISK_LEVEL: Record<number, string> = {
  0: 'Safe',
  1: 'Low',
  2: 'Medium',
  3: 'High',
  4: 'Critical'
};

export const RISK_LEVEL_FROM_STRING: Record<string, number> = {
  'SAFE': 0,
  'LOW': 1,
  'MEDIUM': 2,
  'HIGH': 3,
  'CRITICAL': 4
};

export class SastApi {
  private client: AxiosInstance;
  private token: string = '';
  private baseUrl: string = '';
  private httpsAgent: https.Agent | undefined;

  constructor() {
    this.client = axios.create({ timeout: 600000 });
    this.loadConfig();
  }

  loadConfig() {
    const config = vscode.workspace.getConfiguration('o360');
    this.baseUrl = (config.get<string>('endpoint') || 'https://sast.offensive360.com').replace(/\/+$/, '');
    this.token = config.get<string>('accessToken') || '';
    const allowSelfSigned = config.get<boolean>('allowSelfSignedCerts') || false;

    // Load corporate root CA if NODE_EXTRA_CA_CERTS env var is set, OR from o360.extraCaCerts setting.
    // This is needed on Windows behind TLS-intercepting proxies (Zscaler, Netskope, etc).
    let extraCa: Buffer | undefined;
    const extraCaPath = config.get<string>('extraCaCerts') || process.env.NODE_EXTRA_CA_CERTS;
    if (extraCaPath) {
      try { extraCa = fs.readFileSync(extraCaPath); } catch (e) { logError('loadConfig.extraCaCerts', e); }
    }

    // Always use a keep-alive agent. Default Node.js global agent on Windows
    // can drop sockets aggressively under TLS-intercepting proxies → "socket hang up".
    const agentOpts: https.AgentOptions = {
      keepAlive: true,
      keepAliveMsecs: 30000,
      rejectUnauthorized: !allowSelfSigned,
    };
    if (extraCa) { agentOpts.ca = extraCa; }
    this.httpsAgent = new https.Agent(agentOpts);

    if (allowSelfSigned) {
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
    } else {
      delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    }

    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: 600000,
      httpsAgent: this.httpsAgent,
      headers: this.token ? { 'Authorization': `Bearer ${this.token}` } : {},
      // Surface socket-level failures clearly instead of swallowing them
      validateStatus: (s) => s >= 200 && s < 300,
    });
  }

  isAuthenticated(): boolean {
    if (!this.token || !this.token.startsWith('ey')) { return false; }
    // Client-side JWT expiry pre-check
    const expiry = checkTokenExpiry(this.token);
    return expiry.valid;
  }

  getTokenStatus(): AuthValidationResult {
    if (!this.token || !this.token.startsWith('ey')) {
      return {
        ok: false,
        errorType: 'not_configured',
        message: 'Offensive360 is not configured. Please set your server endpoint and API token in settings.'
      };
    }

    const expiry = checkTokenExpiry(this.token);
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

  async validateConnection(): Promise<AuthValidationResult> {
    const tokenStatus = this.getTokenStatus();
    if (!tokenStatus.ok) { return tokenStatus; }

    try {
      const response = await this.client.get('/app/api/HealthCheck');
      if (response.status === 200) {
        return { ok: true, errorType: 'none', message: '', expiresAt: tokenStatus.expiresAt, remainingDays: tokenStatus.remainingDays };
      }
      return { ok: false, errorType: 'server_error', message: getAuthErrorMessage(response.status, false) };
    } catch (error: any) {
      const status = error?.response?.status;
      if (status) {
        const errorType = status === 401 ? 'expired' : status === 403 ? 'forbidden' : 'server_error';
        return { ok: false, errorType, message: getAuthErrorMessage(status, false) };
      }
      // Network error (no response)
      logError('validateConnection', error);
      return { ok: false, errorType: 'network', message: getAuthErrorMessage(null, true) };
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.client.get('/app/api/HealthCheck');
      return response.status === 200;
    } catch (error) {
      logError('healthCheck', error);
      return false;
    }
  }

  async listProjects(): Promise<Project[]> {
    const response = await this.client.get('/app/api/Project');
    const data = response.data;
    if (Array.isArray(data)) { return data; }
    if (data && data.pageItems) { return data.pageItems; }
    return [];
  }

  async getProject(id: string): Promise<Project> {
    const response = await this.client.get(`/app/api/Project/${id}`);
    return response.data;
  }

  /**
   * Deletes a project from the server to avoid leaving scan artifacts in the dashboard.
   */
  async deleteProject(projectId: string): Promise<void> {
    try {
      await this.client.delete(`/app/api/Project/${projectId}`);
    } catch {
      // best-effort cleanup
    }
  }

  async scanFileUpload(zipPath: string, projectName: string): Promise<any> {
    return this.uploadWithRetry('/app/api/Project/scanProjectFile', zipPath, projectName, 'VsCodeExtension', 'FileSource');
  }

  /**
   * Wraps a multipart upload with bounded retries on transient socket-level failures.
   * Re-creates the FormData and read stream on every attempt — streams are not reusable.
   */
  private async uploadWithRetry(
    urlPath: string,
    zipPath: string,
    projectName: string,
    sourceType: string,
    fileFieldName: string,
    extraFields?: Record<string, string>
  ): Promise<any> {
    const transientCodes = new Set([
      'ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'EPIPE',
      'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED'
    ]);
    // axios surfaces "socket hang up" with code undefined; match by message too
    const isSocketHangup = (err: any) =>
      typeof err?.message === 'string' && err.message.toLowerCase().includes('socket hang up');

    const maxAttempts = 3;
    let lastErr: any;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const form = new FormData();
      form.append(fileFieldName, fs.createReadStream(zipPath));
      form.append('Name', projectName);
      form.append('ExternalScanSourceType', sourceType);
      if (extraFields) {
        for (const [k, v] of Object.entries(extraFields)) { form.append(k, v); }
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
      } catch (err: any) {
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
  async externalScan(zipPath: string, projectName: string, sourceType: string = 'VsCodeExtension'): Promise<ExternalScanResponse> {
    const form = new FormData();
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
  static convertExternalVulns(vulns: ExternalScanVuln[]): LangScanResult[] {
    return vulns.map(v => {
      const parts = (v.lineNumber || '0,0').split(',');
      const lineNo = parseInt(parts[0]) || 0;
      const columnNo = parseInt(parts[1]) || 0;

      let snippet = '';
      if (v.codeSnippet) {
        try { snippet = Buffer.from(v.codeSnippet, 'base64').toString('utf8'); } catch { snippet = v.codeSnippet; }
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
        effect: (v as any).effect,
        recommendation: (v as any).recommendation
      } as LangScanResult & { effect?: string; recommendation?: string };
    });
  }

  async scanGitRepo(repoUrl: string, projectName: string, branch?: string): Promise<any> {
    const body: any = {
      Name: projectName,
      GitUrl: repoUrl
    };
    if (branch) {
      body.Branch = branch;
    }
    const response = await this.client.post('/app/api/Project/scanGitRepo', body);
    return response.data;
  }

  async reScanFile(projectId: string): Promise<any> {
    const response = await this.client.put(`/app/api/Project/${projectId}/reScanProjectFile`);
    return response.data;
  }

  async reScanGitRepo(projectId: string): Promise<any> {
    const response = await this.client.put(`/app/api/Project/${projectId}/reScanGitRepo`);
    return response.data;
  }

  async getLanguageResults(projectId: string): Promise<LangScanResult[]> {
    try {
      const response = await this.client.get(`/app/api/Project/${projectId}/LangaugeScanResult`);
      const data = response.data;
      if (Array.isArray(data)) { return data; }
      if (data && data.pageItems) { return data.pageItems; }
      return [];
    } catch (error) {
      logError('getLanguageResults', error);
      return [];
    }
  }

  async getDependencyResults(projectId: string): Promise<DepScanResult[]> {
    try {
      const response = await this.client.get(`/app/api/Project/${projectId}/DependencyScanResult`);
      const data = response.data;
      if (Array.isArray(data)) { return data; }
      if (data && data.pageItems) { return data.pageItems; }
      return [];
    } catch (error) {
      logError('getDependencyResults', error);
      return [];
    }
  }

  async getMalwareResults(projectId: string): Promise<MalwareScanResult[]> {
    try {
      const response = await this.client.get(`/app/api/Project/${projectId}/MalwareScanResult`);
      const data = response.data;
      if (Array.isArray(data)) { return data; }
      if (data && data.pageItems) { return data.pageItems; }
      return [];
    } catch (error) {
      logError('getMalwareResults', error);
      return [];
    }
  }

  async getLicenseResults(projectId: string): Promise<LicenseScanResult[]> {
    try {
      const response = await this.client.get(`/app/api/Project/${projectId}/LicenseScanResult`);
      const data = response.data;
      if (Array.isArray(data)) { return data; }
      if (data && data.pageItems) { return data.pageItems; }
      return [];
    } catch (error) {
      logError('getLicenseResults', error);
      return [];
    }
  }

  /**
   * Fetch all result types at once. Called immediately after scan completes,
   * before the server deletes the ephemeral project.
   */
  async getAllResults(projectId: string): Promise<{
    lang: LangScanResult[];
    dep: DepScanResult[];
    malware: MalwareScanResult[];
    license: LicenseScanResult[];
  }> {
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

  async getQueueStatus(projectId: string): Promise<number> {
    try {
      const response = await this.client.get(`/app/api/Project/${projectId}/GetTotalQueuedScans`);
      return response.data;
    } catch (error) {
      logError('getQueueStatus', error);
      return 0;
    }
  }

  async getVulnerabilityDetail(projectId: string, vulnId: string): Promise<any> {
    const response = await this.client.get(`/app/api/project/${projectId}/Vulnerability/${vulnId}`);
    return response.data;
  }

  async tagVulnerability(projectId: string, vulnIds: string[]): Promise<void> {
    await this.client.patch(`/app/api/project/${projectId}/Vulnerability/tagLanguage`, {
      ids: vulnIds
    });
  }

  async untagVulnerability(projectId: string, vulnIds: string[]): Promise<void> {
    await this.client.patch(`/app/api/project/${projectId}/Vulnerability/untagLanguage`, {
      ids: vulnIds
    });
  }

  async getScanStats(projectId: string): Promise<any> {
    try {
      const response = await this.client.get(`/app/api/ScanHistory/${projectId}/stats`);
      return response.data;
    } catch {
      return null;
    }
  }
}
