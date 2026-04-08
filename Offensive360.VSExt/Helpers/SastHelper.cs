using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Newtonsoft.Json;
using Offensive360.VSExt.Properties;
using SAST.VSExt.Models;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Offensive360.VSExt.Helpers
{
    internal static class SastHelper
    {
        private const string projectScanMessagePrefix = "Offensive 360 project scanning";
        private const long MaxFileSizeBytes = 50L * 1024 * 1024; // 50 MB per-file limit
        private const int LargeProjectFileThreshold = 5000;

        private static bool _scanInProgress = false;
        private static string currentFilePath;
        private static string scanFileEndpoint = "/app/api/Project/scanProjectFile";
        private static string externalScanEndpoint = "/app/api/ExternalScan";
        private static string projectEndpoint = "/app/api/Project";

        /// <summary>
        /// Creates an HttpClientHandler that accepts self-signed certificates
        /// when the server uses HTTPS with a non-trusted CA.
        /// </summary>
        private static HttpClientHandler CreateHandler()
        {
            return new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
            };
        }

        public static string IgnoreFilePath(string solutionPath)
        {
            var folderPath = $"{GetSolutionFolderPath(solutionPath)}\\.SASTO360";

            if(!Directory.Exists(folderPath))
            {
                var directory = Directory.CreateDirectory(folderPath);
                directory.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
            }

            return $"{GetSolutionFolderPath(solutionPath)}\\.SASTO360\\sastIgnore";
        }

        public static string VulnerabilityIgnoreConfig(string filePath, int line, int column, string vulnerabilityTitle) => $"{filePath}__{line}:{column}__{vulnerabilityTitle}";

        public static async Task ScanProjectAndShowVulnerabilitiesAsync(this ErrorListProvider _errorListProvider, IVsStatusbar statusBar, string solutionFilePath)
        {
            if (_scanInProgress)
            {
                throw new InvalidOperationException("A scan is already in progress. Please wait for it to complete.");
            }

            _scanInProgress = true;
            try
            {
                // Option D — fire-and-forget plugin-update check (silent if server lacks endpoint)
                try { PluginUpdateChecker.CheckAsync(); } catch { }

                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] ValidateSettings...\n"); } catch {}
                await ValidateSettingsAsync();
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Validation passed!\n"); } catch {}

                var solutionFolder = GetSolutionFolderPath(solutionFilePath);
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] SolutionFolder: {solutionFolder}\n"); } catch {}

                // --- Incremental diff: compute on background thread to avoid UI freeze ---
                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 1/5] Validating settings...");
                ScanCache.CachedScan cached = null;
                try { cached = ScanCache.Load(solutionFolder); } catch { cached = null; }

                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 2/5] Checking for changes...");
                ScanCache.IncrementalDiff diff;
                try
                {
                    diff = await ScanCache.ComputeIncrementalDiffAsync(solutionFolder, cached);
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Diff computed. HasChanges={diff.HasChanges} Changed={diff.ChangedRelativePaths.Count} Total={diff.CurrentHashes.Count}\n"); } catch {}
                }
                catch (Exception diffEx)
                {
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] ComputeIncrementalDiff FAILED: {diffEx.GetType().Name}: {diffEx.Message}\n"); } catch {}
                    // Fall back to full scan if diff fails
                    diff = new ScanCache.IncrementalDiff { HasChanges = true, ChangedRelativePaths = new System.Collections.Generic.List<string>(), DeletedRelativePaths = new System.Collections.Generic.List<string>(), CurrentHashes = new System.Collections.Generic.Dictionary<string, string>() };
                }

                if (!diff.HasChanges && cached != null && cached.Vulnerabilities != null && cached.Vulnerabilities.Count > 0)
                {
                    // No files changed AND cache has actual findings — use cached results
                    await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} — No changes detected, loading cached results...");

                    var ignoredCached = File.Exists(IgnoreFilePath(solutionFilePath)) ? File.ReadAllLines(IgnoreFilePath(solutionFilePath)) : new string[0];
                    foreach (var vulnerability in cached.Vulnerabilities)
                    {
                        var (lineNo, columnNo) = PopulateLineAndColumnNumber(vulnerability.LineNumber);
                        if (!ignoredCached.Contains(VulnerabilityIgnoreConfig(vulnerability.FilePath?.ToLower(), lineNo, columnNo, vulnerability.Title)))
                        {
                            Log(_errorListProvider, vulnerability);
                        }
                    }

                    currentFilePath = solutionFilePath;
                    _errorListProvider.Show();
                    _errorListProvider.ForceShowErrors();
                    await statusBar.HideProgressAsync();
                    return;
                }

                // Always full scan: incremental path was a regression — when only changed files
                // were uploaded, the server returned findings only for those files, and the result
                // overwrote the cache, dropping every other finding in the solution. The API has
                // no meaningful size limit (~2GB), so always uploading the full solution is correct.
                var totalCount = diff.CurrentHashes.Count;
                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 3/5] Preparing {totalCount} files for full scan...");
                if (totalCount > LargeProjectFileThreshold)
                {
                    System.Diagnostics.Debug.WriteLine($"Offensive360: Large project detected ({totalCount} files). Scan may take longer.");
                }
                string zipPath = await Task.Run(() => ZipFolderToFile(solutionFolder));
                _tempZipPath = zipPath;
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Zip created: {zipPath} ({new FileInfo(zipPath).Length / 1024}KB)\n"); } catch {}

                // Warn about large uploads
                var zipSizeMb = new FileInfo(zipPath).Length / (1024 * 1024);
                if (zipSizeMb > 200)
                {
                    await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 3/5] Large upload ({zipSizeMb}MB) — this may take several minutes...");
                    System.Diagnostics.Debug.WriteLine($"Offensive360: Large zip file ({zipSizeMb}MB). Upload may take longer.");
                }

                var projectName = solutionFolder.TrimEnd('\\', '/').Split('\\').Last();
                projectName = projectName?.Length > 13 ? projectName.Substring(0, 13) : projectName;
                projectName = $"{projectName}_{Guid.NewGuid()}";

                ScanResponse scanResponse = null;

                // Use scanProjectFile + polling (same as working VSCode v1.0.4 plugin).
                // Falls back to ExternalScan only for External tokens that get 403.
                try
                {
                    await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 4/5] Uploading ({(new FileInfo(zipPath).Length / 1024):N0} KB)...");
                    var scanEndpoint = $"{Settings.Default.BaseUrl.TrimEnd('/')}{scanFileEndpoint}";
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Calling scanProjectFile: {scanEndpoint}\n"); } catch {}
                    var (httpCode, projectIdStr) = await PostScanViaCurl(scanEndpoint, Settings.Default.AccessToken, zipPath, projectName);
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] scanProjectFile returned HTTP {httpCode}\n"); } catch {}

                    if (httpCode == 0)
                    {
                        throw new HttpRequestException("Cannot connect to the server. Check your endpoint URL and network connection.");
                    }
                    if (httpCode == 401)
                    {
                        throw new UnauthorizedAccessException(
                            "Your access token is invalid or expired (HTTP 401).\n\n" +
                            "Please ask your O360 administrator to generate a new token from:\n" +
                            "Dashboard > Settings > Tokens\n\n" +
                            "Then update it in Tools > Options > Offensive360.");
                    }
                    if (httpCode == 403)
                    {
                        // External token — fall back to ExternalScan
                        throw new SastHttpException(HttpStatusCode.Forbidden, "Server returned 403");
                    }
                    if (httpCode == 413)
                    {
                        throw new HttpRequestException(
                            $"Upload too large (HTTP 413). The server's nginx has a file size limit.\n\n" +
                            $"Options:\n" +
                            $"• Ask your O360 administrator to increase nginx 'client_max_body_size' on port 9091\n" +
                            $"• Scan a smaller subset of files (individual folders instead of whole solution)");
                    }
                    if (httpCode < 200 || httpCode >= 300)
                    {
                        throw new HttpRequestException($"Server returned HTTP {httpCode}. Check your endpoint URL and access token.");
                    }

                    projectIdStr = projectIdStr?.Trim().Trim('"');
                    scanResponse = await WaitForScanAndFetchResultsAsync(statusBar, projectIdStr, projectScanMessagePrefix);
                    await DeleteProjectAsync(projectIdStr);
                }
                catch (SastHttpException ex) when (ex.StatusCode == HttpStatusCode.Forbidden)
                {
                    // scanProjectFile returned 403 — External token, use ExternalScan with retry
                    var extEndpoint = $"{Settings.Default.BaseUrl.TrimEnd('/')}{externalScanEndpoint}";
                    string extBody = null;
                    int extHttpCode = 0;
                    // Retry budget tuned for slow backends + nginx gateway timeouts (502/504):
                    // 6 attempts with exponential backoff 15s, 30s, 60s, 120s, 240s — total ~8 min of
                    // recovery time on top of curl's own 4h --max-time per attempt.
                    const int maxRetries = 6;
                    int[] backoffSeconds = { 0, 15, 30, 60, 120, 240 };
                    for (int attempt = 1; attempt <= maxRetries; attempt++)
                    {
                        if (attempt > 1)
                        {
                            var waitSec = attempt - 1 < backoffSeconds.Length ? backoffSeconds[attempt - 1] : 240;
                            await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 4/5] Server busy (HTTP {extHttpCode}) — waiting {waitSec}s before retry {attempt}/{maxRetries}...");
                            await Task.Delay(waitSec * 1000);
                        }
                        else
                        {
                            await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 4/5] Scanning (ExternalScan)...");
                        }
                        (extHttpCode, extBody) = await PostScanViaCurl(extEndpoint, Settings.Default.AccessToken, zipPath, projectName);
                        if (extHttpCode >= 200 && extHttpCode < 300) break; // success
                        if (extHttpCode == 0 || extHttpCode == 401 || extHttpCode == 403) break; // non-retryable
                        // 5xx → retry (including 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout)
                        try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] ExternalScan HTTP {extHttpCode} on attempt {attempt}/{maxRetries}, will retry with longer backoff\n"); } catch {}
                    }

                    if (extHttpCode == 0)
                    {
                        // All transport attempts (curl, .NET HttpClient, Python) returned 0.
                        // Include the body which carries the underlying error from whichever
                        // attempt got closest (SSL handshake failure, connect timeout, etc.)
                        var detail = string.IsNullOrWhiteSpace(extBody) ? "No diagnostic details available." : extBody;
                        if (detail.Length > 400) detail = detail.Substring(0, 400) + "...";
                        throw new HttpRequestException(
                            $"Could not reach the O360 server after {maxRetries} attempts with multiple upload methods (curl, .NET HttpClient, Python).\n\n" +
                            $"Underlying error: {detail}\n\n" +
                            "Things to check:\n" +
                            "• Is the server URL reachable from this machine? (try it in a browser)\n" +
                            "• Does the corporate proxy / firewall allow HTTPS to the O360 server?\n" +
                            "• Is the server's TLS configuration compatible (TLS 1.2+)?\n" +
                            "• See C:\\Users\\<you>\\Desktop\\o360_scan_log.txt for the full diagnostic log.");
                    }
                    if (extHttpCode == 401 || extHttpCode == 403)
                    {
                        throw new UnauthorizedAccessException(
                            "Your access token is invalid or expired (HTTP " + extHttpCode + ").\n\n" +
                            "Please ask your O360 administrator to generate a new token from:\n" +
                            "Dashboard > Settings > Tokens\n\n" +
                            "Then update it in Tools > Options > Offensive360.");
                    }
                    if (extHttpCode == 502 || extHttpCode == 503 || extHttpCode == 504)
                    {
                        // Nginx gateway errors — backend is too slow or briefly unavailable. This is
                        // NOT a plugin config issue, so don't tell the user to check their settings.
                        var name = extHttpCode == 502 ? "Bad Gateway" : extHttpCode == 503 ? "Service Unavailable" : "Gateway Timeout";
                        throw new HttpRequestException(
                            $"The O360 server is taking too long to respond (HTTP {extHttpCode} {name}) after {maxRetries} attempts over several minutes.\n\n" +
                            "This usually means the SAST backend is under heavy load or your project is very large. " +
                            "Wait a few minutes and try again. If the problem persists, contact your O360 administrator — they may need to increase the server-side proxy timeout (nginx proxy_read_timeout on port 9091).");
                    }
                    if (extHttpCode >= 500)
                    {
                        throw new HttpRequestException($"The O360 server returned HTTP {extHttpCode} after {maxRetries} attempts. Wait a few minutes and try again; if the problem persists, contact your O360 administrator.");
                    }
                    if (extHttpCode < 200 || extHttpCode >= 300)
                    {
                        throw new HttpRequestException($"Server returned HTTP {extHttpCode}. Check your endpoint URL and access token.");
                    }

                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] ExternalScan HTTP {extHttpCode}, body length={extBody?.Length ?? 0}\n"); } catch {}
                    scanResponse = JsonConvert.DeserializeObject<ScanResponse>(extBody);
                    var vulnCount = scanResponse?.Vulnerabilities?.Count() ?? 0;
                    var serverTotal = scanResponse?.TotalVulnerabilities;
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Deserialized: array={vulnCount}, totalVulnerabilities={(serverTotal?.ToString() ?? "(not present)")}\n"); } catch {}
                    if (serverTotal.HasValue && serverTotal.Value != vulnCount)
                    {
                        // Should never happen with the 2026-04-08 backend update, but log loudly if it does
                        try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] WARN: server reported totalVulnerabilities={serverTotal.Value} but array has {vulnCount} items — using server total as canonical\n"); } catch {}
                    }
                    if (scanResponse?.Vulnerabilities == null)
                    {
                        scanResponse = new ScanResponse { Vulnerabilities = new List<VulnerabilityResponse>() };
                    }

                    // Extract projectId for server cleanup. As of the 2026-04-08 backend
                    // update, the ExternalScan inline response is the canonical source
                    // (totalVulnerabilities == vulnerabilities.length == dashboard count),
                    // so we no longer re-query /LangaugeScanResult.
                    string dashboardProjectId = null;
                    try
                    {
                        var extJson = Newtonsoft.Json.Linq.JObject.Parse(extBody);
                        dashboardProjectId = extJson.Value<string>("projectId");
                    }
                    catch { }

                    if (!string.IsNullOrEmpty(dashboardProjectId))
                    {
                        // Best-effort server-side project cleanup (no-op on failure)
                        try { await DeleteProjectAsync(dashboardProjectId); } catch { }
                    }
                }
                finally
                {
                    try { if (zipPath != null && File.Exists(zipPath)) File.Delete(zipPath); } catch { }
                }

                // Always use full scan results — incremental merging caused duplicate counts
                // because server file paths don't reliably match local relative paths.
                // Each scan returns the complete set for the uploaded files; no merging needed.
                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} [Step 5/5] Processing results...");
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] Processing results...\n"); } catch {}
                var finalVulnerabilities = scanResponse.Vulnerabilities?.ToList() ?? new List<VulnerabilityResponse>();
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] finalVulnerabilities.Count={finalVulnerabilities.Count}\n"); } catch {}

                // Save merged results + current hashes + server's canonical total to cache (non-fatal)
                try
                {
                    ScanCache.Save(solutionFolder, finalVulnerabilities, diff.CurrentHashes, scanResponse?.TotalVulnerabilities);
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] ScanCache.Save OK (serverTotal={(scanResponse?.TotalVulnerabilities?.ToString() ?? "n/a")})\n"); } catch {}
                }
                catch (Exception cacheEx)
                {
                    // Cache save failure must never break display of results
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] ScanCache.Save WARN: {cacheEx.GetType().Name}: {cacheEx.Message}\n"); } catch {}
                }

                string[] ignoredVulnerabilities;
                try
                {
                    ignoredVulnerabilities = File.Exists(IgnoreFilePath(solutionFilePath)) ? File.ReadAllLines(IgnoreFilePath(solutionFilePath)) : new string[0];
                }
                catch
                {
                    ignoredVulnerabilities = new string[0];
                }

                // Render every finding the server returned — NO client-side dedup.
                // The server is the source of truth for the dashboard count, and as of
                // the 2026-04-08 IDECO backend update the response includes a
                // totalVulnerabilities field whose value equals vulnerabilities.Count.
                // Previous versions did file+line dedup which silently dropped real
                // findings that legitimately shared a location (e.g. SAST + AI engine
                // finding two different issues on the same line), causing 165/166
                // count mismatches against the dashboard.
                var toolWindowRows = new List<Offensive360.VSExt.ToolWindow.FindingRow>();
                try
                {
                    int rendered = 0;
                    foreach (var vulnerability in finalVulnerabilities)
                    {
                        // Drop only results with NO information at all — these are empty
                        // placeholders the AI engine sometimes returns. Never drop real findings.
                        bool hasDescription = !string.IsNullOrWhiteSpace(vulnerability.Vulnerability);
                        bool hasFile = !string.IsNullOrWhiteSpace(vulnerability.FilePath);
                        if (!hasDescription && !hasFile) continue;

                        var (lineNo, columnNo) = PopulateLineAndColumnNumber(vulnerability.LineNumber);

                        if (!ignoredVulnerabilities.Contains(VulnerabilityIgnoreConfig(vulnerability.FilePath?.ToLower(), lineNo, columnNo, vulnerability.Title)))
                        {
                            try { Log(_errorListProvider, vulnerability); rendered++; }
                            catch (Exception logEx)
                            {
                                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] Log finding skipped: {logEx.GetType().Name}: {logEx.Message}\n"); } catch {}
                            }

                            // Also append to the dedicated Offensive 360 tool window (NEW in v1.12.9).
                            // This is the "separate tab" UI — keeps findings from being visually mixed
                            // with compiler warnings / IntelliSense noise in the generic Error List.
                            try
                            {
                                var absFile = ResolveAbsoluteFilePath(solutionFolder, vulnerability.FilePath, vulnerability.FileName);
                                toolWindowRows.Add(new Offensive360.VSExt.ToolWindow.FindingRow
                                {
                                    Severity = NormalizeRiskLevel(vulnerability.RiskLevel),
                                    Title = vulnerability.Title ?? "",
                                    File = vulnerability.FileName ?? System.IO.Path.GetFileName(vulnerability.FilePath ?? ""),
                                    Line = lineNo,
                                    Column = columnNo,
                                    AbsoluteFilePath = absFile,
                                    Description = vulnerability.Vulnerability ?? "",
                                    Recommendation = "",
                                    References = vulnerability.References ?? "",
                                    CodeSnippet = ""
                                });
                            }
                            catch { /* row-level failure must not break the render */ }
                        }
                    }
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] Rendered {rendered} findings to Error List + {toolWindowRows.Count} to O360 tool window (no dedup)\n"); } catch {}
                }
                catch (Exception renderEx)
                {
                    // Rendering failure shouldn't nuke the whole scan — log and continue to summary
                    try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] [Step 5] Render loop FAILED: {renderEx.GetType().Name}: {renderEx.Message}\n{renderEx.StackTrace}\n"); } catch {}
                }

                // Push into the dedicated tool window store (UI thread) and open the window.
                try
                {
                    await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                    Offensive360.VSExt.ToolWindow.FindingsStore.Replace(toolWindowRows);
                    try
                    {
                        if (Package.GetGlobalService(typeof(SVsShell)) is IVsShell shell)
                        {
                            // Best-effort show of the tool window — uses the already-registered
                            // ProvideToolWindow attribute. Failure here is non-fatal.
                            var package = Offensive360.VSExt.Offensive360VSExtPackage.Instance;
                            if (package != null)
                            {
                                var window = package.FindToolWindow(typeof(Offensive360.VSExt.ToolWindow.FindingsToolWindow), 0, true);
                                if (window?.Frame is IVsWindowFrame frame)
                                {
                                    frame.Show();
                                }
                            }
                        }
                    }
                    catch { }
                }
                catch { }

                currentFilePath = solutionFilePath;
                _errorListProvider.Show();  // Keep Error List open too for back-compat
                _errorListProvider.ForceShowErrors();

                // --- Completion summary ---
                var displayedCount = _errorListProvider.Tasks.Count;
                var totalFound = finalVulnerabilities.Count;
                var suppressedCount = totalFound - displayedCount;
                var summaryParts = new List<string>();

                // Count by severity
                var critical = finalVulnerabilities.Count(v => NormalizeRiskLevel(v.RiskLevel) == "CRITICAL");
                var high = finalVulnerabilities.Count(v => NormalizeRiskLevel(v.RiskLevel) == "HIGH");
                var medium = finalVulnerabilities.Count(v => NormalizeRiskLevel(v.RiskLevel) == "MEDIUM");
                var low = finalVulnerabilities.Count(v => NormalizeRiskLevel(v.RiskLevel) == "LOW");

                if (critical > 0) summaryParts.Add($"{critical} Critical");
                if (high > 0) summaryParts.Add($"{high} High");
                if (medium > 0) summaryParts.Add($"{medium} Medium");
                if (low > 0) summaryParts.Add($"{low} Low");

                var severityBreakdown = summaryParts.Count > 0 ? string.Join(", ", summaryParts) : "none";
                var suppressedNote = suppressedCount > 0 ? $" ({suppressedCount} suppressed)" : "";

                await statusBar.ShowProgressAsync(
                    $"O360 Scan Complete — {displayedCount} vulnerabilities found: {severityBreakdown}{suppressedNote}");

                // Keep the summary visible for a few seconds, then clear
                await Task.Delay(5000);
                await statusBar.HideProgressAsync();
            }
            catch
            {
                await statusBar.HideProgressAsync();
                throw;
            }
            finally
            {
                _scanInProgress = false;
            }
        }
        
        public static void LogException(this ErrorListProvider _errorListProvider, string errorMessage, string fileName = "")
        {
            _errorListProvider.Tasks.Add(new ErrorTask()
            {
                ErrorCategory = TaskErrorCategory.Warning,
                Category = TaskCategory.CodeSense,
                Text = errorMessage,
                Document = fileName
            });
        }

        public static async Task ShowProgressAsync(this IVsStatusbar statusBar, string message)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            object icon = (short)Constants.SBAI_Build;
            statusBar.Animation(10, ref icon);

            int frozen;
            statusBar.IsFrozen(out frozen);
            if (frozen != 0)
            {
                statusBar.FreezeOutput(0);
            }
            statusBar.SetText(message);
            statusBar.FreezeOutput(1);
        }

        public static async Task HideProgressAsync(this IVsStatusbar statusBar)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            object icon = (short)Constants.SBAI_Build;
            statusBar.Animation(0, ref icon);
            statusBar.FreezeOutput(0);
            statusBar.Clear();
        }

        /// <summary>
        /// Forces the Error List to show all categories (errors, warnings, messages)
        /// so O360 findings are visible regardless of the user's current filter.
        /// </summary>
        public static void ForceShowErrors(this ErrorListProvider provider)
        {
            try
            {
                ThreadHelper.ThrowIfNotOnUIThread();
                var dte = (EnvDTE.DTE)Marshal.GetActiveObject("VisualStudio.DTE");
                dte.ExecuteCommand("View.ErrorList");
            }
            catch { /* Error List may already be visible */ }
        }

        private static void Log(ErrorListProvider _errorListProvider, VulnerabilityResponse vulnerability)
        {
            var (lineNo, columnNo) = PopulateLineAndColumnNumber(vulnerability.LineNumber);

            // Resolve the file path: strip any zip prefix, find actual file on disk
            var solutionFolder = GetSolutionFolderPath(currentFilePath);
            var resolvedPath = ResolveFilePath(solutionFolder, vulnerability.FilePath);
            // Store relative path for display (shorter in Error List)
            string displayPath = vulnerability.FilePath;
            if (resolvedPath != null && !string.IsNullOrEmpty(solutionFolder))
            {
                var trimmed = solutionFolder.TrimEnd('\\');
                if (resolvedPath.StartsWith(trimmed, StringComparison.OrdinalIgnoreCase) && resolvedPath.Length > trimmed.Length)
                    displayPath = resolvedPath.Substring(trimmed.Length).TrimStart('\\');
                else
                    displayPath = resolvedPath;
            }

            var errorTask = new ErrorTask
            {
                ErrorCategory = GetErrorCategory(vulnerability.RiskLevel),
                Category = TaskCategory.CodeSense,
                Text = $"[{vulnerability.Title}] {vulnerability.Vulnerability}" ,
                Document = displayPath,
                Line = lineNo - 1,
                Column = columnNo,
                Priority = GetTaskPriority(vulnerability.RiskLevel),
                HelpKeyword = vulnerability.References
            };

            errorTask.Navigate += OnErrorTaskClick;
            errorTask.Help += ErrorTask_Help;
            _errorListProvider.Tasks.Add(errorTask);
        }

        private static (int, int) PopulateLineAndColumnNumber(string lineAndColumn)
        {
            var line = lineAndColumn.Split(',');
            var lineNo = 0;
            var columnNo = 0;
            int.TryParse(line[0], out lineNo);
            int.TryParse(line[1], out columnNo);

            return (lineNo, columnNo);
        }

        private static void ErrorTask_Help(object sender, EventArgs e)
        {
            var errorTask = sender as ErrorTask;
            if (errorTask == null) return;

            // Extract vulnerability type from error text: [Type] Description
            string vulnType = "";
            if (errorTask.Text != null && errorTask.Text.StartsWith("["))
            {
                var endBracket = errorTask.Text.IndexOf(']');
                if (endBracket > 1)
                {
                    vulnType = errorTask.Text.Substring(1, endBracket - 1);
                }
            }

            // Look up offline knowledge base
            var kbEntry = VulnerabilityKnowledgeBase.Lookup(vulnType)
                       ?? VulnerabilityKnowledgeBase.Lookup(errorTask.Text);

            // Always use FixGuidanceDialog — create a fallback entry if KB doesn't have this vuln
            if (kbEntry == null)
            {
                kbEntry = new VulnerabilityKnowledgeBase.VulnKBEntry
                {
                    VulnerabilityId = vulnType,
                    Title = string.IsNullOrWhiteSpace(vulnType) ? "Security Vulnerability" : vulnType,
                    ShortDescription = "No built-in description available for this vulnerability type.",
                    RiskExplanation = "Review the References tab for more information on this finding.",
                    HowToFix = "Please refer to the References tab and the Offensive360 Knowledge Base for remediation guidance.",
                    References = "https://offensive360.com/academy/",
                    CodePatternBad = "",
                    CodePatternGood = "",
                    CWEs = Array.Empty<string>()
                };
            }

            var dialog = new FixGuidanceDialog(
                kbEntry,
                errorTask.Text,
                errorTask.Document,
                errorTask.Line + 1,
                !string.IsNullOrWhiteSpace(errorTask.HelpKeyword) ? errorTask.HelpKeyword : kbEntry.References);
            dialog.ShowFixTab();
            dialog.ShowDialog();
        }

        private static void OnErrorTaskClick(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
            try
            {
                var errorTask = sender as ErrorTask;
                if (errorTask == null || string.IsNullOrWhiteSpace(errorTask.Document)) return;

                var solutionFolder = GetSolutionFolderPath(currentFilePath);
                var filePath = ResolveFilePath(solutionFolder, errorTask.Document);

                if (filePath == null)
                {
                    System.Diagnostics.Debug.WriteLine($"Offensive360: File not found — {errorTask.Document} (solution: {solutionFolder})");
                    return;
                }

                // Use ServiceProvider to get DTE from current VS instance
                var dte = (EnvDTE.DTE)Package.GetGlobalService(typeof(EnvDTE.DTE));
                if (dte == null) return;

                dte.MainWindow.Activate();
                dte.ItemOperations.OpenFile(filePath, EnvDTE.Constants.vsViewKindTextView);
                if (dte.ActiveDocument?.Selection is EnvDTE.TextSelection selection)
                {
                    selection.GotoLine(errorTask.Line + 1, true);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Offensive360: Navigation failed — {ex.Message}");
            }
        }

        /// <summary>
        /// Resolve a file path from the server (relative or absolute) to an absolute path that exists.
        /// Tries multiple strategies so navigation works regardless of how the server returns paths.
        /// </summary>
        private static string ResolveFilePath(string solutionFolder, string document)
        {
            if (string.IsNullOrWhiteSpace(document)) return null;

            // 1. Absolute path as-is
            if (File.Exists(document)) return document;

            // 2. Relative to solution folder
            var normalized = document.Replace('/', '\\');
            if (!string.IsNullOrEmpty(solutionFolder))
            {
                var candidate = Path.Combine(solutionFolder, normalized);
                if (File.Exists(candidate)) return candidate;

                // 3. Strip leading directories one by one (handles zip prefix like "reponame-hash/actual/path")
                var parts = normalized.Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 1; i < parts.Length; i++)
                {
                    var stripped = string.Join("\\", parts, i, parts.Length - i);
                    candidate = Path.Combine(solutionFolder, stripped);
                    if (File.Exists(candidate)) return candidate;
                }
            }

            // 4. Search for filename recursively under solution folder (handles nested paths)
            if (!string.IsNullOrEmpty(solutionFolder) && Directory.Exists(solutionFolder))
            {
                var fileName = Path.GetFileName(document);
                try
                {
                    var matches = Directory.GetFiles(solutionFolder, fileName, SearchOption.AllDirectories);
                    if (matches.Length == 1) return matches[0];
                    // If multiple matches, prefer the one whose path contains the document's directory hint
                    var dirHint = Path.GetDirectoryName(document)?.Replace('/', '\\') ?? "";
                    foreach (var m in matches)
                        if (m.IndexOf(dirHint, StringComparison.OrdinalIgnoreCase) >= 0) return m;
                    if (matches.Length > 0) return matches[0];
                }
                catch { }
            }

            return null;
        }

        /// <summary>
        /// Normalizes risk level from either string ("CRITICAL") or numeric ("4") format.
        /// </summary>
        private static string NormalizeRiskLevel(string riskLevel)
        {
            if (string.IsNullOrEmpty(riskLevel)) return "MEDIUM";
            switch (riskLevel.Trim())
            {
                case "0": return "SAFE";
                case "1": return "LOW";
                case "2": return "MEDIUM";
                case "3": return "HIGH";
                case "4": return "CRITICAL";
                default: return riskLevel.ToUpper();
            }
        }

        private static TaskPriority GetTaskPriority(string riskLevel)
        {
            switch (NormalizeRiskLevel(riskLevel))
            {
                case "CRITICAL":
                case "HIGH":
                    return TaskPriority.High;
                case "MEDIUM":
                    return TaskPriority.Normal;
                case "LOW":
                    return TaskPriority.Low;
            }

            return TaskPriority.Normal;
        }

        private static TaskErrorCategory GetErrorCategory(string riskLevel)
        {
            switch (NormalizeRiskLevel(riskLevel))
            {
                case "CRITICAL":
                    return TaskErrorCategory.Error;    // Red icon
                case "HIGH":
                    return TaskErrorCategory.Warning;  // Amber icon
                case "MEDIUM":
                    return TaskErrorCategory.Message;  // Blue icon
                case "LOW":
                    return TaskErrorCategory.Message;  // Blue/info icon (closest to green)
            }

            return TaskErrorCategory.Warning;
        }

        private static async Task<T> PostAsync<T>(string sastEndpoint, HttpContent formData)
        {
            using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
            {
                client.Timeout = TimeSpan.FromHours(4); // Long timeout for 1GB+ customer projects

                var req = new HttpRequestMessage
                {
                    RequestUri = new Uri(sastEndpoint),
                    Method = HttpMethod.Post,
                    Content = formData
                };

                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                var response = await client.SendAsync(req);
                response.EnsureSuccessStatusCode();

                var responseJson = await response.Content.ReadAsStringAsync();
                var scanResponse = JsonConvert.DeserializeObject<T>(responseJson);

                return scanResponse;
            }
        }

        private static async Task<T> GetAsync<T>(string sastEndpoint)
        {
            using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
            {
                var req = new HttpRequestMessage
                {
                    RequestUri = new Uri(sastEndpoint),
                    Method = HttpMethod.Get
                };

                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                var response = await client.SendAsync(req);
                response.EnsureSuccessStatusCode();

                var responseJson = await response.Content.ReadAsStringAsync();
                var scanResponse = JsonConvert.DeserializeObject<T>(responseJson);

                return scanResponse;
            }
        }

        private class AuthResult
        {
            public bool IsAuthorized { get; set; }
            public int? StatusCode { get; set; }
            public bool IsNetworkError { get; set; }
        }

        private static async Task<AuthResult> VerifySastAuthorizationAsync(string sastEndpoint)
        {
            try
            {
                using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
                {
                    client.Timeout = TimeSpan.FromSeconds(15);

                    var req = new HttpRequestMessage
                    {
                        RequestUri = new Uri(sastEndpoint),
                        Method = HttpMethod.Get
                    };

                    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                    var response = await client.SendAsync(req);
                    var statusCode = (int)response.StatusCode;

                    return new AuthResult
                    {
                        IsAuthorized = response.IsSuccessStatusCode,
                        StatusCode = statusCode,
                        IsNetworkError = false
                    };
                }
            }
            catch (Exception)
            {
                return new AuthResult
                {
                    IsAuthorized = false,
                    StatusCode = null,
                    IsNetworkError = true
                };
            }
        }

        private static string _tempZipPath;

        private static (MultipartFormDataContent, string) GetMultipartFormData(string folderPath = null)
        {
            var projectName = "";

            if (folderPath == null) return (new MultipartFormDataContent(), projectName);

            // Zip to temp file (supports large projects 500MB+)
            _tempZipPath = ZipFolderToFile(folderPath);

            var formData = new MultipartFormDataContent();

            projectName = folderPath.TrimEnd('\\', '/').Split('\\').Last();
            projectName = projectName?.Length > 13 ? projectName.Substring(0, 13) : projectName;
            projectName = $"{projectName}_{Guid.NewGuid()}";

            var fileStream = new FileStream(_tempZipPath, FileMode.Open, FileAccess.Read);
            var streamContent = new StreamContent(fileStream);
            streamContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/zip");

            formData.Add(streamContent, "\"FileSource\"", $"{projectName}.zip");
            formData.Add(new StringContent(projectName), "\"Name\"");
            formData.Add(new StringContent("VsExtension"), "\"ExternalScanSourceType\"");

            return (formData, projectName);
        }

        /// <summary>
        /// Zips a folder to a temporary file on disk (supports large projects 500MB+).
        /// Returns the path to the temp zip file. Caller must delete after use.
        /// </summary>
        private static string ZipFolderToFile(string folderPath)
        {
            if (!Directory.Exists(folderPath)) return null;

            var tempFile = Path.GetTempFileName();
            File.Delete(tempFile);
            tempFile = Path.ChangeExtension(tempFile, ".zip");

            var from = new DirectoryInfo(folderPath);

            using (var zipStream = new FileStream(tempFile, FileMode.Create))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                foreach (var file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
                {
                    var ext = Path.GetExtension(file);
                    if (ScanCache.ExcludeExts.Contains(ext)) continue;

                    var relativePath = file.Substring(from.FullName.Length).TrimStart('\\', '/');
                    var parts = relativePath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Any(p => ScanCache.ExcludeFolders.Contains(p))) continue;

                    try
                    {
                        var fileInfo = new FileInfo(file);
                        if (fileInfo.Length > MaxFileSizeBytes) continue;

                        archive.CreateEntryFromFile(file, relativePath.Replace("\\", "/"));
                    }
                    catch
                    {
                        // Skip files we can't read
                    }
                }
            }

            return tempFile;
        }

        /// <summary>
        /// Zips only the specified files (by relative path) for incremental scanning.
        /// Much faster than full zip for large codebases with few changes.
        /// </summary>
        private static string ZipSpecificFiles(string folderPath, List<string> relativePaths)
        {
            if (!Directory.Exists(folderPath) || relativePaths == null || relativePaths.Count == 0) return null;

            var tempFile = Path.GetTempFileName();
            File.Delete(tempFile);
            tempFile = Path.ChangeExtension(tempFile, ".zip");

            using (var zipStream = new FileStream(tempFile, FileMode.Create))
            using (var archive = new ZipArchive(zipStream, ZipArchiveMode.Create))
            {
                foreach (var relativePath in relativePaths)
                {
                    var fullPath = Path.Combine(folderPath, relativePath);
                    if (!File.Exists(fullPath)) continue;

                    try
                    {
                        var fileInfo = new FileInfo(fullPath);
                        if (fileInfo.Length > MaxFileSizeBytes) continue;

                        archive.CreateEntryFromFile(fullPath, relativePath.Replace("\\", "/"));
                    }
                    catch
                    {
                        // Skip files we can't read
                    }
                }
            }

            return tempFile;
        }

        // Legacy in-memory version kept for backward compat
        private static byte[] ZipFolders(string folderPath)
        {
            var tempFile = ZipFolderToFile(folderPath);
            if (tempFile == null) return null;
            try { return File.ReadAllBytes(tempFile); }
            finally { try { File.Delete(tempFile); } catch { } }
        }

        public static string GetSolutionFolderPath(string solutionFilePath)
        {
            if (string.IsNullOrEmpty(solutionFilePath)) return "";

            // If it's a directory (Folder View mode), return it directly
            if (Directory.Exists(solutionFilePath))
                return solutionFilePath.TrimEnd('\\', '/') + "\\";

            // If it's a file (.sln), return its parent directory
            if (File.Exists(solutionFilePath))
                return Path.GetDirectoryName(solutionFilePath) + "\\";

            // Fallback: strip the last path component
            return solutionFilePath.Replace(solutionFilePath.Split('\\').Last(), "");
        }

        private static async Task ValidateSettingsAsync()
        {
            if (string.IsNullOrWhiteSpace(Settings.Default.BaseUrl) || Settings.Default.BaseUrl == "<Replace with SAST API base url>")
            {
                throw new ArgumentException("Please setup base url under Offensive 360 settings");
            }
            else if (string.IsNullOrWhiteSpace(Settings.Default.AccessToken) || Settings.Default.AccessToken == "<Replace with SAST API access token starting with ey..>")
            {
                throw new ArgumentException("Please setup access token under Offensive 360 settings");
            }
            else
            {
                Uri uriResult;
                bool isValidEndpoint = Uri.TryCreate(Settings.Default.BaseUrl, UriKind.Absolute, out uriResult);
                isValidEndpoint = uriResult?.Scheme == Uri.UriSchemeHttp || uriResult?.Scheme == Uri.UriSchemeHttps;

                if (!isValidEndpoint)
                {
                    throw new ArgumentException("Please setup correct base url under Offensive 360 settings");
                }

                // Skip validation — go straight to scan. The upload itself will fail fast if server is unreachable.
                // Previous curl-based validation was intermittently deadlocking in the VS process context.
                System.Diagnostics.Debug.WriteLine("Offensive360: Skipping pre-validation, will validate during upload");
            }
        }

        /// <summary>
        /// Validates server connectivity using curl to avoid .NET HttpClient SSL issues
        /// with self-signed certificates and nginx SSL renegotiation on on-prem instances.
        /// </summary>
        private static async Task<AuthResult> VerifyServerViaCurlAsync(string baseUrl, string token)
        {
            try
            {
                var bashPath = @"C:\Program Files\Git\bin\bash.exe";
                if (!File.Exists(bashPath))
                    bashPath = @"C:\Program Files (x86)\Git\bin\bash.exe";
                if (!File.Exists(bashPath))
                {
                    // Fall back to .NET HttpClient if no bash
                    return await VerifySastAuthorizationAsync($"{baseUrl}{projectEndpoint}?page=1&pageSize=1");
                }

                // Use curl.exe directly (not via bash) — simpler and avoids shell quoting issues
                var curlPath = @"C:\Program Files\Git\mingw64\bin\curl.exe";
                if (!File.Exists(curlPath))
                    curlPath = @"C:\Program Files (x86)\Git\mingw64\bin\curl.exe";
                if (!File.Exists(curlPath))
                {
                    // Fall back to .NET HttpClient if no curl
                    return await VerifySastAuthorizationAsync($"{baseUrl}{projectEndpoint}?page=1&pageSize=1");
                }

                var psi = new ProcessStartInfo
                {
                    FileName = curlPath,
                    Arguments = $"-sk --connect-timeout 10 --max-time 15 -o NUL -w \"%{{http_code}}\" -H \"Authorization: Bearer {token}\" \"{baseUrl}/app/api/HealthCheck\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = false  // Don't redirect stderr — prevents deadlock
                };

                try
                {
                    string curlOutput = "";
                    using (var process = Process.Start(psi))
                    {
                        // Read stdout asynchronously to avoid deadlocks
                        var stdoutBuilder = new System.Text.StringBuilder();
                        process.OutputDataReceived += (s, args) => { if (args.Data != null) stdoutBuilder.Append(args.Data); };
                        process.BeginOutputReadLine();
                        var exited = await Task.Run(() => process.WaitForExit(20000));
                        curlOutput = stdoutBuilder.ToString();
                        if (!exited)
                        {
                            try { process.Kill(); } catch { }
                            return new AuthResult { IsAuthorized = false, StatusCode = null, IsNetworkError = true };
                        }
                    }

                    System.Diagnostics.Debug.WriteLine($"Offensive360: curl health check output: '{curlOutput.Trim()}'");
                    string codeStr = curlOutput.Trim();
                    int.TryParse(codeStr, out int httpCode);

                    if (httpCode == 0)
                        return new AuthResult { IsAuthorized = false, StatusCode = null, IsNetworkError = true };

                    // HealthCheck returns 401 when running (no auth needed to confirm server is alive)
                    // 401 = server is running and reachable, just not authorized for this endpoint
                    // 200 = server is running
                    // 403 = server is running, token has limited access
                    return new AuthResult
                    {
                        IsAuthorized = httpCode == 200 || httpCode == 401 || httpCode == 403,
                        StatusCode = httpCode,
                        IsNetworkError = false
                    };
                }
                finally
                {
                    // No temp files to clean up — using direct curl output
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Offensive360: VerifyServerViaCurlAsync failed — {ex.GetType().Name}: {ex.Message}");
                return new AuthResult { IsAuthorized = false, StatusCode = null, IsNetworkError = true };
            }
        }

        private class SastHttpException : Exception
        {
            public HttpStatusCode StatusCode { get; }
            public SastHttpException(HttpStatusCode code, string message) : base(message) { StatusCode = code; }
        }

        private static async Task<string> PostAsStringAsync(string sastEndpoint, HttpContent formData)
        {
            using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
            {
                client.Timeout = TimeSpan.FromHours(4); // Long timeout for 1GB+ customer projects

                var req = new HttpRequestMessage
                {
                    RequestUri = new Uri(sastEndpoint),
                    Method = HttpMethod.Post,
                    Content = formData
                };

                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                var response = await client.SendAsync(req);
                if (!response.IsSuccessStatusCode)
                {
                    throw new SastHttpException(response.StatusCode, $"Server returned {(int)response.StatusCode}");
                }

                return await response.Content.ReadAsStringAsync();
            }
        }

        /// <summary>
        /// Posts a multipart scan upload with multiple fallback strategies:
        /// 1. Git curl (preferred, handles most SSL edge cases)
        /// 2. .NET HttpClient with forced TLS 1.2 + cert bypass (works when curl/SChannel hits nginx renegotiation)
        /// 3. Python requests with OpenSSL (last resort, only if Python is installed)
        /// </summary>
        private static async Task<(int httpCode, string body)> PostScanViaCurl(string endpoint, string token, string zipFilePath, string projectName)
        {
            // Attempt 1: Git curl
            var curlResult = await PostScanViaCurlInternal(endpoint, token, zipFilePath, projectName);
            if (curlResult.httpCode != 0 && curlResult.httpCode != 502)
                return curlResult;

            try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] curl returned HTTP {curlResult.httpCode}, trying .NET HttpClient fallback...\n"); } catch {}

            // Attempt 2: .NET HttpClient with forced TLS 1.2 and cert bypass.
            // This is the most reliable path when Git curl/SChannel can't negotiate
            // with the customer's nginx — HttpClient uses a different TLS stack.
            var dotnetResult = await PostScanViaDotNetAsync(endpoint, token, zipFilePath, projectName);
            if (dotnetResult.httpCode != 0 && dotnetResult.httpCode != 502)
                return dotnetResult;

            try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] .NET HttpClient returned HTTP {dotnetResult.httpCode}, trying Python fallback...\n"); } catch {}

            // Attempt 3: Python requests with OpenSSL (last resort)
            var pythonResult = await PostScanViaPython(endpoint, token, zipFilePath, projectName);
            if (pythonResult.httpCode != 0)
                return pythonResult;

            // All failed — return whichever got closest to a real response
            if (curlResult.httpCode != 0) return curlResult;
            if (dotnetResult.httpCode != 0) return dotnetResult;
            return pythonResult;
        }

        /// <summary>
        /// .NET HttpClient upload path. Forces TLS 1.2 and accepts any certificate.
        /// Works on customer machines where Git curl's SChannel hits SSL renegotiation issues
        /// with on-prem nginx, and where Python is not installed.
        /// </summary>
        private static async Task<(int httpCode, string body)> PostScanViaDotNetAsync(string endpoint, string token, string zipFilePath, string projectName)
        {
            try
            {
                // Force TLS 1.2 (older .NET Framework defaults to TLS 1.0/1.1 which nginx rejects)
                try { System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12; } catch { }

                var handler = new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true,
                    AllowAutoRedirect = true
                };

                using (var client = new HttpClient(handler, disposeHandler: true))
                {
                    client.Timeout = TimeSpan.FromHours(4);
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

                    using (var form = new MultipartFormDataContent())
                    using (var fileStream = new FileStream(zipFilePath, FileMode.Open, FileAccess.Read))
                    {
                        var fileContent = new StreamContent(fileStream);
                        fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/zip");
                        form.Add(fileContent, "FileSource", $"{projectName}.zip");
                        form.Add(new StringContent(projectName), "Name");
                        form.Add(new StringContent("VsExtension"), "ExternalScanSourceType");

                        try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] .NET HttpClient POST {endpoint}...\n"); } catch {}
                        var resp = await client.PostAsync(endpoint, form).ConfigureAwait(false);
                        var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                        try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] .NET HttpClient HTTP {(int)resp.StatusCode}, body length={body?.Length ?? 0}\n"); } catch {}
                        return ((int)resp.StatusCode, body ?? "");
                    }
                }
            }
            catch (Exception ex)
            {
                // Flatten exception chain for logging
                var root = ex; while (root.InnerException != null) root = root.InnerException;
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] .NET HttpClient EXCEPTION: {ex.GetType().Name}: {ex.Message} | Inner: {root.GetType().Name}: {root.Message}\n"); } catch {}
                return (0, $".NET HttpClient error: {root.GetType().Name}: {root.Message}");
            }
        }

        /// <summary>
        /// Uploads via Python requests (uses OpenSSL, not Schannel).
        /// Handles servers where curl/Schannel fails on SSL renegotiation during multipart POST.
        /// </summary>
        private static async Task<(int httpCode, string body)> PostScanViaPython(string endpoint, string token, string zipFilePath, string projectName)
        {
            var pythonPath = @"C:\Program Files\Python312\python.exe";
            if (!File.Exists(pythonPath))
            {
                // Try common Python paths
                foreach (var p in new[] { @"C:\Python312\python.exe", @"C:\Python311\python.exe", @"C:\Python310\python.exe" })
                    if (File.Exists(p)) { pythonPath = p; break; }
            }
            if (!File.Exists(pythonPath))
            {
                // Try PATH
                pythonPath = "python";
            }

            var outputFile = Path.GetTempFileName();
            var statusFile = Path.GetTempFileName();
            var scriptFile = Path.GetTempFileName() + ".py";

            var scriptContent = $@"
import sys, json
try:
    import requests, urllib3
    urllib3.disable_warnings()
    resp = requests.post(
        '{endpoint}',
        headers={{'Authorization': 'Bearer {token}'}},
        files={{'FileSource': ('{projectName}.zip', open(r'{zipFilePath}', 'rb'), 'application/zip')}},
        data={{'Name': '{projectName}', 'ExternalScanSourceType': 'VsExtension'}},
        verify=False, timeout=900
    )
    with open(r'{outputFile}', 'w') as f: f.write(resp.text)
    with open(r'{statusFile}', 'w') as f: f.write(str(resp.status_code))
except Exception as e:
    with open(r'{statusFile}', 'w') as f: f.write('0')
    with open(r'{outputFile}', 'w') as f: f.write(str(e))
";
            File.WriteAllText(scriptFile, scriptContent);

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = pythonPath,
                    Arguments = $"\"{scriptFile}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(psi))
                {
                    var exited = await Task.Run(() => process.WaitForExit(960000));
                    if (!exited)
                    {
                        try { process.Kill(); } catch { }
                        return (0, "Python upload timed out");
                    }
                }

                string body = File.Exists(outputFile) ? File.ReadAllText(outputFile) : "";
                string codeStr = File.Exists(statusFile) ? File.ReadAllText(statusFile).Trim() : "0";
                int.TryParse(codeStr, out int httpCode);
                return (httpCode, body);
            }
            catch
            {
                return (0, "Python not available");
            }
            finally
            {
                try { File.Delete(outputFile); } catch { }
                try { File.Delete(statusFile); } catch { }
                try { File.Delete(scriptFile); } catch { }
            }
        }

        private static async Task<(int httpCode, string body)> PostScanViaCurlInternal(string endpoint, string token, string zipFilePath, string projectName)
        {
            // Use Git's curl directly (better SSL compatibility than system curl)
            var curlPath = @"C:\Program Files\Git\mingw64\bin\curl.exe";
            if (!File.Exists(curlPath))
                curlPath = @"C:\Program Files (x86)\Git\mingw64\bin\curl.exe";
            if (!File.Exists(curlPath))
                curlPath = "curl";

            // Capture stderr to a file so we can diagnose SSL / connection failures.
            // Using -v + --stderr file is deadlock-safe because curl writes directly
            // to the file; we don't read stderr from the pipe.
            var stderrFile = Path.GetTempFileName();

            var psi = new ProcessStartInfo
            {
                FileName = curlPath,
                // Long timeouts for very large customer projects (~1GB source).
                // connect-timeout 60s, max-time 14400s (4 hours).
                // --stderr writes verbose output to file (deadlock-safe).
                Arguments = $"-skv --connect-timeout 60 --max-time 14400 " +
                    $"--stderr \"{stderrFile}\" " +
                    $"-w \"|||HTTP_CODE:%{{http_code}}\" " +
                    $"-F \"FileSource=@{zipFilePath};type=application/zip\" " +
                    $"-F \"Name={projectName}\" " +
                    $"-F \"ExternalScanSourceType=VsExtension\" " +
                    $"-H \"Authorization: Bearer {token}\" " +
                    $"\"{endpoint}\"",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = false
            };

            System.Diagnostics.Debug.WriteLine($"Offensive360: curl upload → {endpoint}");

            try
            {
                using (var process = Process.Start(psi))
                {
                    var stdoutBuilder = new System.Text.StringBuilder();
                    process.OutputDataReceived += (s, args) => { if (args.Data != null) stdoutBuilder.Append(args.Data); };
                    process.BeginOutputReadLine();

                    // Watchdog: 4h 5min — slightly longer than curl's --max-time 14400
                    var exited = await Task.Run(() => process.WaitForExit(14700000));
                    if (!exited)
                    {
                        try { process.Kill(); } catch { }
                        throw new TimeoutException("Scan upload timed out after 4 hours. Please contact your O360 administrator if your project is exceptionally large.");
                    }

                    var output = stdoutBuilder.ToString();

                    // Parse response — HTTP code is after |||HTTP_CODE: marker
                    var marker = "|||HTTP_CODE:";
                    var markerIdx = output.LastIndexOf(marker);
                    int httpCode = 0;
                    string body = output;
                    if (markerIdx >= 0)
                    {
                        int.TryParse(output.Substring(markerIdx + marker.Length).Trim(), out httpCode);
                        body = output.Substring(0, markerIdx);
                    }

                    System.Diagnostics.Debug.WriteLine($"Offensive360: curl result — HTTP {httpCode}, body length {body.Length}, exit {process.ExitCode}");

                    // Log diagnostic info on failure so we can see *why* curl failed
                    if (httpCode == 0 || process.ExitCode != 0)
                    {
                        try
                        {
                            var stderrContent = File.Exists(stderrFile) ? File.ReadAllText(stderrFile) : "";
                            // Keep the last ~800 chars so the log isn't flooded
                            if (stderrContent.Length > 800)
                                stderrContent = "..." + stderrContent.Substring(stderrContent.Length - 800);
                            File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt",
                                $"[{DateTime.Now}] curl exit={process.ExitCode} httpCode={httpCode}\ncurl stderr tail:\n{stderrContent}\n");
                        }
                        catch { }
                    }

                    return (httpCode, body);
                }
            }
            finally
            {
                try { if (File.Exists(stderrFile)) File.Delete(stderrFile); } catch { }
            }
        }

        /// <summary>
        /// Polls until scan completes, then immediately fetches results before
        /// the server deletes the ephemeral project (KeepInvisibleAndDeletePostScan).
        /// </summary>
        private static async Task<ScanResponse> WaitForScanAndFetchResultsAsync(IVsStatusbar statusBar, string projectId, string scanMessagePrefix)
        {
            var pollPeriod = TimeSpan.FromSeconds(10);
            // 4-hour result polling cap for 1GB+ projects with long server-side analysis
            var maxWaitTime = TimeSpan.FromHours(4);
            var stopWatch = new Stopwatch();
            stopWatch.Start();
            var firstPoll = true;

            do
            {
                // Short initial delay (3s), then standard interval — avoids missing fast scans
                await Task.Delay(firstPoll ? TimeSpan.FromSeconds(3) : pollPeriod);
                firstPoll = false;

                var statusUrl = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}";

                using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
                {
                    var req = new HttpRequestMessage
                    {
                        RequestUri = new Uri(statusUrl),
                        Method = HttpMethod.Get
                    };
                    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                    var response = await client.SendAsync(req);

                    if (response.StatusCode == HttpStatusCode.NotFound)
                    {
                        stopWatch.Stop();
                        throw new Exception("Project not found (404). The scan may have been deleted by the server.");
                    }

                    if (response.IsSuccessStatusCode)
                    {
                        var body = await response.Content.ReadAsStringAsync();
                        var project = Newtonsoft.Json.Linq.JObject.Parse(body);
                        var status = project.Value<int>("status");

                        switch (status)
                        {
                            case 2: // Succeeded
                            case 4: // Partial Failed
                                stopWatch.Stop();
                                await statusBar.ShowProgressAsync($"{scanMessagePrefix} — retrieving results");
                                // Fetch results IMMEDIATELY before server deletes the ephemeral project
                                return await GetScanResultsAsync(projectId);
                            case 3: // Failed
                                throw new Exception("Scan failed on server");
                            case 5: // Skipped
                                throw new Exception("Scan was skipped by server");
                            default: // 0=Queued, 1=InProgress
                                var statusText = status == 0 ? "queued" : status == 1 ? "in progress" : $"status {status}";
                                await statusBar.ShowProgressAsync($"{scanMessagePrefix} is {statusText}");
                                break;
                        }
                    }
                }
            }
            while (stopWatch.Elapsed < maxWaitTime);

            stopWatch.Stop();
            throw new TimeoutException($"Scan timed out after {maxWaitTime.TotalMinutes} minutes");
        }

        /// <summary>
        /// Deletes a project from the server to avoid leaving scan artifacts visible in the dashboard.
        /// </summary>
        private static async Task DeleteProjectAsync(string projectId)
        {
            try
            {
                var url = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}";
                using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
                {
                    var req = new HttpRequestMessage
                    {
                        RequestUri = new Uri(url),
                        Method = HttpMethod.Delete
                    };
                    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);
                    await client.SendAsync(req);
                }
            }
            catch { /* best-effort cleanup */ }
        }

        private static readonly string[] riskLevelNames = { "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

        /// <summary>
        /// Best-effort resolution of an absolute file path for the tool window's double-click
        /// navigation. Tries filePath (raw), filePath joined to the solution folder, and a
        /// recursive search by file name under the solution folder (strips any zip prefix).
        /// Returns null if nothing matches — the tool window handles null gracefully.
        /// </summary>
        private static string ResolveAbsoluteFilePath(string solutionFolder, string filePath, string fileName)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(filePath) && File.Exists(filePath)) return filePath;
                if (!string.IsNullOrWhiteSpace(solutionFolder) && !string.IsNullOrWhiteSpace(filePath))
                {
                    var joined = Path.Combine(solutionFolder, filePath.TrimStart('\\', '/'));
                    if (File.Exists(joined)) return joined;
                    // Strip common zip prefix dirs one level at a time
                    var parts = filePath.Replace('\\', '/').Split('/');
                    for (int start = 1; start < parts.Length; start++)
                    {
                        var sub = string.Join("\\", parts, start, parts.Length - start);
                        var candidate = Path.Combine(solutionFolder, sub);
                        if (File.Exists(candidate)) return candidate;
                    }
                }
                if (!string.IsNullOrWhiteSpace(solutionFolder) && !string.IsNullOrWhiteSpace(fileName))
                {
                    var matches = Directory.GetFiles(solutionFolder, fileName, SearchOption.AllDirectories);
                    if (matches != null && matches.Length > 0) return matches[0];
                }
            }
            catch { }
            return null;
        }

        private static async Task<ScanResponse> GetScanResultsAsync(string projectId)
        {
            // Wait for server to populate results — poll project for vulnerabilitiesCount > 0
            for (int attempt = 0; attempt < 12; attempt++)
            {
                try
                {
                    var checkUrl = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}";
                    using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
                    {
                        var req = new HttpRequestMessage { RequestUri = new Uri(checkUrl), Method = HttpMethod.Get };
                        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);
                        var resp = await client.SendAsync(req);
                        if (resp.IsSuccessStatusCode)
                        {
                            var body = await resp.Content.ReadAsStringAsync();
                            var project = Newtonsoft.Json.Linq.JObject.Parse(body);
                            var vulnCount = project.Value<int>("vulnerabilitiesCount");
                            if (vulnCount > 0) break;
                        }
                    }
                }
                catch { break; }
                await Task.Delay(5000);
            }

            // Fetch results
            var results = await FetchLangResultsAsync(projectId);
            if (results.Vulnerabilities != null && results.Vulnerabilities.Any())
                return results;

            // One more try after 10s
            await Task.Delay(10000);
            return await FetchLangResultsAsync(projectId);
        }

        private static async Task<ScanResponse> FetchLangResultsAsync(string projectId)
        {
            var resultsUrl = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}/LangaugeScanResult";

            using (var client = new HttpClient(CreateHandler(), disposeHandler: true))
            {
                var req = new HttpRequestMessage
                {
                    RequestUri = new Uri(resultsUrl),
                    Method = HttpMethod.Get
                };
                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                var response = await client.SendAsync(req);
                response.EnsureSuccessStatusCode();

                var body = await response.Content.ReadAsStringAsync();
                var items = Newtonsoft.Json.Linq.JToken.Parse(body);

                // The response may be an array directly or an object with pageItems
                var array = items is Newtonsoft.Json.Linq.JArray
                    ? (Newtonsoft.Json.Linq.JArray)items
                    : items["pageItems"] as Newtonsoft.Json.Linq.JArray ?? new Newtonsoft.Json.Linq.JArray();

                var vulnerabilities = array.Select(item => new VulnerabilityResponse
                {
                    Title = item.Value<string>("type") ?? "",
                    LineNumber = $"{item.Value<int>("lineNo")},{item.Value<int>("columnNo")}",
                    RiskLevel = MapRiskLevel(item.Value<int>("riskLevel")),
                    Vulnerability = item.Value<string>("vulnerability") ?? "",
                    FileName = item.Value<string>("fileName") ?? "",
                    FilePath = item.Value<string>("filePath") ?? "",
                    References = item.Value<string>("references") ?? ""
                }).ToList();

                return new ScanResponse { Vulnerabilities = vulnerabilities };
            }
        }

        private static string MapRiskLevel(int level)
        {
            if (level >= 0 && level < riskLevelNames.Length)
                return riskLevelNames[level];
            return "MEDIUM";
        }
    }
}