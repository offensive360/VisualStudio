using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Newtonsoft.Json;
using Offensive360.VSExt.Properties;
using SAST.VSExt.Models;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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

        private static string currentFilePath;
        private static string scanFileEndpoint = "/app/api/Project/scanProjectFile";
        private static string projectEndpoint = "/app/api/Project";

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
            try
            {
                await ValidateSettingsAsync();

                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} is queued");

                var (formData, projectName) = GetMultipartFormData(folderPath: GetSolutionFolderPath(solutionFilePath));

                // Upload and get project ID
                var projectIdStr = await PostAsStringAsync($"{Settings.Default.BaseUrl.TrimEnd('/')}{scanFileEndpoint}", formData);
                projectIdStr = projectIdStr?.Trim().Trim('"');
                formData.Dispose();

                // Poll for scan completion AND fetch results immediately
                // (before server deletes the ephemeral project)
                var scanResponse = await WaitForScanAndFetchResultsAsync(statusBar, projectIdStr, projectScanMessagePrefix);

                var ignoredVulnerabilities = File.Exists(IgnoreFilePath(solutionFilePath)) ? File.ReadAllLines(IgnoreFilePath(solutionFilePath)) : new string[0];

                foreach (var vulnerability in scanResponse.Vulnerabilities)
                {
                    var (lineNo, columnNo) = PopulateLineAndColumnNumber(vulnerability.LineNumber);

                    if (!ignoredVulnerabilities.Contains(VulnerabilityIgnoreConfig(vulnerability.FilePath?.ToLower(), lineNo, columnNo, vulnerability.Title)))
                    {
                        Log(_errorListProvider, vulnerability);
                    }
                }

                currentFilePath = solutionFilePath;

                await statusBar.HideProgressAsync();
            }
            catch
            {
                await statusBar.HideProgressAsync();

                throw;
            }
        }
        
        public static void LogException(this ErrorListProvider _errorListProvider, string errorMessage, string fileName = "")
        {
            _errorListProvider.Tasks.Add(new ErrorTask()
            {
                ErrorCategory = TaskErrorCategory.Warning,
                Category = TaskCategory.All,
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

        private static void Log(ErrorListProvider _errorListProvider, VulnerabilityResponse vulnerability)
        {
            var (lineNo, columnNo) = PopulateLineAndColumnNumber(vulnerability.LineNumber);

            var errorTask = new ErrorTask
            {
                ErrorCategory = GetErrorCategory(vulnerability.RiskLevel),
                Category = TaskCategory.All,
                Text = $"[{vulnerability.Title}] {vulnerability.Vulnerability}" ,
                Document = vulnerability.FilePath,
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

            // Try knowledge base first
            var kbEntry = VulnerabilityKnowledgeBase.Lookup(vulnType);
            if (kbEntry != null)
            {
                System.Windows.MessageBox.Show(
                    VulnerabilityKnowledgeBase.GetFullHelp(vulnType),
                    $"Offensive360 - {kbEntry.Title}",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Information);
                return;
            }

            // Fallback: open filtered reference URLs
            string helpLink = errorTask.HelpKeyword;
            if (!string.IsNullOrWhiteSpace(helpLink))
            {
                var safeUrls = VulnerabilityKnowledgeBase.FilterReferences(helpLink);
                if (safeUrls.Count > 0)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo { FileName = safeUrls[0], UseShellExecute = true });
                    }
                    catch { }
                    return;
                }
            }

            // No help available
            System.Windows.MessageBox.Show(
                $"No detailed fix guidance available for \"{vulnType}\".\nCheck the O360 dashboard for more information.",
                "Offensive360 - Help",
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Information);
        }

        private static void OnErrorTaskClick(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            try
            {
                var errorTask = sender as ErrorTask;
                var dte = (EnvDTE.DTE)Marshal.GetActiveObject("VisualStudio.DTE");
                dte.MainWindow.Activate();

                var filePath = $"{currentFilePath.Replace(currentFilePath.Split('\\').Last(), "")}{errorTask.Document}";

                EnvDTE.Window w = dte.ItemOperations.OpenFile(filePath, EnvDTE.Constants.vsViewKindTextView);
                ((EnvDTE.TextSelection)dte.ActiveDocument.Selection).GotoLine((errorTask.Line + 1), true);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Offensive360: Navigation failed — {ex.Message}");
            }
        }

        private static TaskPriority GetTaskPriority(string riskLevel)
        {
            switch (riskLevel?.ToUpper())
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
            switch (riskLevel?.ToUpper())
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
            using (var client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromMinutes(60);

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
            using (var client = new HttpClient())
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
                using (var client = new HttpClient())
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

        private static (MultipartFormDataContent, string) GetMultipartFormData(string folderPath = null)
        {
            byte[] zipContent = null;
            var projectName = "";

            if (folderPath != null)
            {
                zipContent = ZipFolders(folderPath);
            }

            var formData = new MultipartFormDataContent();
            var content = new ByteArrayContent(zipContent);
            content.Headers.ContentType = MediaTypeHeaderValue.Parse("multipart/form-data");

            if (folderPath != null)
            {
                projectName = folderPath.Substring(0, folderPath.Length - 1).Split('\\').Last();
                projectName = projectName?.Length > 13 ? projectName.Substring(0, 13) : projectName;
                projectName = $"{projectName}_{Guid.NewGuid()}";

                formData.Add(content, "\"FileSource\"", Path.GetFileName($"{projectName}_{Guid.NewGuid()}.zip"));
                formData.Add(new StringContent(projectName), "\"Name\"");
                // KeepInvisibleAndDeletePostScan disabled until server-side delayed deletion is fixed
                // formData.Add(new StringContent("True"), "\"KeepInvisibleAndDeletePostScan\"");
                formData.Add(new StringContent("VsExtension"), "\"ExternalScanSourceType\"");
            }

            return (formData, projectName);
        }

        private static byte[] ZipFolders(string folderPath)
        {
            if (Directory.Exists(folderPath))
            {
                var from = new DirectoryInfo(folderPath);

                using (var zipToOpen = new MemoryStream())
                {
                    using (var archive = new ZipArchive(zipToOpen, ZipArchiveMode.Create))
                    {
                        var exludeFileExtensions = new string[] { ".zip", ".dll", ".pdf", ".txt", ".exe", ".DS_Store", ".ipr", ".iws", ".bak", ".tmp", ".aac", ".aif", ".iff", ".m3u", ".mid", ".mp3", ".mpa", ".ra", ".wav", ".wma", ".3g2", ".3gp", ".asf", ".asx", ".avi", ".flv", ".mov", ".mp4", ".mpg", ".rm", ".swf", ".vob", ".wmv", ".bmp", ".gif", ".jpg", ".png", ".psd", ".tif", ".swf", ".jar", ".zip", ".rar", ".exe", ".dll", ".pdb", ".7z", ".gz", ".tar.gz", ".tar", ".gz", ".ahtm", ".ahtml", ".fhtml", ".hdm", ".hdml", ".hsql", ".ht", ".hta", ".htc", ".htd", ".war", ".ear", ".htmls", ".ihtml", ".mht", ".mhtm", ".mhtml", ".ssi", ".stm", ".stml", ".ttml", ".txn", ".xhtm", ".xhtml", ".class", ".iml" };

                        var excludeSystemFiles = new string[] { "upgradelog.htm" };

                        var excludeSystemFolders = new string[] { ".vs", "cvs", ".svn", ".hg", ".git", ".bzr", "bin", "obj", "backup", ".idea", ".vscode", "node_modules" };

                        var files = Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories)
                                                .Where(f =>
                                                    !exludeFileExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()) &&
                                                    !excludeSystemFiles.Contains(f.ToLowerInvariant().Split('\\').Last()) &&
                                                    !excludeSystemFolders.Any(e => f.ToLowerInvariant().Contains($"\\{e}\\")));

                        foreach (var file in files)
                        {
                            var relPath = file.Substring(from.FullName.Length).Replace("\\", "/");
                            var readmeEntry = archive.CreateEntryFromFile(file, relPath);
                        }
                    }
                    return zipToOpen.ToArray();
                }
            }
            else
            {
                return null;
            }
        }

        public static string GetSolutionFolderPath(string solutionFilePath)
        {
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

                var authResult = await VerifySastAuthorizationAsync($"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}?page=1&pageSize=1");
                if (!authResult.IsAuthorized)
                {
                    throw new UnauthorizedAccessException(
                        VulnerabilityKnowledgeBase.GetAuthErrorMessage(authResult.StatusCode, authResult.IsNetworkError));
                }
            }
        }

        private static async Task<string> PostAsStringAsync(string sastEndpoint, HttpContent formData)
        {
            using (var client = new HttpClient())
            {
                client.Timeout = TimeSpan.FromMinutes(60);

                var req = new HttpRequestMessage
                {
                    RequestUri = new Uri(sastEndpoint),
                    Method = HttpMethod.Post,
                    Content = formData
                };

                req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", Settings.Default.AccessToken);

                var response = await client.SendAsync(req);
                response.EnsureSuccessStatusCode();

                return await response.Content.ReadAsStringAsync();
            }
        }

        /// <summary>
        /// Polls until scan completes, then immediately fetches results before
        /// the server deletes the ephemeral project (KeepInvisibleAndDeletePostScan).
        /// </summary>
        private static async Task<ScanResponse> WaitForScanAndFetchResultsAsync(IVsStatusbar statusBar, string projectId, string scanMessagePrefix)
        {
            var pollPeriod = TimeSpan.FromSeconds(10);
            var maxWaitTime = TimeSpan.FromMinutes(60);
            var stopWatch = new Stopwatch();
            stopWatch.Start();
            var firstPoll = true;

            do
            {
                // Short initial delay (3s), then standard interval — avoids missing fast scans
                await Task.Delay(firstPoll ? TimeSpan.FromSeconds(3) : pollPeriod);
                firstPoll = false;

                var statusUrl = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}";

                using (var client = new HttpClient())
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

        private static readonly string[] riskLevelNames = { "SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

        private static async Task<ScanResponse> GetScanResultsAsync(string projectId)
        {
            var resultsUrl = $"{Settings.Default.BaseUrl.TrimEnd('/')}{projectEndpoint}/{projectId}/LangaugeScanResult";

            using (var client = new HttpClient())
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