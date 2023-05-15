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
        private static string externalScanEndpoint = "/app/api/ExternalScan";
        private static string queuePosEndpoint = $"{externalScanEndpoint}/scanQueuePosition";

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

                var scanProcess = PostAsync<ScanResponse>($"{Settings.Default.BaseUrl.TrimEnd('/')}{externalScanEndpoint}", formData);

                await _errorListProvider.WaitAndShowQueuePositionAsync(statusBar, projectName, projectScanMessagePrefix);

                await statusBar.ShowProgressAsync($"{projectScanMessagePrefix} is in-progress");

                var scanResponse = await scanProcess;

                formData.Dispose();

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
                ErrorCategory = TaskErrorCategory.Warning,
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
            throw new NotImplementedException();
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
            catch
            {
                //DO Something
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

        private static async Task<bool> VerifySastAuthorizationAsync(string sastEndpoint)
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

                return !(response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden);
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
                formData.Add(new StringContent("True"), "\"KeepInvisibleAndDeletePostScan\"");
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

                var isAuthorized = await VerifySastAuthorizationAsync($"{Settings.Default.BaseUrl.TrimEnd('/')}{queuePosEndpoint}");
                if (!isAuthorized)
                {
                    throw new UnauthorizedAccessException("Unable to authorize SAST API with provided access token");
                }
            }
        }

        private static async Task WaitAndShowQueuePositionAsync(
            this ErrorListProvider _errorListProvider,
            IVsStatusbar statusBar,
            string projectName,
            string scanMessagePrefix)
        {
            var pollPeriod = TimeSpan.FromSeconds(10);
            var maxWaitTime = TimeSpan.FromMinutes(60);
            var stopWatch = new Stopwatch();
            stopWatch.Start();

            do
            {
                await Task.Delay(pollPeriod);

                var queuePosition = await GetAsync<int>($"{Settings.Default.BaseUrl.TrimEnd('/')}{queuePosEndpoint}?projectName={projectName}");
                if (queuePosition <= 0)
                {

                    stopWatch.Stop();
                    return;
                }
                await statusBar.ShowProgressAsync($"{scanMessagePrefix} is yet to start and your queue position is {queuePosition}");
            }
            while (stopWatch.Elapsed < maxWaitTime);

            stopWatch.Stop();
            throw new TimeoutException($"Operation '{nameof(WaitAndShowQueuePositionAsync)}' timed out after exceeding limit of {maxWaitTime}");
        }
    }
}