using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using OffensiveVS360.Models;
using OffensiveVS360.Options;

namespace OffensiveVS360.Services
{
    public class ScanProgressEventArgs : EventArgs
    {
        public string Message { get; set; }
        public ScanProgressEventArgs(string message) { Message = message; }
    }

    public class ScanService : IDisposable
    {
        private static readonly HashSet<string> ExcludedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".pdb", ".obj", ".bin", ".lib", ".a", ".so", ".dylib",
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wmv",
            ".zip", ".tar", ".gz", ".rar", ".7z", ".bz2",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".ttf", ".otf", ".woff", ".woff2", ".eot",
            ".db", ".sqlite", ".mdb", ".accdb",
            ".DS_Store", ".lock"
        };

        private static readonly HashSet<string> ExcludedDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "node_modules", ".git", "bin", "obj", "build", "dist", "out",
            "target", ".idea", ".vs", "vendor", "__pycache__", ".gradle",
            "packages", "artifacts"
        };

        private const string ScanSourceType = "VisualStudioExtension";
        private const int QueuePollIntervalMs = 10000;
        private const int MaxQueueWaitMinutes = 60;

        private readonly HttpClient _httpClient;
        private bool _scanInProgress;

        public event EventHandler<ScanProgressEventArgs> ProgressChanged;

        public bool IsScanInProgress => _scanInProgress;

        public ScanService()
        {
            var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
            };
            _httpClient = new HttpClient(handler)
            {
                Timeout = Timeout.InfiniteTimeSpan
            };
        }

        public async Task<ScanResponse> ScanFolderAsync(string folderPath, CancellationToken cancellationToken)
        {
            if (_scanInProgress)
                throw new InvalidOperationException("A scan is already in progress.");

            _scanInProgress = true;
            try
            {
                var settings = OptionsPage.GetSettings();
                ValidateSettings(settings);

                var projectName = GenerateProjectName(folderPath);
                ReportProgress($"Preparing files for scan: {projectName}");

                var zipBytes = ZipFolder(folderPath);
                ReportProgress($"Uploading {(zipBytes.Length / 1024.0 / 1024.0):F1} MB to server...");

                cancellationToken.ThrowIfCancellationRequested();

                var response = await PostScanAsync(settings, projectName, zipBytes, projectName + ".zip", cancellationToken);
                ReportProgress($"Scan complete: {response.Vulnerabilities?.Count ?? 0} findings");
                return response;
            }
            finally
            {
                _scanInProgress = false;
            }
        }

        public async Task<ScanResponse> ScanFileAsync(string filePath, CancellationToken cancellationToken)
        {
            if (_scanInProgress)
                throw new InvalidOperationException("A scan is already in progress.");

            _scanInProgress = true;
            try
            {
                var settings = OptionsPage.GetSettings();
                ValidateSettings(settings);

                var projectName = GenerateProjectName(filePath);
                var fileName = Path.GetFileName(filePath);
                ReportProgress($"Scanning file: {fileName}");

                var zipBytes = ZipSingleFile(filePath);
                var response = await PostScanAsync(settings, projectName, zipBytes, projectName + ".zip", cancellationToken);
                ReportProgress($"Scan complete: {response.Vulnerabilities?.Count ?? 0} findings");
                return response;
            }
            finally
            {
                _scanInProgress = false;
            }
        }

        private async Task<ScanResponse> PostScanAsync(
            O360Settings settings, string projectName, byte[] zipBytes, string fileName,
            CancellationToken cancellationToken)
        {
            var endpoint = settings.Endpoint.TrimEnd('/');

            _httpClient.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", settings.AccessToken);

            // Try ExternalScan first, fall back to Project/scanProjectFile if 403
            var useExternalScan = await IsExternalScanAvailable(endpoint, cancellationToken);

            if (useExternalScan)
            {
                return await PostViaExternalScan(endpoint, settings, projectName, zipBytes, fileName, cancellationToken);
            }
            else
            {
                return await PostViaProjectScan(endpoint, settings, projectName, zipBytes, fileName, cancellationToken);
            }
        }

        private async Task<bool> IsExternalScanAvailable(string endpoint, CancellationToken cancellationToken)
        {
            try
            {
                var url = $"{endpoint}/app/api/ExternalScan/scanQueuePosition";
                var response = await _httpClient.GetAsync(url, cancellationToken);
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task<ScanResponse> PostViaExternalScan(
            string endpoint, O360Settings settings, string projectName, byte[] zipBytes,
            string fileName, CancellationToken cancellationToken)
        {
            var url = $"{endpoint}/app/api/ExternalScan";

            using (var content = new MultipartFormDataContent())
            {
                content.Add(new StringContent(projectName), "name");
                content.Add(new StringContent("True"), "keepInvisibleAndDeletePostScan");
                content.Add(new StringContent(ScanSourceType), "externalScanSourceType");
                content.Add(new StringContent(settings.ScanDependencies.ToString()), "allowDependencyScan");
                content.Add(new StringContent(settings.ScanLicenses.ToString()), "allowLicenseScan");
                content.Add(new StringContent(settings.ScanMalware.ToString()), "allowMalwareScan");

                var fileContent = new ByteArrayContent(zipBytes);
                fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/zip");
                content.Add(fileContent, "fileSource", fileName);

                var scanTask = _httpClient.PostAsync(url, content, cancellationToken);
                await PollQueuePositionAsync(settings, projectName, cancellationToken);
                var response = await scanTask;
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<ScanResponse>(json);
            }
        }

        private async Task<ScanResponse> PostViaProjectScan(
            string endpoint, O360Settings settings, string projectName, byte[] zipBytes,
            string fileName, CancellationToken cancellationToken)
        {
            var url = $"{endpoint}/app/api/Project/scanProjectFile";

            using (var content = new MultipartFormDataContent())
            {
                content.Add(new StringContent(projectName), "Name");
                content.Add(new StringContent(ScanSourceType), "ExternalScanSourceType");

                var fileContent = new ByteArrayContent(zipBytes);
                fileContent.Headers.ContentType = MediaTypeHeaderValue.Parse("application/zip");
                content.Add(fileContent, "FileSource", fileName);

                ReportProgress("Uploading to server...");
                var response = await _httpClient.PostAsync(url, content, cancellationToken);
                response.EnsureSuccessStatusCode();

                var json = await response.Content.ReadAsStringAsync();

                // Project endpoint returns projectId, need to poll for completion then fetch results
                string projectId = null;
                try
                {
                    var obj = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                    if (obj != null)
                    {
                        if (obj.ContainsKey("id")) projectId = obj["id"]?.ToString();
                        else if (obj.ContainsKey("projectId")) projectId = obj["projectId"]?.ToString();
                    }
                }
                catch
                {
                    projectId = json.Trim().Trim('"');
                }

                if (string.IsNullOrEmpty(projectId))
                    throw new Exception("No project ID returned from server");

                ReportProgress("Waiting for scan to complete...");
                return await WaitForScanAndFetchResults(endpoint, projectId, cancellationToken);
            }
        }

        private async Task<ScanResponse> WaitForScanAndFetchResults(string endpoint, string projectId, CancellationToken cancellationToken)
        {
            var maxWait = MaxQueueWaitMinutes * 60 * 1000;
            var elapsed = 0;

            while (elapsed < maxWait && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(5000, cancellationToken);
                elapsed += 5000;

                var statusUrl = $"{endpoint}/app/api/Project/{projectId}";
                var response = await _httpClient.GetAsync(statusUrl, cancellationToken);

                if (!response.IsSuccessStatusCode) continue;

                var json = await response.Content.ReadAsStringAsync();
                var project = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                if (project == null || !project.ContainsKey("status")) continue;

                var status = Convert.ToInt32(project["status"]);
                switch (status)
                {
                    case 2: // Succeeded
                    case 4: // Partial
                        ReportProgress("Fetching results...");
                        return await FetchProjectResults(endpoint, projectId, cancellationToken);
                    case 3: // Failed
                        throw new Exception("Scan failed on server");
                    case 5: // Skipped
                        throw new Exception("Scan was skipped by server");
                    default: // Queued (0) or InProgress (1)
                        var statusText = status == 0 ? "Queued" : "In Progress";
                        ReportProgress($"Scan {statusText}...");
                        break;
                }
            }

            throw new Exception($"Scan timed out after {MaxQueueWaitMinutes} minutes");
        }

        private async Task<ScanResponse> FetchProjectResults(string endpoint, string projectId, CancellationToken cancellationToken)
        {
            var result = new ScanResponse();
            result.Vulnerabilities = new List<Vulnerability>();

            // Fetch language vulnerabilities
            var langUrl = $"{endpoint}/app/api/Project/{projectId}/LangaugeScanResult?page=1&pageSize=500";
            try
            {
                var response = await _httpClient.GetAsync(langUrl, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    var pageData = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);
                    if (pageData != null && pageData.ContainsKey("pageItems"))
                    {
                        var items = JsonConvert.DeserializeObject<List<Vulnerability>>(pageData["pageItems"].ToString());
                        if (items != null) result.Vulnerabilities.AddRange(items);
                    }
                }
            }
            catch { /* ignore fetch errors for individual result types */ }

            return result;
        }

        private async Task PollQueuePositionAsync(O360Settings settings, string projectName, CancellationToken cancellationToken)
        {
            var endpoint = settings.Endpoint.TrimEnd('/');
            var url = $"{endpoint}/app/api/ExternalScan/scanQueuePosition?projectName={Uri.EscapeDataString(projectName)}";
            var maxWait = MaxQueueWaitMinutes * 60 * 1000;
            var elapsed = 0;

            while (elapsed < maxWait && !cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(QueuePollIntervalMs, cancellationToken);
                elapsed += QueuePollIntervalMs;

                try
                {
                    var response = await _httpClient.GetAsync(url, cancellationToken);
                    if (!response.IsSuccessStatusCode) return;

                    var body = await response.Content.ReadAsStringAsync();
                    if (int.TryParse(body.Trim(), out var position))
                    {
                        if (position <= 0) return;
                        ReportProgress($"Queue position: {position}");
                    }
                    else
                    {
                        return; // Scan started
                    }
                }
                catch
                {
                    return; // Scan likely started
                }
            }
        }

        private byte[] ZipFolder(string folderPath)
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    AddDirectoryToZip(archive, folderPath, folderPath);
                }
                return ms.ToArray();
            }
        }

        private void AddDirectoryToZip(ZipArchive archive, string rootPath, string currentPath)
        {
            foreach (var file in Directory.GetFiles(currentPath))
            {
                var ext = Path.GetExtension(file);
                if (ExcludedExtensions.Contains(ext)) continue;

                var relativePath = file.Substring(rootPath.Length).TrimStart(Path.DirectorySeparatorChar, '/');
                archive.CreateEntryFromFile(file, relativePath.Replace('\\', '/'));
            }

            foreach (var dir in Directory.GetDirectories(currentPath))
            {
                var dirName = Path.GetFileName(dir);
                if (ExcludedDirs.Contains(dirName)) continue;
                AddDirectoryToZip(archive, rootPath, dir);
            }
        }

        private byte[] ZipSingleFile(string filePath)
        {
            using (var ms = new MemoryStream())
            {
                using (var archive = new ZipArchive(ms, ZipArchiveMode.Create, true))
                {
                    archive.CreateEntryFromFile(filePath, Path.GetFileName(filePath));
                }
                return ms.ToArray();
            }
        }

        private string GenerateProjectName(string path)
        {
            var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar));
            if (name.Length > 13) name = name.Substring(0, 13);
            var guid = Guid.NewGuid().ToString("N").Substring(0, 4);
            return $"{name}_{guid}";
        }

        private void ValidateSettings(O360Settings settings)
        {
            if (string.IsNullOrWhiteSpace(settings.Endpoint))
                throw new InvalidOperationException("O360 SAST endpoint is not configured. Go to Tools → Options → O360 SAST.");
            if (string.IsNullOrWhiteSpace(settings.AccessToken))
                throw new InvalidOperationException("O360 SAST access token is not configured. Go to Tools → Options → O360 SAST.");
        }

        private void ReportProgress(string message)
        {
            ProgressChanged?.Invoke(this, new ScanProgressEventArgs(message));
        }

        public void Dispose()
        {
            _httpClient?.Dispose();
        }
    }
}
