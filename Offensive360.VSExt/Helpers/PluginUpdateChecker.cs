using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Newtonsoft.Json;
using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Offensive360.VSExt.Helpers
{
    /// <summary>
    /// Plugin update notifier — fetches the latest release directly from the
    /// GitHub Releases API of offensive360/VisualStudio. No IDECO server
    /// dependency: anyone with internet sees updates immediately the moment a
    /// new release is published. Behaviour:
    ///   * fire-and-forget on every scan trigger, never blocks
    ///   * throttled (24h cache + once per session) so we never spam GitHub
    ///   * silent on any failure (404, network, parse, rate-limit)
    ///   * ALL errors swallowed — update notifications must NEVER break scans
    /// </summary>
    internal static class PluginUpdateChecker
    {
        private const string CurrentVersion = "1.12.10";
        private const string ReleasesApiUrl = "https://api.github.com/repos/offensive360/VisualStudio/releases/latest";
        private const string UserAgent = "Offensive360-VS-Plugin/" + CurrentVersion;
        private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);
        private static DateTime _lastCheck = DateTime.MinValue;
        private static bool _notifiedThisSession = false;

        private class GitHubRelease
        {
            [JsonProperty("tag_name")] public string TagName { get; set; }
            [JsonProperty("name")] public string Name { get; set; }
            [JsonProperty("body")] public string Body { get; set; }
            [JsonProperty("html_url")] public string HtmlUrl { get; set; }
            [JsonProperty("draft")] public bool Draft { get; set; }
            [JsonProperty("prerelease")] public bool Prerelease { get; set; }
            [JsonProperty("assets")] public GitHubAsset[] Assets { get; set; }
        }

        private class GitHubAsset
        {
            [JsonProperty("name")] public string Name { get; set; }
            [JsonProperty("browser_download_url")] public string BrowserDownloadUrl { get; set; }
        }

        /// <summary>
        /// Fire-and-forget. Never throws. Never blocks the scan.
        /// </summary>
        public static void CheckAsync()
        {
            if (_notifiedThisSession) return;
            if (DateTime.UtcNow - _lastCheck < CacheTtl) return;
            _lastCheck = DateTime.UtcNow;

            _ = Task.Run(async () =>
            {
                try
                {
                    // Force TLS 1.2 — older .NET Framework on Windows Server defaults to TLS 1.0/1.1 which GitHub rejects
                    try { ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12; } catch { }

                    using (var client = new HttpClient())
                    {
                        client.Timeout = TimeSpan.FromSeconds(10);
                        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

                        var resp = await client.GetAsync(ReleasesApiUrl).ConfigureAwait(false);
                        if (!resp.IsSuccessStatusCode) return;
                        var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                        if (string.IsNullOrWhiteSpace(body)) return;

                        var release = JsonConvert.DeserializeObject<GitHubRelease>(body);
                        if (release == null || release.Draft || release.Prerelease) return;
                        if (string.IsNullOrWhiteSpace(release.TagName)) return;

                        var latestVersion = release.TagName.TrimStart('v', 'V');
                        if (!IsNewer(latestVersion, CurrentVersion)) return;

                        // Find the .vsix asset (first one ending in .vsix wins)
                        var vsix = release.Assets?.FirstOrDefault(a =>
                            !string.IsNullOrEmpty(a?.Name) &&
                            a.Name.EndsWith(".vsix", StringComparison.OrdinalIgnoreCase));
                        var downloadUrl = vsix?.BrowserDownloadUrl ?? release.HtmlUrl;
                        var notes = TruncateNotes(release.Body);

                        _notifiedThisSession = true;
                        await ShowNotificationAsync(latestVersion, downloadUrl, notes).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Silent: update notifications must NEVER block scans or surface errors.
                }
            });
        }

        private static string TruncateNotes(string body)
        {
            if (string.IsNullOrWhiteSpace(body)) return "";
            // Strip the trailing markdown noise we add to release notes
            var idx = body.IndexOf("🤖 Generated with", StringComparison.Ordinal);
            if (idx > 0) body = body.Substring(0, idx);
            body = body.Trim();
            // Cap at ~600 chars so the message box stays readable
            if (body.Length > 600) body = body.Substring(0, 600).TrimEnd() + "…";
            return body;
        }

        private static bool IsNewer(string serverVersion, string current)
        {
            try
            {
                var a = ParseVersion(serverVersion);
                var b = ParseVersion(current);
                for (int i = 0; i < 4; i++)
                {
                    if (a[i] != b[i]) return a[i] > b[i];
                }
                return false;
            }
            catch { return false; }
        }

        private static int[] ParseVersion(string v)
        {
            var parts = (v ?? "0").Split('.');
            var result = new int[4];
            for (int i = 0; i < 4 && i < parts.Length; i++)
            {
                int.TryParse(parts[i], out result[i]);
            }
            return result;
        }

        private static async Task ShowNotificationAsync(string latestVersion, string downloadUrl, string notes)
        {
            try
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var msg = $"Offensive 360: a new plugin version is available — v{latestVersion} (you have v{CurrentVersion}).";
                if (!string.IsNullOrWhiteSpace(notes))
                {
                    msg += $"\n\n{notes}";
                }
                if (!string.IsNullOrWhiteSpace(downloadUrl))
                {
                    msg += $"\n\nDownload: {downloadUrl}\n\nClick OK to open the download page in your browser.";
                }
                var result = VsShellUtilities.ShowMessageBox(
                    ServiceProvider.GlobalProvider,
                    msg,
                    "Offensive 360 — Plugin Update Available",
                    OLEMSGICON.OLEMSGICON_INFO,
                    string.IsNullOrWhiteSpace(downloadUrl) ? OLEMSGBUTTON.OLEMSGBUTTON_OK : OLEMSGBUTTON.OLEMSGBUTTON_OKCANCEL,
                    OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                if (result == 1 /* IDOK */ && !string.IsNullOrWhiteSpace(downloadUrl))
                {
                    try { Process.Start(new ProcessStartInfo(downloadUrl) { UseShellExecute = true }); } catch { }
                }
            }
            catch { /* notification UI failure must not break scans */ }
        }
    }
}
