using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Newtonsoft.Json;
using Offensive360.VSExt.Properties;
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Offensive360.VSExt.Helpers
{
    /// <summary>
    /// Option D — server-driven plugin update notifications.
    /// On scan trigger, asks the IDECO server "is there a newer plugin?". If yes,
    /// shows a one-time-per-day balloon with a link to the download URL. Endpoint
    /// is optional on the server side: any failure (404, network, parse error) is
    /// silently ignored, so this is fully backward-compatible with older servers.
    /// </summary>
    internal static class PluginUpdateChecker
    {
        private const string PluginId = "vs";
        private const string CurrentVersion = "1.12.3";
        private const string UpdateEndpoint = "/app/api/PluginUpdate";
        private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(24);
        private static DateTime _lastCheck = DateTime.MinValue;
        private static bool _notifiedThisSession = false;

        private class UpdateResponse
        {
            [JsonProperty("latestVersion")] public string LatestVersion { get; set; }
            [JsonProperty("downloadUrl")] public string DownloadUrl { get; set; }
            [JsonProperty("releaseNotes")] public string ReleaseNotes { get; set; }
            [JsonProperty("mandatory")] public bool Mandatory { get; set; }
        }

        /// <summary>
        /// Fire-and-forget. Never throws. Never blocks the scan.
        /// </summary>
        public static void CheckAsync()
        {
            // Throttle: at most once per 24h, and at most once per session.
            if (_notifiedThisSession) return;
            if (DateTime.UtcNow - _lastCheck < CacheTtl) return;
            _lastCheck = DateTime.UtcNow;

            _ = Task.Run(async () =>
            {
                try
                {
                    var baseUrl = Settings.Default.BaseUrl?.TrimEnd('/');
                    var token = Settings.Default.AccessToken;
                    if (string.IsNullOrWhiteSpace(baseUrl) || string.IsNullOrWhiteSpace(token)) return;

                    var url = $"{baseUrl}{UpdateEndpoint}?plugin={PluginId}&current={CurrentVersion}";
                    var handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (m, c, ch, e) => true
                    };
                    using (var client = new HttpClient(handler, true))
                    {
                        client.Timeout = TimeSpan.FromSeconds(10);
                        var req = new HttpRequestMessage { RequestUri = new Uri(url), Method = HttpMethod.Get };
                        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                        var resp = await client.SendAsync(req).ConfigureAwait(false);
                        if (!resp.IsSuccessStatusCode) return;
                        var body = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                        if (string.IsNullOrWhiteSpace(body)) return;
                        var info = JsonConvert.DeserializeObject<UpdateResponse>(body);
                        if (info == null || string.IsNullOrWhiteSpace(info.LatestVersion)) return;
                        if (!IsNewer(info.LatestVersion, CurrentVersion)) return;
                        _notifiedThisSession = true;
                        await ShowNotificationAsync(info).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Silent: update notifications must NEVER block scans or surface errors.
                }
            });
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

        private static async Task ShowNotificationAsync(UpdateResponse info)
        {
            try
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var prefix = info.Mandatory ? "REQUIRED update available" : "Offensive 360: update available";
                var msg = $"{prefix} — v{info.LatestVersion} (you have v{CurrentVersion}).";
                if (!string.IsNullOrWhiteSpace(info.ReleaseNotes))
                {
                    msg += $"\n{info.ReleaseNotes}";
                }
                if (!string.IsNullOrWhiteSpace(info.DownloadUrl))
                {
                    msg += $"\n\nDownload: {info.DownloadUrl}\n\nClick OK to open the download page.";
                }
                var result = VsShellUtilities.ShowMessageBox(
                    ServiceProvider.GlobalProvider,
                    msg,
                    "Offensive 360 — Plugin Update",
                    info.Mandatory ? OLEMSGICON.OLEMSGICON_WARNING : OLEMSGICON.OLEMSGICON_INFO,
                    string.IsNullOrWhiteSpace(info.DownloadUrl) ? OLEMSGBUTTON.OLEMSGBUTTON_OK : OLEMSGBUTTON.OLEMSGBUTTON_OKCANCEL,
                    OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST);
                if (result == 1 /* IDOK */ && !string.IsNullOrWhiteSpace(info.DownloadUrl))
                {
                    try { Process.Start(new ProcessStartInfo(info.DownloadUrl) { UseShellExecute = true }); } catch { }
                }
            }
            catch { /* notification UI failure must not break scans */ }
        }
    }
}
