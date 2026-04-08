using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Offensive360.VSExt.Helpers
{
    internal static class ScanCache
    {
        private const string CacheDir = ".SASTO360";
        private const string CacheFile = "lastScanResults.json";
        // Bump this whenever the cache schema changes. On load, if the version marker is
        // missing or different, the existing cache is wiped (clean install upgrade).
        private const string CacheSchemaVersion = "v2-2026-04-07";
        private const string SchemaMarkerFile = "schema.version";

        public class CachedScan
        {
            // Lowercase JSON keys to share cache format with the Android Studio plugin
            // (avoids cross-plugin double-scanning when both IDEs work on the same project).
            [JsonProperty("timestamp")]
            public long Timestamp { get; set; }

            [JsonProperty("fileHashes")]
            public Dictionary<string, string> FileHashes { get; set; } = new Dictionary<string, string>();

            // AS plugin writes "findings"; we accept both keys on read for backward compat.
            [JsonProperty("findings")]
            public List<SAST.VSExt.Models.VulnerabilityResponse> Vulnerabilities { get; set; } = new List<SAST.VSExt.Models.VulnerabilityResponse>();
        }

        /// <summary>
        /// Result of comparing current files against cached hashes.
        /// </summary>
        public class IncrementalDiff
        {
            public bool HasChanges { get; set; }
            public List<string> ChangedRelativePaths { get; set; } = new List<string>();
            public List<string> DeletedRelativePaths { get; set; } = new List<string>();
            public Dictionary<string, string> CurrentHashes { get; set; } = new Dictionary<string, string>();
        }

        public static readonly HashSet<string> ExcludeExts = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".zip", ".dll", ".pdf", ".exe", ".DS_Store", ".bak", ".tmp",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wmv", ".flv",
            ".bmp", ".gif", ".jpg", ".png", ".psd", ".tif", ".ico", ".svg",
            ".jar", ".rar", ".7z", ".gz", ".tar", ".war", ".ear",
            ".pdb", ".class", ".iml", ".nupkg", ".vsix", ".aar",
            ".woff", ".woff2", ".ttf", ".otf", ".eot",
            ".db", ".sqlite", ".mdb", ".lock",
            ".sln", ".csproj", ".vbproj", ".vcxproj", ".fsproj", ".proj",
            ".suo", ".user", ".cache", ".snk", ".pfx", ".p12"
        };

        public static readonly HashSet<string> ExcludeFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            ".vs", "cvs", ".svn", ".hg", ".git", ".bzr", "bin", "obj",
            "backup", "backup1", "backup2", "backup3", "backups",
            ".idea", ".vscode", "node_modules", "packages",
            "dist", "build", "out", "target", ".gradle", "__pycache__",
            ".SASTO360", "TestResults", "test-results", ".nuget"
        };

        public static string GetCachePath(string solutionFolder)
        {
            var dir = Path.Combine(solutionFolder, CacheDir);
            if (!Directory.Exists(dir))
            {
                var di = Directory.CreateDirectory(dir);
                di.Attributes = FileAttributes.Directory | FileAttributes.Hidden;
            }
            return Path.Combine(dir, CacheFile);
        }

        public static string ComputeMD5(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = md5.ComputeHash(stream);
                    var sb = new StringBuilder();
                    foreach (var b in hash) sb.Append(b.ToString("x2"));
                    return sb.ToString();
                }
            }
            catch { return ""; }
        }

        /// <summary>
        /// Computes file hashes on a background thread to avoid blocking the UI.
        /// </summary>
        public static Task<Dictionary<string, string>> ComputeFileHashesAsync(string folderPath)
        {
            return Task.Run(() => ComputeFileHashes(folderPath));
        }

        public static Dictionary<string, string> ComputeFileHashes(string folderPath)
        {
            var hashes = new Dictionary<string, string>();

            foreach (var file in Directory.EnumerateFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                var ext = Path.GetExtension(file);
                if (ExcludeExts.Contains(ext)) continue;
                var relativePath = file.Substring(folderPath.Length).TrimStart('\\', '/');
                var parts = relativePath.Split(new[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
                if (Array.Exists(parts, p => ExcludeFolders.Contains(p))) continue;

                // Skip files larger than 50 MB for hashing
                try
                {
                    var fi = new FileInfo(file);
                    if (fi.Length > 50L * 1024 * 1024) continue;
                }
                catch { continue; }

                hashes[relativePath] = ComputeMD5(file);
            }
            return hashes;
        }

        /// <summary>
        /// Compares current file state against cached hashes and returns only changed/new/deleted files.
        /// Runs on a background thread.
        /// </summary>
        public static Task<IncrementalDiff> ComputeIncrementalDiffAsync(string folderPath, CachedScan cached)
        {
            return Task.Run(() => ComputeIncrementalDiff(folderPath, cached));
        }

        public static IncrementalDiff ComputeIncrementalDiff(string folderPath, CachedScan cached)
        {
            var currentHashes = ComputeFileHashes(folderPath);
            var diff = new IncrementalDiff { CurrentHashes = currentHashes };

            if (cached == null || cached.FileHashes == null || cached.FileHashes.Count == 0)
            {
                // No cache = everything is new
                diff.HasChanges = true;
                diff.ChangedRelativePaths = currentHashes.Keys.ToList();
                return diff;
            }

            // Find changed and new files
            foreach (var kvp in currentHashes)
            {
                if (!cached.FileHashes.TryGetValue(kvp.Key, out var oldHash) || oldHash != kvp.Value)
                {
                    diff.ChangedRelativePaths.Add(kvp.Key);
                }
            }

            // Find deleted files
            foreach (var kvp in cached.FileHashes)
            {
                if (!currentHashes.ContainsKey(kvp.Key))
                {
                    diff.DeletedRelativePaths.Add(kvp.Key);
                }
            }

            diff.HasChanges = diff.ChangedRelativePaths.Count > 0 || diff.DeletedRelativePaths.Count > 0;
            return diff;
        }

        /// <summary>
        /// Merges new scan results for changed files with cached results for unchanged files.
        /// Removes vulnerabilities from deleted/changed files and adds new ones.
        /// </summary>
        public static List<SAST.VSExt.Models.VulnerabilityResponse> MergeResults(
            CachedScan cached,
            List<SAST.VSExt.Models.VulnerabilityResponse> newVulnerabilities,
            List<string> changedFiles,
            List<string> deletedFiles)
        {
            var merged = new List<SAST.VSExt.Models.VulnerabilityResponse>();

            // Normalize changed/deleted file paths for comparison
            var affectedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in changedFiles) affectedFiles.Add(NormalizePath(f));
            foreach (var f in deletedFiles) affectedFiles.Add(NormalizePath(f));

            // Keep cached vulnerabilities for files that did NOT change
            if (cached?.Vulnerabilities != null)
            {
                foreach (var v in cached.Vulnerabilities)
                {
                    var vPath = NormalizePath(v.FilePath ?? "");
                    if (!affectedFiles.Contains(vPath))
                    {
                        merged.Add(v);
                    }
                }
            }

            // Add new vulnerabilities from the incremental scan
            if (newVulnerabilities != null)
            {
                merged.AddRange(newVulnerabilities);
            }

            return merged;
        }

        private static string NormalizePath(string p)
        {
            return p.Replace("\\", "/").TrimStart('/').ToLowerInvariant();
        }

        public static void Save(string solutionFolder, List<SAST.VSExt.Models.VulnerabilityResponse> vulnerabilities, Dictionary<string, string> fileHashes)
        {
            try
            {
                var cached = new CachedScan
                {
                    Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    FileHashes = fileHashes,
                    Vulnerabilities = vulnerabilities
                };
                var json = JsonConvert.SerializeObject(cached, Formatting.Indented);
                File.WriteAllText(GetCachePath(solutionFolder), json);
            }
            catch { /* best-effort caching */ }
        }

        /// <summary>
        /// Wipes any cache from a prior plugin version on first load after upgrade.
        /// Idempotent: writes a schema-version marker so this only runs once per upgrade.
        /// </summary>
        private static void EnsureFreshSchema(string solutionFolder)
        {
            try
            {
                var dir = Path.Combine(solutionFolder, CacheDir);
                if (!Directory.Exists(dir)) return;
                var markerPath = Path.Combine(dir, SchemaMarkerFile);
                string existing = File.Exists(markerPath) ? File.ReadAllText(markerPath).Trim() : "";
                if (existing == CacheSchemaVersion) return;
                // Schema changed (or first run after upgrade): delete stale cache file
                var cachePath = Path.Combine(dir, CacheFile);
                if (File.Exists(cachePath))
                {
                    try { File.Delete(cachePath); } catch { }
                }
                File.WriteAllText(markerPath, CacheSchemaVersion);
            }
            catch { /* best-effort cleanup */ }
        }

        public static CachedScan Load(string solutionFolder)
        {
            try
            {
                EnsureFreshSchema(solutionFolder);
                var path = GetCachePath(solutionFolder);
                if (!File.Exists(path)) return null;
                var json = File.ReadAllText(path);
                return JsonConvert.DeserializeObject<CachedScan>(json);
            }
            catch { return null; }
        }

        public static bool HasFilesChanged(string solutionFolder, CachedScan cached)
        {
            if (cached == null || cached.FileHashes == null || cached.FileHashes.Count == 0) return true;
            var currentHashes = ComputeFileHashes(solutionFolder);
            if (currentHashes.Count != cached.FileHashes.Count) return true;
            foreach (var kvp in currentHashes)
            {
                if (!cached.FileHashes.TryGetValue(kvp.Key, out var oldHash) || oldHash != kvp.Value) return true;
            }
            return false;
        }
    }
}
