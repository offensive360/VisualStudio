using System;
using System.IO;

namespace Offensive360.VSExt.Helpers
{
    /// <summary>
    /// Central diagnostic logger for the Offensive 360 VS extension.
    ///
    /// Writes to a per-user file under %LOCALAPPDATA%\Offensive360\o360_scan_log.txt.
    /// This is the standard Windows per-user data location — works on ANY user
    /// account on ANY machine (not only the developer's Administrator desktop).
    ///
    /// Every call is best-effort: failures (disk full, permission denied, etc.)
    /// are swallowed so diagnostic logging can NEVER break a scan.
    /// </summary>
    internal static class O360Logger
    {
        private static readonly object _sync = new object();
        private static string _cachedPath;

        /// <summary>
        /// Returns the absolute path to the log file. Creates the parent dir on first
        /// access. Safe to call from any thread.
        /// </summary>
        public static string GetLogPath()
        {
            if (_cachedPath != null) return _cachedPath;
            try
            {
                var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                if (string.IsNullOrEmpty(baseDir))
                {
                    baseDir = Path.GetTempPath();
                }
                var dir = Path.Combine(baseDir, "Offensive360");
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                _cachedPath = Path.Combine(dir, "o360_scan_log.txt");
            }
            catch
            {
                // Fall back to temp if we can't create the dir
                try { _cachedPath = Path.Combine(Path.GetTempPath(), "o360_scan_log.txt"); } catch { }
            }
            return _cachedPath;
        }

        /// <summary>Append a timestamped line to the log. Never throws.</summary>
        public static void Log(string message)
        {
            try
            {
                var path = GetLogPath();
                if (string.IsNullOrEmpty(path)) return;
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
                lock (_sync)
                {
                    File.AppendAllText(path, line);
                }
            }
            catch { /* best-effort */ }
        }

        /// <summary>Truncate the log file (called at the start of each scan).</summary>
        public static void Reset()
        {
            try
            {
                var path = GetLogPath();
                if (string.IsNullOrEmpty(path)) return;
                lock (_sync)
                {
                    File.WriteAllText(path, "");
                }
            }
            catch { /* best-effort */ }
        }
    }
}
