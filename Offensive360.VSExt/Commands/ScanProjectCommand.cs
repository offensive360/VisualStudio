using EnvDTE;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Offensive360.VSExt.Helpers;
using System;
using System.ComponentModel.Design;
using Task = System.Threading.Tasks.Task;

namespace Offensive360.VSExt
{
    internal sealed class ScanProjectCommand
    {
        public const int CommandId = 0x0100;

        public static readonly Guid CommandSet = new Guid("37c394e5-ec3b-4e7f-9d98-25a7662c2bcd");

        private readonly AsyncPackage package;

        private static ErrorListProvider _errorListProvider;

        private static DTE _dte;

        private static IVsStatusbar _statusBar;

        private ScanProjectCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand((sender, e) =>
            {
                ThreadHelper.JoinableTaskFactory.RunAsync(async () => await ExecuteAsync(sender, e));
            }, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static ScanProjectCommand Instance
        {
            get;
            private set;
        }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new ScanProjectCommand(package, commandService);

            _errorListProvider = errorListProvider;

            _dte = (DTE)(await ServiceProvider.GetGlobalServiceAsync(typeof(SDTE)));

            _statusBar = (IVsStatusbar)await ServiceProvider.GetGlobalServiceAsync(typeof(SVsStatusbar));
        }

        private async Task ExecuteAsync(object sender, EventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

            System.Diagnostics.Debug.WriteLine("Offensive360: Scan command triggered");

            _errorListProvider.Tasks.Clear();

            var menu = (MenuCommand)sender;

            try
            {
                menu.Enabled = false;

                // Get the project path — supports both Solution mode and Folder View mode
                string solutionPath = "";

                // Method 1: Solution.FullName (works when .sln is open)
                try { solutionPath = _dte?.DTE?.Solution?.FullName ?? ""; } catch { }

                // Method 2: IVsSolution (works in Folder View and Solution mode)
                if (string.IsNullOrEmpty(solutionPath) || !System.IO.File.Exists(solutionPath))
                {
                    try
                    {
                        var vsSolution = (IVsSolution)await ServiceProvider.GetGlobalServiceAsync(typeof(SVsSolution));
                        if (vsSolution != null)
                        {
                            vsSolution.GetSolutionInfo(out string solutionDir, out string solutionFile, out string userOptsFile);
                            System.Diagnostics.Debug.WriteLine($"Offensive360: GetSolutionInfo dir='{solutionDir}' file='{solutionFile}'");
                            if (!string.IsNullOrEmpty(solutionFile))
                                solutionPath = solutionFile;
                            else if (!string.IsNullOrEmpty(solutionDir))
                                solutionPath = solutionDir.TrimEnd('\\', '/');
                        }
                    }
                    catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"Offensive360: GetSolutionInfo failed: {ex.Message}"); }
                }

                // Method 3: IVsSolution property for open folder
                if (string.IsNullOrEmpty(solutionPath))
                {
                    try
                    {
                        var vsSolution = (IVsSolution)await ServiceProvider.GetGlobalServiceAsync(typeof(SVsSolution));
                        if (vsSolution != null)
                        {
                            vsSolution.GetProperty((int)__VSPROPID.VSPROPID_SolutionDirectory, out object dirObj);
                            var dir = dirObj as string;
                            if (!string.IsNullOrEmpty(dir))
                                solutionPath = dir;
                        }
                    }
                    catch { }
                }

                // Method 4: Active document's directory as last resort
                if (string.IsNullOrEmpty(solutionPath))
                {
                    try
                    {
                        var activeDoc = _dte?.DTE?.ActiveDocument?.FullName;
                        if (!string.IsNullOrEmpty(activeDoc))
                            solutionPath = System.IO.Path.GetDirectoryName(activeDoc);
                    }
                    catch { }
                }

                // Method 5: Title bar shows the folder name — parse it as a last resort
                if (string.IsNullOrEmpty(solutionPath))
                {
                    try
                    {
                        var caption = _dte?.DTE?.MainWindow?.Caption ?? "";
                        // VS title in Folder View: "FolderName - Microsoft Visual Studio"
                        if (caption.Contains(" - "))
                        {
                            var folderName = caption.Split(new[] { " - " }, StringSplitOptions.None)[0].Trim();
                            // Try common locations
                            var desktopPath = System.IO.Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.Desktop), folderName);
                            if (System.IO.Directory.Exists(desktopPath))
                                solutionPath = desktopPath;
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrEmpty(solutionPath))
                {
                    System.Windows.MessageBox.Show(
                        "No solution or folder is open.\n\nPlease open a solution (.sln) or folder to scan.",
                        "Offensive360 SAST",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                    return;
                }

                System.Diagnostics.Debug.WriteLine($"Offensive360: Scanning path: {solutionPath}");
                try { Offensive360.VSExt.Helpers.O360Logger.Log($"Scan starting. Path: {solutionPath}"); } catch {}
                await _errorListProvider.ScanProjectAndShowVulnerabilitiesAsync(_statusBar, solutionPath);
            }
            catch (Exception ex)
            {
                // Flatten to the innermost exception so the real cause isn't hidden by outer wrappers
                var root = ex;
                while (root.InnerException != null) root = root.InnerException;
                var detail = $"{root.GetType().Name}: {root.Message}";
                System.Diagnostics.Debug.WriteLine($"Offensive360: Scan error — {detail}");
                try { Offensive360.VSExt.Helpers.O360Logger.Log($"\n[{DateTime.Now}] ERROR: {ex.GetType().Name}: {ex.Message}\nInner: {detail}\n{ex.StackTrace}"); } catch {}
                _errorListProvider.LogException($"Offensive360 Scan Error: {detail}");
                System.Windows.MessageBox.Show(
                    $"Scan failed: {detail}\n\n" +
                    "Troubleshooting:\n" +
                    "• Check server URL and access token in Tools > Options > Offensive360\n" +
                    "• Verify the server is reachable from this machine\n" +
                    $"• See full log at {Offensive360.VSExt.Helpers.O360Logger.GetLogPath()}",
                    "Offensive360 SAST - Scan Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
            }
            finally
            {
                menu.Enabled = true;
            }

            _errorListProvider.Show();
            await _statusBar.HideProgressAsync();
        }
    }
}
