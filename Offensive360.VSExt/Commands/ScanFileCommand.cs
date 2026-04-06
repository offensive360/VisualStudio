using EnvDTE;
using EnvDTE80;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Offensive360.VSExt.Helpers;
using System;
using System.ComponentModel.Design;
using System.IO;
using Task = System.Threading.Tasks.Task;

namespace Offensive360.VSExt
{
    /// <summary>
    /// Scans only the active/selected file.
    /// Available from Build > Offensive 360 > Scan File, editor context menu, and Solution Explorer file context.
    /// </summary>
    internal sealed class ScanFileCommand
    {
        public const int CommandId = 0x0102;
        public static readonly Guid CommandSet = new Guid("37c394e5-ec3b-4e7f-9d98-25a7662c2bcd");

        private readonly AsyncPackage package;
        private static ErrorListProvider _errorListProvider;
        private static DTE2 _dte;
        private static IVsStatusbar _statusBar;

        private IAsyncServiceProvider ServiceProvider => package;

        private ScanFileCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand((sender, e) =>
            {
                ThreadHelper.JoinableTaskFactory.RunAsync(async () => await ExecuteAsync(sender, e));
            }, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static ScanFileCommand Instance { get; private set; }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new ScanFileCommand(package, commandService);
            _errorListProvider = errorListProvider;
            _dte = (DTE2)(await ((IAsyncServiceProvider)package).GetServiceAsync(typeof(SDTE)));
            _statusBar = (IVsStatusbar)await ((IAsyncServiceProvider)package).GetServiceAsync(typeof(SVsStatusbar));
        }

        private async Task ExecuteAsync(object sender, EventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            _errorListProvider.Tasks.Clear();

            try
            {
                string filePath = null;

                // Get active document
                try { filePath = _dte?.DTE?.ActiveDocument?.FullName; } catch { }

                // Fallback: selected item in Solution Explorer
                if (string.IsNullOrEmpty(filePath))
                {
                    try
                    {
                        var selectedItems = _dte?.DTE?.SelectedItems;
                        if (selectedItems != null && selectedItems.Count > 0)
                        {
                            var item = selectedItems.Item(1);
                            if (item.ProjectItem != null)
                                filePath = item.ProjectItem.FileNames[1];
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                {
                    System.Windows.MessageBox.Show(
                        "No file is open or selected.\n\nOpen a source file in the editor or select one in Solution Explorer.",
                        "Offensive360 SAST",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                    return;
                }

                // Scan the project containing this file (single file scans don't work
                // reliably because the server needs project context for accurate analysis)
                var projectDir = Path.GetDirectoryName(filePath);

                // Walk up to find the project root (look for .csproj, .vbproj, or use parent of file)
                try
                {
                    var activeProject = _dte?.DTE?.ActiveDocument?.ProjectItem?.ContainingProject;
                    if (activeProject != null && !string.IsNullOrEmpty(activeProject.FullName))
                        projectDir = Path.GetDirectoryName(activeProject.FullName);
                }
                catch { }

                try { File.WriteAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"[{DateTime.Now}] Scan File (project): {projectDir} (file: {filePath})\n"); } catch { }
                await _errorListProvider.ScanProjectAndShowVulnerabilitiesAsync(_statusBar, projectDir);
            }
            catch (Exception ex)
            {
                try { File.AppendAllText(@"C:\Users\Administrator\Desktop\o360_scan_log.txt", $"\n[{DateTime.Now}] ERROR: {ex.GetType().Name}: {ex.Message}\n"); } catch { }
                _errorListProvider.LogException($"Offensive360 Scan Error: {ex.Message}");
                System.Windows.MessageBox.Show(
                    $"Scan failed: {ex.Message}\n\nCheck Tools > Options > Offensive360.",
                    "Offensive360 SAST - Scan Error",
                    System.Windows.MessageBoxButton.OK,
                    System.Windows.MessageBoxImage.Warning);
            }

            _errorListProvider.Show();
            await _statusBar.HideProgressAsync();
        }
    }
}
