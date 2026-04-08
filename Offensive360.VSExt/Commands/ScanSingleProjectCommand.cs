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
    /// Scans only the selected project (not the entire solution).
    /// Available from Build > Offensive 360 > Scan Project and Solution Explorer context menu.
    /// </summary>
    internal sealed class ScanSingleProjectCommand
    {
        public const int CommandId = 0x0101;
        public static readonly Guid CommandSet = new Guid("37c394e5-ec3b-4e7f-9d98-25a7662c2bcd");

        private readonly AsyncPackage package;
        private static ErrorListProvider _errorListProvider;
        private static DTE2 _dte;
        private static IVsStatusbar _statusBar;

        private IAsyncServiceProvider ServiceProvider => package;

        private ScanSingleProjectCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand((sender, e) =>
            {
                ThreadHelper.JoinableTaskFactory.RunAsync(async () => await ExecuteAsync(sender, e));
            }, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        public static ScanSingleProjectCommand Instance { get; private set; }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new ScanSingleProjectCommand(package, commandService);
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
                string projectPath = null;

                // Get selected project from Solution Explorer
                try
                {
                    var selectedItems = _dte?.DTE?.SelectedItems;
                    if (selectedItems != null && selectedItems.Count > 0)
                    {
                        var item = selectedItems.Item(1);
                        if (item.Project != null)
                        {
                            var projFile = item.Project.FullName;
                            if (!string.IsNullOrEmpty(projFile) && File.Exists(projFile))
                                projectPath = Path.GetDirectoryName(projFile);
                        }
                    }
                }
                catch { }

                // Fallback: use the startup project
                if (string.IsNullOrEmpty(projectPath))
                {
                    try
                    {
                        var startupProjects = (Array)_dte?.DTE?.Solution?.SolutionBuild?.StartupProjects;
                        if (startupProjects != null && startupProjects.Length > 0)
                        {
                            var projName = startupProjects.GetValue(0) as string;
                            foreach (EnvDTE.Project proj in _dte.DTE.Solution.Projects)
                            {
                                if (proj.UniqueName == projName && !string.IsNullOrEmpty(proj.FullName))
                                {
                                    projectPath = Path.GetDirectoryName(proj.FullName);
                                    break;
                                }
                            }
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrEmpty(projectPath) || !Directory.Exists(projectPath))
                {
                    System.Windows.MessageBox.Show(
                        "No project selected.\n\nRight-click a project in Solution Explorer and choose 'O360: Scan Project', or select a project first.",
                        "Offensive360 SAST",
                        System.Windows.MessageBoxButton.OK,
                        System.Windows.MessageBoxImage.Information);
                    return;
                }

                try { Offensive360.VSExt.Helpers.O360Logger.Log($"Scan Project: {projectPath}"); } catch { }
                await _errorListProvider.ScanProjectAndShowVulnerabilitiesAsync(_statusBar, projectPath);
            }
            catch (Exception ex)
            {
                try { Offensive360.VSExt.Helpers.O360Logger.Log($"\n[{DateTime.Now}] ERROR: {ex.GetType().Name}: {ex.Message}"); } catch { }
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
