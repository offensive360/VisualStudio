using System;
using System.ComponentModel.Design;
using System.Threading;
using EnvDTE;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using OffensiveVS360.Services;
using OffensiveVS360.ToolWindow;
using Task = System.Threading.Tasks.Task;

namespace OffensiveVS360.Commands
{
    internal static class CommandIds
    {
        public const int ScanSolution  = 0x0100;
        public const int ScanProject   = 0x0101;
        public const int ScanFile      = 0x0102;
        public const int ClearFindings = 0x0103;
        public const int ShowFindings  = 0x0104;

        public static readonly Guid CommandSetGuid = new Guid("A1B2C3D4-E5F6-7A8B-9C0D-E1F2A3B4C5D6");
    }

    internal sealed class O360Commands
    {
        private readonly AsyncPackage _package;
        private readonly ScanService _scanService;

        private O360Commands(AsyncPackage package, OleMenuCommandService commandService, ScanService scanService)
        {
            _package = package;
            _scanService = scanService;
            RegisterCommands(commandService);
        }

        public static async Task InitializeAsync(AsyncPackage package, ScanService scanService)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);
            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            if (commandService == null) return;
            new O360Commands(package, commandService, scanService);
        }

        private void RegisterCommands(OleMenuCommandService cs)
        {
            AddCommand(cs, CommandIds.ScanSolution,  OnScanSolution);
            AddCommand(cs, CommandIds.ScanProject,   OnScanProject);
            AddCommand(cs, CommandIds.ScanFile,      OnScanFile);
            AddCommand(cs, CommandIds.ClearFindings, OnClearFindings);
            AddCommand(cs, CommandIds.ShowFindings,  OnShowFindings);
        }

        private static void AddCommand(OleMenuCommandService cs, int id, EventHandler handler)
        {
            var cmdId = new CommandID(CommandIds.CommandSetGuid, id);
            cs.AddCommand(new MenuCommand(handler, cmdId));
        }

        private void OnScanSolution(object sender, EventArgs e)
        {
            _ = _package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var dte = await _package.GetServiceAsync(typeof(DTE)) as DTE;
                if (dte?.Solution == null || string.IsNullOrEmpty(dte.Solution.FullName))
                {
                    ShowError("No solution is currently open.");
                    return;
                }

                var solutionDir = System.IO.Path.GetDirectoryName(dte.Solution.FullName);
                await RunScanAsync(() => _scanService.ScanFolderAsync(solutionDir, CancellationToken.None));
            });
        }

        private void OnScanProject(object sender, EventArgs e)
        {
            _ = _package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var dte = await _package.GetServiceAsync(typeof(DTE)) as DTE;

                Project activeProject = null;
                if (dte?.ActiveSolutionProjects is Array projects && projects.Length > 0)
                    activeProject = projects.GetValue(0) as Project;

                if (activeProject == null)
                {
                    ShowError("No project is selected. Select a project in Solution Explorer first.");
                    return;
                }

                var projectDir = System.IO.Path.GetDirectoryName(activeProject.FullName);
                await RunScanAsync(() => _scanService.ScanFolderAsync(projectDir, CancellationToken.None));
            });
        }

        private void OnScanFile(object sender, EventArgs e)
        {
            _ = _package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var dte = await _package.GetServiceAsync(typeof(DTE)) as DTE;
                var activeDoc = dte?.ActiveDocument;
                if (activeDoc == null)
                {
                    ShowError("No file is currently open.");
                    return;
                }

                await RunScanAsync(() => _scanService.ScanFileAsync(activeDoc.FullName, CancellationToken.None));
            });
        }

        private void OnClearFindings(object sender, EventArgs e)
        {
            _ = _package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var window = await GetFindingsWindowAsync();
                window?.ClearFindings();
            });
        }

        private void OnShowFindings(object sender, EventArgs e)
        {
            _ = _package.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var toolWindow = await _package.ShowToolWindowAsync(
                    typeof(FindingsWindow), 0, create: true, _package.DisposalToken);
            });
        }

        private async Task RunScanAsync(Func<System.Threading.Tasks.Task<Models.ScanResponse>> scanFunc)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            var window = await GetFindingsWindowAsync(create: true);
            if (window == null) return;

            await window.RunScanAsync(scanFunc);
        }

        private async System.Threading.Tasks.Task<FindingsWindowControl> GetFindingsWindowAsync(bool create = false)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            var toolWindow = await _package.ShowToolWindowAsync(
                typeof(FindingsWindow), 0, create: create, _package.DisposalToken) as FindingsWindow;
            return toolWindow?.Control;
        }

        private static void ShowError(string message)
        {
            _ = ThreadHelper.JoinableTaskFactory.RunAsync(async () =>
            {
                await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
                var uiShell = Package.GetGlobalService(typeof(IVsUIShell)) as IVsUIShell;
                if (uiShell != null)
                {
                    var clsid = Guid.Empty;
                    uiShell.ShowMessageBox(0, ref clsid, "O360 SAST", message,
                        string.Empty, 0,
                        OLEMSGBUTTON.OLEMSGBUTTON_OK,
                        OLEMSGDEFBUTTON.OLEMSGDEFBUTTON_FIRST,
                        OLEMSGICON.OLEMSGICON_WARNING, 0, out _);
                }
            });
        }
    }
}
