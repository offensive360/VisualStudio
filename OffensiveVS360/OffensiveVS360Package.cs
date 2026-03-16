using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using OffensiveVS360.Commands;
using OffensiveVS360.Options;
using OffensiveVS360.Services;
using OffensiveVS360.ToolWindow;
using Task = System.Threading.Tasks.Task;

namespace OffensiveVS360
{
    [PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
    [InstalledProductRegistration("O360 SAST", "Enterprise static application security testing", "3.0")]
    [ProvideMenuResource("Menus.ctmenu", 1)]
    [ProvideToolWindow(typeof(FindingsWindow),
        Style = VsDockStyle.Tabbed,
        Window = ToolWindowGuids.SolutionExplorer,
        Orientation = ToolWindowOrientation.Right)]
    [ProvideOptionPage(typeof(OptionsPage), "O360 SAST", "Settings", 0, 0, true)]
    [Guid("F5A2D3B1-C8E9-4F7A-B2D3-E5F6A7B8C9D0")]
    public sealed class OffensiveVS360Package : AsyncPackage
    {
        private ScanService _scanService;

        protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
        {
            await base.InitializeAsync(cancellationToken, progress);
            await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

            // Initialize scan service
            _scanService = new ScanService();

            // Wire up options page instance
            var optionsPage = (OptionsPage)GetDialogPage(typeof(OptionsPage));
            OptionsPage.SetInstance(optionsPage);

            // Register commands
            await O360Commands.InitializeAsync(this, _scanService);

            // Wire scan service progress to findings window (lazy — window may not be open yet)
            _scanService.ProgressChanged += OnScanProgress;
        }

        private void OnScanProgress(object sender, ScanProgressEventArgs e)
        {
            // Update VS status bar
            _ = JoinableTaskFactory.RunAsync(async () =>
            {
                await JoinableTaskFactory.SwitchToMainThreadAsync();
                var statusBar = await GetServiceAsync(typeof(IVsStatusbar)) as IVsStatusbar;
                statusBar?.SetText($"O360 SAST: {e.Message}");
            });
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _scanService?.Dispose();
            base.Dispose(disposing);
        }
    }
}
