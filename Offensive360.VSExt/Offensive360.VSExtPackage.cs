using EnvDTE;
using Microsoft.VisualStudio;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.Runtime.InteropServices;
using System.Threading;                                                                                
using Task = System.Threading.Tasks.Task;

namespace Offensive360.VSExt
{
    [PackageRegistration(UseManagedResourcesOnly = true, AllowsBackgroundLoading = true)]
    [Guid(PackageGuidString)]
    [ProvideAutoLoad(VSConstants.UICONTEXT.ShellInitialized_string, PackageAutoLoadFlags.BackgroundLoad)]
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    [ProvideMenuResource("Menus.ctmenu", 1)]
    [ProvideOptionPage(typeof(SettingDialogPage), "Offensive360", SettingDialogPage.PageName, 901, 902, false, 903)]
    public sealed class Offensive360VSExtPackage : AsyncPackage
    {
        private DTE _dte;

        private ErrorListProvider _errorListProvider;

        private IVsStatusbar _statusBar;

        public const string PackageGuidString = "6d8478e8-93eb-45cd-901f-7f0e9c636772";

        #region Package Members

        protected override async Task InitializeAsync(CancellationToken cancellationToken, IProgress<ServiceProgressData> progress)
        {
            await JoinableTaskFactory.SwitchToMainThreadAsync(cancellationToken);

            _dte = (await GetServiceAsync(typeof(SDTE))) as DTE;
            _statusBar = (IVsStatusbar)await ServiceProvider.GetGlobalServiceAsync(typeof(SVsStatusbar));

            _errorListProvider = new ErrorListProvider(new ServiceProvider((Microsoft.VisualStudio.OLE.Interop.IServiceProvider)_dte));

            await ScanProjectCommand.InitializeAsync(this, _errorListProvider);

            await ClearAllErrorCommand.InitializeAsync(this, _errorListProvider);

            await GetHelpCommand.InitializeAsync(this, _errorListProvider);

            await SuppressCommand.InitializeAsync(this, _errorListProvider);
        }

        #endregion
    }
}
