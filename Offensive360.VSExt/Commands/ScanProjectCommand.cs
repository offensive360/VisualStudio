using EnvDTE;
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
            var menuItem = new MenuCommand(async(sender, e) => ExecuteAsync(sender, e) , menuCommandID);
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

            _errorListProvider.Tasks.Clear();

            var menu = (MenuCommand)sender;

            try
            {
                menu.Enabled = false;
                await _errorListProvider.ScanProjectAndShowVulnerabilitiesAsync(_statusBar, _dte.DTE.Solution.FullName);
            }
            catch (Exception ex)
            {
                _errorListProvider.LogException(ex.Message);
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
