using Microsoft.VisualStudio.Shell;
using System;
using System.ComponentModel.Design;
using Task = System.Threading.Tasks.Task;

namespace Offensive360.VSExt
{
    internal sealed class ClearAllErrorCommand
    {
        private readonly AsyncPackage package;

        public const int CommandId = 0x0300;

        public static readonly Guid CommandSet = new Guid("762f92d8-926a-4160-8519-badb7cc9a872");

        private static ErrorListProvider _errorListProvider;

        private ClearAllErrorCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new OleMenuCommand(ExecuteAsync, menuCommandID);
            menuItem.BeforeQueryStatus += BeforeQueryStatus;
            commandService.AddCommand(menuItem);
        }

        public static ClearAllErrorCommand Instance
        {
            get;
            private set;
        }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new ClearAllErrorCommand(package, commandService);

            _errorListProvider = errorListProvider;
        }

        private void ExecuteAsync(object sender, EventArgs e)
        {
            _errorListProvider.Tasks.Clear();
        }

        private void BeforeQueryStatus(object sender, EventArgs e)
        {
            var button = (OleMenuCommand)sender;
            button.Enabled = _errorListProvider.Tasks.Count > 0;
        }
    }
}
