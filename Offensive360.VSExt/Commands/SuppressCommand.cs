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
    internal sealed class SuppressCommand
    {
        private readonly AsyncPackage package;

        public const int CommandId = 0x0400;

        public static readonly Guid CommandSet = new Guid("762f92d8-926a-4160-8519-badb7cc9a872");

        private static ErrorListProvider _errorListProvider;

        private SuppressCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new OleMenuCommand(async (sender, e) => ExecuteAsync(sender, e), menuCommandID);
            menuItem.BeforeQueryStatus += BeforeQueryStatus;
            commandService.AddCommand(menuItem);
        }

        public static SuppressCommand Instance
        {
            get;
            private set;
        }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new SuppressCommand(package, commandService);

            _errorListProvider = errorListProvider;
        }

        private async Task ExecuteAsync(object sender, EventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

            var dte = await package.GetServiceAsync(typeof(SDTE)) as DTE2;
            var errorList = dte.ToolWindows.ErrorList as IErrorList;
            var taskItem = (TaskListItem)errorList.TableControl.SelectedEntry.Identity;
            var vulnerabilityTitle = taskItem.Text.Substring(taskItem.Text.IndexOf("["), taskItem.Text.IndexOf("]")).Trim('[').Trim(']');
            var vulnerabilityConfig = SastHelper.VulnerabilityIgnoreConfig(taskItem.Document?.ToLower(), taskItem.Line + 1, taskItem.Column, vulnerabilityTitle);
            await AppendToIgnoreFileAsync(vulnerabilityConfig, dte.DTE.Solution.FullName);

            _errorListProvider.Tasks.Remove(taskItem);
        }

        private void BeforeQueryStatus(object sender, EventArgs e)
        {
            var button = (OleMenuCommand)sender;
            button.Enabled = _errorListProvider.Tasks.Count > 0;
        }

        private async Task AppendToIgnoreFileAsync(string strMessage, string solutionFilePath)
        {
            var stream = new FileStream(SastHelper.IgnoreFilePath(solutionFilePath), FileMode.Append, FileAccess.Write);
            var streamWriter = new StreamWriter((Stream)stream);
            await streamWriter.WriteLineAsync(strMessage);
            streamWriter.Close();
            stream.Close();
        }
    }
}
