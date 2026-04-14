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
            var vulnerabilityTitle = "";
            var openBracket = taskItem.Text.IndexOf('[');
            var closeBracket = taskItem.Text.IndexOf(']');
            if (openBracket >= 0 && closeBracket > openBracket)
            {
                vulnerabilityTitle = taskItem.Text.Substring(openBracket + 1, closeBracket - openBracket - 1);
            }

            var result = System.Windows.MessageBox.Show(
                $"Suppress this vulnerability?\n\nFile: {taskItem.Document}\nLine: {taskItem.Line + 1}\nType: {vulnerabilityTitle}\n\nIt will be ignored in future scans.\nEdit .SASTO360\\sastIgnore to undo.",
                "Offensive360 — Confirm Suppression",
                System.Windows.MessageBoxButton.YesNo,
                System.Windows.MessageBoxImage.Question);
            if (result != System.Windows.MessageBoxResult.Yes) return;

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
            using (var stream = new FileStream(SastHelper.IgnoreFilePath(solutionFilePath), FileMode.Append, FileAccess.Write))
            using (var writer = new StreamWriter(stream))
            {
                await writer.WriteLineAsync(strMessage);
            }
        }
    }
}
