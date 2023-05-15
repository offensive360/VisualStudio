using EnvDTE;
using EnvDTE80;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using System;
using System.ComponentModel.Design;
using System.IO;
using Task = System.Threading.Tasks.Task;

namespace Offensive360.VSExt
{
    internal sealed class GetHelpCommand
    {
        private readonly AsyncPackage package;

        public const int CommandId = 0x0200;

        public static readonly Guid CommandSet = new Guid("762f92d8-926a-4160-8519-badb7cc9a872");

        private static ErrorListProvider _errorListProvider;

        private GetHelpCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new OleMenuCommand(async (sender, e) => ExecuteAsync(sender, e), menuCommandID);
            menuItem.BeforeQueryStatus += async(sender, e) => BeforeQueryStatusAsync(sender, e);
            commandService.AddCommand(menuItem);
        }

        public static GetHelpCommand Instance
        {
            get;
            private set;
        }

        public static async Task InitializeAsync(AsyncPackage package, ErrorListProvider errorListProvider)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            var commandService = await package.GetServiceAsync(typeof(IMenuCommandService)) as OleMenuCommandService;
            Instance = new GetHelpCommand(package, commandService);

            _errorListProvider = errorListProvider;
        }

        private async Task ExecuteAsync(object sender, EventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            var dte = await package.GetServiceAsync(typeof(SDTE)) as DTE2;
            var errorList = dte.ToolWindows.ErrorList as IErrorList;
            var selectedItemHelpLink = ((TaskListItem)errorList.TableControl.SelectedEntry.Identity).HelpKeyword;

            if (!string.IsNullOrWhiteSpace(selectedItemHelpLink))
            {
                try
                {
                    var toolPathToOpenALink = GetToolPathToOpenALink();
                    if(!string.IsNullOrWhiteSpace(toolPathToOpenALink))
                    {
                        System.Diagnostics.Process.Start(toolPathToOpenALink, selectedItemHelpLink);
                    }
                    else
                    {
                        dte.ItemOperations.Navigate(selectedItemHelpLink.Split('|')[0], vsNavigateOptions.vsNavigateOptionsNewWindow);
                    }
                    
                }
                catch { }
            }
        }

        private async Task BeforeQueryStatusAsync(object sender, EventArgs e)
        {
            var button = (OleMenuCommand)sender;
            var dte = await package.GetServiceAsync(typeof(SDTE)) as DTE2;
            var errorList = dte.ToolWindows.ErrorList as IErrorList;
            var selectedItemHelpLink = ((TaskListItem)errorList.TableControl.SelectedEntry.Identity)?.HelpKeyword;

            if (string.IsNullOrWhiteSpace(selectedItemHelpLink) || _errorListProvider.Tasks.Count <= 0)
            {
                button.Enabled = false;
            }
            else
            {
                button.Enabled = true;
            }
        }

        private string GetToolPathToOpenALink()
        {
            var localApplicationDataDirectoryPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var programFilesDirectoryPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            var programFilesX86DirectoryPath = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            
            var chromeRelativePath = Path.Combine("Google", Path.Combine("Chrome", Path.Combine("Application", "chrome.exe")));
            var edgeRelativePath = Path.Combine("Microsoft", Path.Combine("Edge", Path.Combine("Application", "msedge.exe")));

            if (File.Exists(Path.Combine(localApplicationDataDirectoryPath, chromeRelativePath)))
            {
                return Path.Combine(localApplicationDataDirectoryPath, chromeRelativePath);
            }
            else if (File.Exists(Path.Combine(programFilesDirectoryPath, chromeRelativePath)))
            {
                return Path.Combine(programFilesDirectoryPath, chromeRelativePath);
            }
            else if (File.Exists(Path.Combine(programFilesX86DirectoryPath, chromeRelativePath)))
            {
                return Path.Combine(programFilesX86DirectoryPath, chromeRelativePath);
            }
            else if (File.Exists(Path.Combine(localApplicationDataDirectoryPath, edgeRelativePath)))
            {
                return Path.Combine(localApplicationDataDirectoryPath, edgeRelativePath);
            }
            else if (File.Exists(Path.Combine(programFilesDirectoryPath, edgeRelativePath)))
            {
                return Path.Combine(programFilesDirectoryPath, edgeRelativePath);
            }
            else if (File.Exists(Path.Combine(programFilesX86DirectoryPath, edgeRelativePath)))
            {
                return Path.Combine(programFilesX86DirectoryPath, edgeRelativePath);
            }
            else
            {
                return string.Empty;
            }
        }
    }
}