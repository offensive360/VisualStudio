using EnvDTE;
using EnvDTE80;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Offensive360.VSExt.Helpers;
using System;
using System.ComponentModel.Design;
using System.IO;
using System.Text.RegularExpressions;
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
            var selectedItem = (TaskListItem)errorList.TableControl.SelectedEntry.Identity;
            var selectedItemHelpLink = selectedItem.HelpKeyword;

            if (!string.IsNullOrWhiteSpace(selectedItemHelpLink))
            {
                try
                {
                    // Try to extract vulnerability type from the help keyword or error text
                    var vulnType = ExtractVulnType(selectedItemHelpLink, selectedItem.Text);
                    var kbEntry = VulnerabilityKnowledgeBase.Lookup(vulnType);

                    // Always use FixGuidanceDialog — create fallback entry if not in KB
                    if (kbEntry == null)
                    {
                        kbEntry = new VulnerabilityKnowledgeBase.VulnKBEntry
                        {
                            VulnerabilityId = vulnType,
                            Title = string.IsNullOrWhiteSpace(vulnType) ? "Security Vulnerability" : vulnType,
                            ShortDescription = "No built-in description available. See References tab for more information.",
                            RiskExplanation = "Review this finding carefully and consult the Offensive360 Knowledge Base.",
                            HowToFix = "Please refer to the References tab and the Offensive360 Knowledge Base for remediation guidance.",
                            References = $"https://knowledge-base.offensive360.com/{Uri.EscapeDataString(vulnType ?? "")}/\nhttps://offensive360.com/academy/",
                            CodePatternBad = "",
                            CodePatternGood = "",
                            CWEs = new string[0]
                        };
                    }

                    var dialog = new FixGuidanceDialog(
                        kbEntry,
                        selectedItem.Text,
                        "",
                        0,
                        !string.IsNullOrWhiteSpace(selectedItemHelpLink) ? selectedItemHelpLink : kbEntry.References);
                    dialog.ShowFixTab();
                    dialog.ShowDialog();
                }
                catch { }
            }
        }

        /// <summary>
        /// Extract vulnerability type from the help keyword URL or error text.
        /// </summary>
        private string ExtractVulnType(string helpKeyword, string errorText)
        {
            // Try to get vuln type from the URL fragment or path (e.g., ".../sql_injection" or "...#sql-injection")
            if (!string.IsNullOrWhiteSpace(helpKeyword))
            {
                var uri = helpKeyword.Split('|')[0].Trim();

                // Check fragment
                var hashIdx = uri.LastIndexOf('#');
                if (hashIdx >= 0 && hashIdx < uri.Length - 1)
                {
                    return uri.Substring(hashIdx + 1);
                }

                // Check last path segment
                var slashIdx = uri.LastIndexOf('/');
                if (slashIdx >= 0 && slashIdx < uri.Length - 1)
                {
                    var segment = uri.Substring(slashIdx + 1);
                    // Remove query string
                    var qIdx = segment.IndexOf('?');
                    if (qIdx >= 0) segment = segment.Substring(0, qIdx);
                    if (!string.IsNullOrWhiteSpace(segment) && !segment.Contains("."))
                    {
                        return segment;
                    }
                }
            }

            // Fallback: use the error text itself
            if (!string.IsNullOrWhiteSpace(errorText))
            {
                // Try to extract a known pattern like "[VulnType]" or "VulnType:"
                var match = Regex.Match(errorText, @"\[([^\]]+)\]");
                if (match.Success)
                    return match.Groups[1].Value;

                // Use the first part before any colon or dash
                var colonIdx = errorText.IndexOf(':');
                if (colonIdx > 0)
                    return errorText.Substring(0, colonIdx).Trim();
            }

            return helpKeyword ?? errorText ?? string.Empty;
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