using EnvDTE;
using Microsoft.VisualStudio.Shell;
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace Offensive360.VSExt.ToolWindow
{
    public partial class FindingsToolWindowControl : UserControl
    {
        public FindingsToolWindowControl()
        {
            InitializeComponent();

            // Bind the grid through a CollectionView so we can filter without mutating the source store.
            var view = CollectionViewSource.GetDefaultView(FindingsStore.Rows);
            view.Filter = FilterPredicate;
            FindingsGrid.ItemsSource = view;

            FindingsStore.Updated += (s, e) =>
            {
                Dispatcher.Invoke(() =>
                {
                    RefreshHeader();
                    CollectionViewSource.GetDefaultView(FindingsStore.Rows)?.Refresh();
                });
            };
            RefreshHeader();
        }

        private bool FilterPredicate(object item)
        {
            var r = item as FindingRow;
            if (r == null) return false;
            var sev = (r.Severity ?? "").ToUpperInvariant();
            if (sev == "CRITICAL" && !(CriticalCheck?.IsChecked ?? true)) return false;
            if (sev == "HIGH" && !(HighCheck?.IsChecked ?? true)) return false;
            if (sev == "MEDIUM" && !(MediumCheck?.IsChecked ?? true)) return false;
            if (sev == "LOW" && !(LowCheck?.IsChecked ?? true)) return false;
            var needle = SearchBox?.Text ?? "";
            if (!string.IsNullOrWhiteSpace(needle))
            {
                var n = needle.Trim();
                bool any =
                    (r.Title != null && r.Title.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (r.File != null && r.File.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (r.Description != null && r.Description.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0);
                if (!any) return false;
            }
            return true;
        }

        private void RefreshHeader()
        {
            HeaderLabel.Text =
                $"Offensive 360 — {FindingsStore.Rows.Count} findings  " +
                $"(Critical {FindingsStore.Critical}, High {FindingsStore.High}, Medium {FindingsStore.Medium}, Low {FindingsStore.Low})";
        }

        private void Filter_Changed(object sender, RoutedEventArgs e)
        {
            CollectionViewSource.GetDefaultView(FindingsStore.Rows)?.Refresh();
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            CollectionViewSource.GetDefaultView(FindingsStore.Rows)?.Refresh();
        }

        private void FindingsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            var row = FindingsGrid.SelectedItem as FindingRow;
            if (row == null)
            {
                DetailTitle.Text = "Select a finding to see details.";
                DetailLocation.Text = "";
                DetailDescription.Text = "";
                DetailRecommendation.Text = "";
                DetailCode.Text = "";
                return;
            }
            DetailTitle.Text = $"[{row.Severity}] {row.Title}";
            DetailLocation.Text = $"{row.File}:{row.Line}";
            DetailDescription.Text = row.Description ?? "";
            DetailRecommendation.Text = row.Recommendation ?? "";
            DetailCode.Text = row.CodeSnippet ?? "";
        }

        private void FindingsGrid_MouseDoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            var row = FindingsGrid.SelectedItem as FindingRow;
            if (row == null) return;
            NavigateTo(row);
        }

        private void NavigateTo(FindingRow row)
        {
            try
            {
                ThreadHelper.ThrowIfNotOnUIThread();
                var dte = Package.GetGlobalService(typeof(EnvDTE.DTE)) as DTE;
                if (dte == null) return;

                string path = row.AbsoluteFilePath;
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    // Fall back to resolving via File name under the solution folder
                    try
                    {
                        var sol = dte.Solution?.FullName;
                        if (!string.IsNullOrEmpty(sol) && File.Exists(sol))
                        {
                            var solDir = Path.GetDirectoryName(sol);
                            if (!string.IsNullOrEmpty(solDir) && !string.IsNullOrEmpty(row.File))
                            {
                                var matches = Directory.GetFiles(solDir, row.File, SearchOption.AllDirectories);
                                if (matches != null && matches.Length > 0) path = matches[0];
                            }
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;

                // Explicitly request the text view, activate the returned window,
                // and read Selection from the returned Window's Document — NOT from
                // dte.ActiveDocument. ActiveDocument may still point to the
                // previously-active document on the first click because the window
                // activation hasn't propagated yet (this is the "4-click bug"
                // reported against v1.12.10/11: first double-click jumped to the
                // wrong line, second double-click worked).
                var win = dte.ItemOperations.OpenFile(path, EnvDTE.Constants.vsViewKindCode);
                if (win == null) return;
                try { win.Activate(); } catch { }

                if (row.Line <= 0) return;

                // Prefer the Selection from the Window's own Document. Fall back to
                // ActiveDocument only if the Window didn't expose one.
                TextSelection selection = null;
                try
                {
                    var winDoc = win.Document;
                    if (winDoc != null)
                    {
                        selection = winDoc.Selection as TextSelection;
                    }
                }
                catch { }

                if (selection == null)
                {
                    try { selection = dte.ActiveDocument?.Selection as TextSelection; } catch { }
                }

                if (selection != null)
                {
                    try
                    {
                        selection.GotoLine(row.Line, true);
                        if (row.Column > 0)
                        {
                            try { selection.MoveToLineAndOffset(row.Line, row.Column, false); } catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { /* navigation failure must not crash the tool window */ }
        }
    }
}
