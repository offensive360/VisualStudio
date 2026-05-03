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

            // Keep the editor in sync with the selected row. Without this, the
            // detail pane could show line 34 / "AKIA..." while the editor was
            // still parked at line 32 / "stripeApiKey" from the previous
            // double-click — reported as "line and code is different".
            NavigateTo(row);
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
                if (dte == null) { try { Offensive360.VSExt.Helpers.O360Logger.Log("[Nav] dte=null"); } catch {} return; }

                string path = row.AbsoluteFilePath;
                // ItemOperations.OpenFile silently returns null for non-rooted paths,
                // so any relative survivor must be re-resolved under the solution folder
                // here. (Belt-and-braces: ResolveAbsoluteFilePath already guarantees
                // absolute paths in v1.12.21+.)
                if (!string.IsNullOrWhiteSpace(path) && !Path.IsPathRooted(path)) path = null;
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                {
                    try
                    {
                        var sol = dte.Solution?.FullName;
                        if (!string.IsNullOrEmpty(sol) && File.Exists(sol))
                        {
                            var solDir = Path.GetDirectoryName(sol);
                            if (!string.IsNullOrEmpty(solDir) && !string.IsNullOrEmpty(row.File))
                            {
                                var matches = Directory.GetFiles(solDir, row.File, SearchOption.AllDirectories);
                                if (matches != null && matches.Length > 0) path = Path.GetFullPath(matches[0]);
                            }
                        }
                    }
                    catch { }
                }

                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || !Path.IsPathRooted(path))
                {
                    try { Offensive360.VSExt.Helpers.O360Logger.Log($"[Nav] file not found/relative: row.File={row.File} abs={row.AbsoluteFilePath} resolved={path}"); } catch {}
                    return;
                }

                try { Offensive360.VSExt.Helpers.O360Logger.Log($"[Nav] target {path}:{row.Line}:{row.Column}"); } catch {}

                var win = dte.ItemOperations.OpenFile(path, EnvDTE.Constants.vsViewKindCode);
                if (win == null) { try { Offensive360.VSExt.Helpers.O360Logger.Log("[Nav] OpenFile returned null"); } catch {} return; }
                try { win.Activate(); } catch { }

                if (row.Line <= 0) return;

                // Always pull Selection from dte.ActiveDocument AFTER win.Activate().
                // The win.Document path was unreliable on selection-driven navigation —
                // GotoLine was being called against a stale TextSelection that didn't
                // belong to the now-active editor, leaving the visible caret unmoved.
                TextSelection selection = null;
                try { selection = dte.ActiveDocument?.Selection as TextSelection; } catch { }
                if (selection == null)
                {
                    try
                    {
                        var winDoc = win.Document;
                        if (winDoc != null) selection = winDoc.Selection as TextSelection;
                    }
                    catch { }
                }

                if (selection == null)
                {
                    try { Offensive360.VSExt.Helpers.O360Logger.Log("[Nav] no TextSelection on active doc OR window"); } catch {}
                    return;
                }

                try
                {
                    selection.GotoLine(row.Line, true);
                    if (row.Column > 0)
                    {
                        try { selection.MoveToLineAndOffset(row.Line, row.Column, false); } catch { }
                    }
                    try { Offensive360.VSExt.Helpers.O360Logger.Log($"[Nav] GotoLine({row.Line}) OK — caret now line={selection.CurrentLine}"); } catch {}
                }
                catch (Exception navEx)
                {
                    try { Offensive360.VSExt.Helpers.O360Logger.Log($"[Nav] GotoLine threw {navEx.GetType().Name}: {navEx.Message}"); } catch {}
                }
            }
            catch (Exception outerEx)
            {
                try { Offensive360.VSExt.Helpers.O360Logger.Log($"[Nav] outer threw {outerEx.GetType().Name}: {outerEx.Message}"); } catch {}
            }
        }
    }
}
