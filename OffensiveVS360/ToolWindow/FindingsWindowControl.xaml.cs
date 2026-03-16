using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using EnvDTE;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using OffensiveVS360.Models;
using OffensiveVS360.Services;
using Task = System.Threading.Tasks.Task;

namespace OffensiveVS360.ToolWindow
{
    public class FindingRow
    {
        public Vulnerability Vulnerability { get; set; }
        public string SeverityLabel { get; set; }
        public Brush SeverityColor { get; set; }
        public string Title { get; set; }
        public string FileDisplay { get; set; }
        public string Location { get; set; }
    }

    public partial class FindingsWindowControl : UserControl
    {
        private readonly ObservableCollection<FindingRow> _findings = new ObservableCollection<FindingRow>();
        private CancellationTokenSource _cts;
        private ScanService _scanService;

        public FindingsWindowControl()
        {
            InitializeComponent();
            listFindings.ItemsSource = _findings;
        }

        internal void SetScanService(ScanService svc)
        {
            _scanService = svc;
            _scanService.ProgressChanged += (s, e) =>
                Dispatcher.Invoke(() => lblStatus.Text = e.Message);
        }

        internal void ShowResults(ScanResponse result)
        {
            Dispatcher.Invoke(() =>
            {
                _findings.Clear();

                if (result?.Vulnerabilities == null || result.Vulnerabilities.Count == 0)
                {
                    lblStatus.Text = "Scan complete — no findings.";
                    summaryBar.Visibility = Visibility.Collapsed;
                    return;
                }

                var ordered = result.Vulnerabilities
                    .OrderByDescending(v => (int)v.GetRiskLevel())
                    .ToList();

                foreach (var v in ordered)
                    _findings.Add(BuildRow(v));

                UpdateSummary(result.Vulnerabilities);
                lblStatus.Text = $"{result.Vulnerabilities.Count} finding(s)";
                summaryBar.Visibility = Visibility.Visible;
            });
        }

        internal void ClearFindings()
        {
            Dispatcher.Invoke(() =>
            {
                _findings.Clear();
                detailPanel.Visibility = Visibility.Collapsed;
                summaryBar.Visibility = Visibility.Collapsed;
                lblStatus.Text = "No scan results";
            });
        }

        private FindingRow BuildRow(Vulnerability v)
        {
            var risk = v.GetRiskLevel();
            return new FindingRow
            {
                Vulnerability = v,
                SeverityLabel = risk.ToString(),
                SeverityColor = GetSeverityBrush(risk),
                Title = v.DisplayTitle,
                FileDisplay = System.IO.Path.GetFileName(v.FilePath ?? v.FileName ?? ""),
                Location = $"Line {v.LineNumber}"
            };
        }

        private Brush GetSeverityBrush(RiskLevel risk)
        {
            switch (risk)
            {
                case RiskLevel.Critical: return new SolidColorBrush(Color.FromRgb(0xC0, 0x00, 0x00));
                case RiskLevel.High:     return new SolidColorBrush(Color.FromRgb(0xFF, 0x45, 0x00));
                case RiskLevel.Medium:   return new SolidColorBrush(Color.FromRgb(0xFF, 0xA5, 0x00));
                case RiskLevel.Low:      return new SolidColorBrush(Color.FromRgb(0x46, 0x82, 0xB4));
                default:                 return new SolidColorBrush(Color.FromRgb(0x80, 0x80, 0x80));
            }
        }

        private void UpdateSummary(List<Vulnerability> vulns)
        {
            int critical = 0, high = 0, medium = 0, low = 0, info = 0;
            foreach (var v in vulns)
            {
                switch (v.GetRiskLevel())
                {
                    case RiskLevel.Critical: critical++; break;
                    case RiskLevel.High:     high++; break;
                    case RiskLevel.Medium:   medium++; break;
                    case RiskLevel.Low:      low++; break;
                    default:                 info++; break;
                }
            }
            lblCritical.Text = $"{critical} Critical";
            lblHigh.Text = $"{high} High";
            lblMedium.Text = $"{medium} Medium";
            lblLow.Text = $"{low} Low";
            lblInfo.Text = $"{info} Info";
        }

        private async void BtnScanSolution_Click(object sender, RoutedEventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

            var dte = Package.GetGlobalService(typeof(DTE)) as DTE;
            if (dte?.Solution == null || string.IsNullOrEmpty(dte.Solution.FullName))
            {
                MessageBox.Show("No solution is open.", "O360 SAST", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var solutionDir = System.IO.Path.GetDirectoryName(dte.Solution.FullName);
            await RunScanAsync(() => _scanService.ScanFolderAsync(solutionDir, _cts.Token));
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            ClearFindings();
        }

        internal async Task RunScanAsync(Func<System.Threading.Tasks.Task<ScanResponse>> scanFunc)
        {
            _cts?.Cancel();
            _cts = new CancellationTokenSource();

            btnScanSolution.IsEnabled = false;
            btnClear.IsEnabled = false;
            detailPanel.Visibility = Visibility.Collapsed;
            lblStatus.Text = "Scanning...";

            try
            {
                var result = await scanFunc();
                ShowResults(result);
            }
            catch (OperationCanceledException)
            {
                lblStatus.Text = "Scan cancelled.";
            }
            catch (Exception ex)
            {
                lblStatus.Text = $"Error: {ex.Message}";
                MessageBox.Show(ex.Message, "O360 SAST — Scan Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                btnScanSolution.IsEnabled = true;
                btnClear.IsEnabled = true;
            }
        }

        private void ListFindings_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (listFindings.SelectedItem is FindingRow row)
                ShowDetail(row.Vulnerability);
        }

        private async void ListFindings_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (listFindings.SelectedItem is FindingRow row)
                await NavigateToFindingAsync(row.Vulnerability);
        }

        private void ShowDetail(Vulnerability v)
        {
            detailTitle.Text = v.DisplayTitle;
            detailFile.Text = $"{v.FilePath ?? v.FileName}  ·  Line {v.LineNumber}";

            detailEffect.Text = v.Effect ?? v.VulnerabilityText ?? "";
            detailEffect.Visibility = string.IsNullOrWhiteSpace(detailEffect.Text)
                ? Visibility.Collapsed : Visibility.Visible;

            if (!string.IsNullOrWhiteSpace(v.Recommendation))
            {
                recLabel.Visibility = Visibility.Visible;
                detailRec.Text = v.Recommendation;
                detailRec.Visibility = Visibility.Visible;
            }
            else
            {
                recLabel.Visibility = Visibility.Collapsed;
                detailRec.Visibility = Visibility.Collapsed;
            }

            if (!string.IsNullOrWhiteSpace(v.CodeSnippet))
            {
                codeLabel.Visibility = Visibility.Visible;
                codeBox.Visibility = Visibility.Visible;
                detailCode.Text = v.CodeSnippet;
            }
            else
            {
                codeLabel.Visibility = Visibility.Collapsed;
                codeBox.Visibility = Visibility.Collapsed;
            }

            detailPanel.Visibility = Visibility.Visible;
        }

        private async Task NavigateToFindingAsync(Vulnerability v)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();
            try
            {
                var dte = Package.GetGlobalService(typeof(DTE)) as DTE;
                if (dte == null) return;

                var filePath = v.FilePath ?? v.FileName;
                if (string.IsNullOrEmpty(filePath)) return;

                // Try to find the file in the solution
                var fullPath = ResolveFilePath(dte, filePath);
                if (fullPath == null) return;

                var window = dte.ItemOperations.OpenFile(fullPath);
                if (window == null) return;

                var textDoc = window.Document?.Object("TextDocument") as TextDocument;
                if (textDoc == null) return;

                var ep = textDoc.StartPoint.CreateEditPoint();
                var line = v.GetLineNumberInt();
                ep.MoveToLineAndOffset(line, 1);
                ep.TryToShow(EnvDTE.vsFindResults.vsFindResultsNone, true);

                var sel = textDoc.Selection;
                sel.MoveToLineAndOffset(line, Math.Max(1, v.GetColumnNumberInt()));
                sel.MoveToLineAndOffset(line, Math.Max(1, v.GetColumnNumberInt()) + 1, true);
            }
            catch { /* Navigation is best-effort */ }
        }

        private string ResolveFilePath(DTE dte, string filePath)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // If it's an absolute path and exists, use it directly
            if (System.IO.File.Exists(filePath)) return filePath;

            // Try to find relative to solution root
            if (dte.Solution != null && !string.IsNullOrEmpty(dte.Solution.FullName))
            {
                var solutionDir = System.IO.Path.GetDirectoryName(dte.Solution.FullName);
                var candidate = System.IO.Path.Combine(solutionDir, filePath.TrimStart('/', '\\'));
                if (System.IO.File.Exists(candidate)) return candidate;
            }

            return null;
        }
    }
}
