using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using Offensive360.VSExt.Helpers;

namespace Offensive360.VSExt
{
    public partial class FixGuidanceDialog : Window
    {
        private readonly string _secureCode;
        private readonly string _vulnCode;
        private readonly string _fixGuidance;

        /// <summary>
        /// Opens the dialog using the embedded offline knowledge base entry.
        /// Falls back to internet (knowledge-base.offensive360.com) if offline KB is missing content.
        /// </summary>
        public FixGuidanceDialog(VulnerabilityKnowledgeBase.VulnKBEntry entry, string errorText, string filePath, int lineNumber, string references)
        {
            InitializeComponent();

            if (entry == null)
                throw new ArgumentNullException(nameof(entry));

            _secureCode = entry.CodePatternGood ?? "";
            _vulnCode = entry.CodePatternBad ?? "";
            _fixGuidance = entry.HowToFix ?? "";

            PopulateHeader(entry, filePath, lineNumber);
            PopulateDetailsTab(entry, errorText);
            PopulateFixTab(entry);
            PopulateRefsTab(entry, references);

            // If offline KB is missing description or fix, fetch from internet asynchronously
            bool needsOnlineFetch = string.IsNullOrWhiteSpace(entry.ShortDescription) ||
                                    string.IsNullOrWhiteSpace(entry.HowToFix);
            if (needsOnlineFetch)
            {
                FetchOnlineKBAsync(entry.VulnerabilityId ?? entry.Title ?? "");
            }
        }

        private async void FetchOnlineKBAsync(string vulnType)
        {
            if (string.IsNullOrWhiteSpace(vulnType)) return;
            var slug = System.Text.RegularExpressions.Regex.Replace(vulnType.ToLowerInvariant(), @"[^a-z0-9]", "-").Trim('-');
            var urls = new[]
            {
                $"https://knowledge-base.offensive360.com/api/vulnerabilities/{slug}",
                $"https://knowledge-base.offensive360.com/{vulnType}/"
            };

            foreach (var url in urls)
            {
                try
                {
                    System.Net.Http.HttpResponseMessage response;
                    string body;
                    using (var client = new System.Net.Http.HttpClient { Timeout = System.TimeSpan.FromSeconds(5) })
                    {
                        client.DefaultRequestHeaders.Add("Accept", "application/json,text/html");
                        response = await client.GetAsync(url);
                        if (!response.IsSuccessStatusCode) continue;
                        body = await response.Content.ReadAsStringAsync();
                    }

                    string description = null, impact = null, howToFix = null;

                    // Try JSON
                    try
                    {
                        var json = Newtonsoft.Json.Linq.JObject.Parse(body);
                        description = json.Value<string>("description") ?? json.Value<string>("info");
                        impact = json.Value<string>("impact") ?? json.Value<string>("effect");
                        howToFix = json.Value<string>("recommendation") ?? json.Value<string>("howToFix");
                    }
                    catch
                    {
                        // HTML — extract first paragraph
                        var m = System.Text.RegularExpressions.Regex.Match(body, @"<p[^>]*>(.*?)</p>",
                            System.Text.RegularExpressions.RegexOptions.Singleline);
                        if (m.Success)
                            description = System.Text.RegularExpressions.Regex.Replace(m.Groups[1].Value, @"<[^>]+>", "").Trim();
                    }

                    if (!string.IsNullOrWhiteSpace(description) || !string.IsNullOrWhiteSpace(howToFix))
                    {
                        // Update UI on dispatcher thread
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        {
                            if (!string.IsNullOrWhiteSpace(description) &&
                                (DescriptionText.Text.StartsWith("No built-in") || string.IsNullOrWhiteSpace(DescriptionText.Text)))
                                DescriptionText.Text = description;
                            if (!string.IsNullOrWhiteSpace(impact) &&
                                (ImpactText.Text.StartsWith("Review") || string.IsNullOrWhiteSpace(ImpactText.Text)))
                                ImpactText.Text = impact;
                            if (!string.IsNullOrWhiteSpace(howToFix) &&
                                (FixRecommendationText.Text.StartsWith("Please refer") || string.IsNullOrWhiteSpace(FixRecommendationText.Text)))
                                FixRecommendationText.Text = howToFix;
                        });
                        break;
                    }
                }
                catch { }
            }
        }

        private void PopulateHeader(VulnerabilityKnowledgeBase.VulnKBEntry entry, string filePath, int lineNumber)
        {
            TitleText.Text = entry.Title;

            // Severity from risk explanation
            var riskLower = (entry.RiskExplanation ?? "").ToLowerInvariant();
            Color badgeColor;
            string severityLabel;

            if (riskLower.StartsWith("critical"))
            {
                badgeColor = Color.FromRgb(0xDC, 0x35, 0x45);
                severityLabel = "CRITICAL";
                TitleText.Foreground = new SolidColorBrush(Color.FromRgb(0xF4, 0x47, 0x47));
            }
            else if (riskLower.StartsWith("high"))
            {
                badgeColor = Color.FromRgb(0xFD, 0x7E, 0x14);
                severityLabel = "HIGH";
                TitleText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0x8C, 0x00));
            }
            else if (riskLower.StartsWith("medium"))
            {
                badgeColor = Color.FromRgb(0xFF, 0xC1, 0x07);
                severityLabel = "MEDIUM";
                TitleText.Foreground = new SolidColorBrush(Color.FromRgb(0xFF, 0xD7, 0x00));
            }
            else if (riskLower.StartsWith("low"))
            {
                badgeColor = Color.FromRgb(0x17, 0xA2, 0xB8);
                severityLabel = "LOW";
                TitleText.Foreground = new SolidColorBrush(Color.FromRgb(0x4E, 0xC9, 0xB0));
            }
            else
            {
                badgeColor = Color.FromRgb(0x6C, 0x75, 0x7D);
                severityLabel = "INFO";
                TitleText.Foreground = new SolidColorBrush(Color.FromRgb(0xD4, 0xD4, 0xD4));
            }

            SeverityBadge.Background = new SolidColorBrush(badgeColor);
            SeverityText.Text = severityLabel;

            // Metadata
            MetaType.Text = entry.Title;
            MetaSeverity.Text = severityLabel;
            MetaFile.Text = !string.IsNullOrEmpty(filePath)
                ? $"{filePath}:{lineNumber}"
                : "N/A";
        }

        private void PopulateDetailsTab(VulnerabilityKnowledgeBase.VulnKBEntry entry, string errorText)
        {
            DescriptionText.Text = entry.ShortDescription ?? "No description available.";

            // Impact = risk explanation
            if (!string.IsNullOrEmpty(entry.RiskExplanation))
            {
                ImpactText.Text = entry.RiskExplanation;
            }
            else
            {
                ImpactLabel.Visibility = Visibility.Collapsed;
                ImpactText.Visibility = Visibility.Collapsed;
            }

            // Affected code = the vulnerable pattern from KB
            if (!string.IsNullOrEmpty(entry.CodePatternBad))
            {
                AffectedCodeText.Text = entry.CodePatternBad;
            }
            else
            {
                AffectedCodeLabel.Visibility = Visibility.Collapsed;
                AffectedCodeBlock.Visibility = Visibility.Collapsed;
            }
        }

        private void PopulateFixTab(VulnerabilityKnowledgeBase.VulnKBEntry entry)
        {
            // Recommendation
            FixRecommendationText.Text = entry.HowToFix ?? "No specific fix recommendation available. Check the References tab.";

            // Vulnerable code
            if (!string.IsNullOrEmpty(entry.CodePatternBad))
            {
                VulnCodeText.Text = entry.CodePatternBad;
            }
            else
            {
                VulnCodeLabel.Visibility = Visibility.Collapsed;
                VulnCodeGrid.Visibility = Visibility.Collapsed;
            }

            // Secure code
            if (!string.IsNullOrEmpty(entry.CodePatternGood))
            {
                SecureCodeText.Text = entry.CodePatternGood;
            }
            else
            {
                SecureCodeLabel.Visibility = Visibility.Collapsed;
                SecureCodeGrid.Visibility = Visibility.Collapsed;
            }
        }

        private void PopulateRefsTab(VulnerabilityKnowledgeBase.VulnKBEntry entry, string references)
        {
            var urls = new List<string>();

            // CWE links
            if (entry.CWEs != null)
            {
                foreach (var cwe in entry.CWEs)
                {
                    var num = cwe.Replace("CWE-", "").Trim();
                    urls.Add($"https://cwe.mitre.org/data/definitions/{num}.html");
                }
            }

            // KB references (from VulnerabilityInfo.json)
            if (!string.IsNullOrWhiteSpace(entry.References))
            {
                var kbRefs = VulnerabilityKnowledgeBase.FilterReferences(entry.References);
                foreach (var r in kbRefs)
                    if (!urls.Contains(r)) urls.Add(r);
            }

            // Server-provided references
            if (!string.IsNullOrWhiteSpace(references))
            {
                var filtered = VulnerabilityKnowledgeBase.FilterReferences(references);
                foreach (var r in filtered)
                    if (!urls.Contains(r)) urls.Add(r);
            }

            // Only add O360 KB link if the KB entry has a real reference URL — never auto-generate from title/ID
            // (auto-generated URLs like /Sensitive%20payment%20card%20.../ don't exist on the website)

            // Deduplicate URLs by domain+path (case-insensitive) to prevent duplicates
            var seenUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            urls = urls.Where(u => seenUrls.Add(u.TrimEnd('/'))).ToList();

            if (urls.Count == 0)
            {
                NoRefsText.Visibility = Visibility.Visible;
                return;
            }

            foreach (var url in urls)
            {
                var link = new TextBlock
                {
                    Margin = new Thickness(0, 3, 0, 3),
                    FontSize = 12.5
                };

                var hyperlink = new Hyperlink(new Run(url))
                {
                    NavigateUri = new Uri(url),
                    Foreground = new SolidColorBrush(Color.FromRgb(0x56, 0x9C, 0xD6))
                };
                hyperlink.RequestNavigate += (s, e) =>
                {
                    try { Process.Start(new ProcessStartInfo { FileName = e.Uri.AbsoluteUri, UseShellExecute = true }); } catch { }
                    e.Handled = true;
                };

                link.Inlines.Add(hyperlink);
                RefsContainer.Children.Add(link);
            }
        }

        // --- Tab switching ---
        private void Tab_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            if (btn == null) return;

            var activeStyle = (Style)FindResource("TabBtnActive");
            var inactiveStyle = (Style)FindResource("TabBtn");

            TabDetails.Style = inactiveStyle;
            TabFix.Style = inactiveStyle;
            TabRefs.Style = inactiveStyle;

            PanelDetails.Visibility = Visibility.Collapsed;
            PanelFix.Visibility = Visibility.Collapsed;
            PanelRefs.Visibility = Visibility.Collapsed;

            if (btn == TabDetails)
            {
                TabDetails.Style = activeStyle;
                PanelDetails.Visibility = Visibility.Visible;
            }
            else if (btn == TabFix)
            {
                TabFix.Style = activeStyle;
                PanelFix.Visibility = Visibility.Visible;
            }
            else if (btn == TabRefs)
            {
                TabRefs.Style = activeStyle;
                PanelRefs.Visibility = Visibility.Visible;
            }
        }

        // --- Copy buttons ---
        private void CopyFix_Click(object sender, RoutedEventArgs e)
        {
            CopyToClipboard(_fixGuidance, CopyFixBtn);
        }

        private void CopyVulnCode_Click(object sender, RoutedEventArgs e)
        {
            CopyToClipboard(_vulnCode, sender as Button);
        }

        private void CopySecureCode_Click(object sender, RoutedEventArgs e)
        {
            CopyToClipboard(_secureCode, sender as Button);
        }

        private void CopyToClipboard(string text, Button btn)
        {
            if (string.IsNullOrEmpty(text)) return;

            try
            {
                Clipboard.SetText(text);
                if (btn != null)
                {
                    var original = btn.Content;
                    btn.Content = "Copied!";
                    var timer = new System.Windows.Threading.DispatcherTimer
                    {
                        Interval = TimeSpan.FromSeconds(2)
                    };
                    timer.Tick += (s, args) =>
                    {
                        btn.Content = original;
                        timer.Stop();
                    };
                    timer.Start();
                }
            }
            catch { }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        /// <summary>
        /// Opens the dialog on the Fix tab directly (shortcut for "View Fix" action).
        /// </summary>
        public void ShowFixTab()
        {
            Tab_Click(TabFix, new RoutedEventArgs());
        }
    }
}
