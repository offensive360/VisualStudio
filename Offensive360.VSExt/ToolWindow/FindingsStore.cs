using System;
using System.Collections.ObjectModel;
using System.ComponentModel;

namespace Offensive360.VSExt.ToolWindow
{
    /// <summary>
    /// Observable row used by the Offensive 360 findings DataGrid.
    /// Kept as a plain POCO with INotifyPropertyChanged for WPF binding.
    /// </summary>
    public class FindingRow : INotifyPropertyChanged
    {
        public string Severity { get; set; }
        public string Title { get; set; }
        public string File { get; set; }
        public int Line { get; set; }
        public int Column { get; set; }
        /// <summary>Absolute file path used for double-click navigation.</summary>
        public string AbsoluteFilePath { get; set; }
        public string Description { get; set; }
        public string Recommendation { get; set; }
        public string References { get; set; }
        public string CodeSnippet { get; set; }

        /// <summary>Ordering key for severity column: 0=Critical, 1=High, 2=Medium, 3=Low.</summary>
        public int SeverityOrder
        {
            get
            {
                switch ((Severity ?? "").ToUpperInvariant())
                {
                    case "CRITICAL": return 0;
                    case "HIGH": return 1;
                    case "MEDIUM": return 2;
                    case "LOW": return 3;
                    default: return 99;
                }
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
    }

    /// <summary>
    /// Single process-wide store of the current scan's findings.
    /// The scan flow calls Replace() when a new scan completes; the tool window
    /// binds its DataGrid to Rows and updates automatically.
    /// </summary>
    public static class FindingsStore
    {
        public static ObservableCollection<FindingRow> Rows { get; } = new ObservableCollection<FindingRow>();

        /// <summary>Counter so the panel header shows "O360: 94 findings (Critical 23, High 28, ...)".</summary>
        public static int Critical { get; private set; }
        public static int High { get; private set; }
        public static int Medium { get; private set; }
        public static int Low { get; private set; }

        /// <summary>Raised on the UI thread after Replace() so the tool window can refresh its header label.</summary>
        public static event EventHandler Updated;

        public static void Replace(System.Collections.Generic.IEnumerable<FindingRow> newRows)
        {
            Rows.Clear();
            Critical = High = Medium = Low = 0;
            if (newRows != null)
            {
                foreach (var r in newRows)
                {
                    Rows.Add(r);
                    switch ((r.Severity ?? "").ToUpperInvariant())
                    {
                        case "CRITICAL": Critical++; break;
                        case "HIGH": High++; break;
                        case "MEDIUM": Medium++; break;
                        case "LOW": Low++; break;
                    }
                }
            }
            Updated?.Invoke(null, EventArgs.Empty);
        }

        public static void Clear()
        {
            Rows.Clear();
            Critical = High = Medium = Low = 0;
            Updated?.Invoke(null, EventArgs.Empty);
        }
    }
}
