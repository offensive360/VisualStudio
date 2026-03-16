using System.Runtime.InteropServices;
using Microsoft.VisualStudio.Shell;

namespace OffensiveVS360.ToolWindow
{
    [Guid("B2C3D4E5-F6A7-8B9C-0D1E-F2A3B4C5D6E7")]
    public class FindingsWindow : ToolWindowPane
    {
        public FindingsWindowControl Control { get; private set; }

        public FindingsWindow() : base(null)
        {
            Caption = "O360 Security Findings";
            Control = new FindingsWindowControl();
            Content = Control;
        }
    }
}
