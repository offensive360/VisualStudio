using Microsoft.VisualStudio.Shell;
using System;
using System.Runtime.InteropServices;

namespace Offensive360.VSExt.ToolWindow
{
    [Guid("6d8478e8-93eb-45cd-901f-7f0e9c636773")]
    public class FindingsToolWindow : ToolWindowPane
    {
        public const string WindowGuidString = "6d8478e8-93eb-45cd-901f-7f0e9c636773";
        public const string WindowTitle = "Offensive 360";

        public FindingsToolWindow() : base(null)
        {
            Caption = WindowTitle;
            // No moniker — default icon is fine. (KnownMonikers set varies across VS SDK versions
            // and picking one that isn't present breaks the build.)
            Content = new FindingsToolWindowControl();
        }
    }
}
