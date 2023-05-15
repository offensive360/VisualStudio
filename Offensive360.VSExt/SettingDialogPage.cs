using EnvDTE;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using Offensive360.VSExt.Helpers;
using Offensive360.VSExt.Properties;
using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;

namespace Offensive360.VSExt
{
    internal class SettingDialogPage : UIElementDialogPage
    {
        public const string PageName = "General";

        private SettingDialogControl dialogControl;

        protected override UIElement Child
        {
            get
            {
                if (dialogControl == null)
                {
                    dialogControl = new SettingDialogControl();
                }
                return dialogControl;
            }
        }

        protected override void OnActivate(CancelEventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();
            base.OnActivate(e);

            string doNotDeleteFilePath = Assembly.GetExecutingAssembly().Location;
            doNotDeleteFilePath = doNotDeleteFilePath.Replace(doNotDeleteFilePath.Split('\\').Last(), "Resources\\DoNotDeleteMe.txt");
            
            if (!File.ReadLines(doNotDeleteFilePath).Any())
            {
                File.WriteAllText(doNotDeleteFilePath, DateTime.Now.ToString());
                Settings.Default.BaseUrl = "<Replace with SAST API base url>";
                Settings.Default.AccessToken = "<Replace with SAST API access token starting with ey..>";

                var dte = (DTE)(ServiceProvider.GetGlobalServiceAsync(typeof(SDTE))).Result;

                if (File.Exists(SastHelper.IgnoreFilePath(dte.DTE.Solution.FullName)))
                {
                    File.Delete(SastHelper.IgnoreFilePath(dte.DTE.Solution.FullName));
                }

            }

            dialogControl.txtAccessToken.Text = Settings.Default.AccessToken;
            dialogControl.txtBaseUrl.Text = Settings.Default.BaseUrl;
        }

        protected override void OnApply(PageApplyEventArgs e)
        {
            if (e.ApplyBehavior == ApplyKind.Apply)
            {
                Settings.Default.AccessToken = dialogControl.txtAccessToken.Text;
                Settings.Default.BaseUrl = dialogControl.txtBaseUrl.Text;
                Settings.Default.Save();
            }

            base.OnApply(e);
        }
    }
}
