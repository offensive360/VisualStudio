using System.ComponentModel;
using Microsoft.VisualStudio.Shell;

namespace OffensiveVS360.Options
{
    public class O360Settings
    {
        public string Endpoint { get; set; } = "";
        public string AccessToken { get; set; } = "";
        public bool ScanDependencies { get; set; } = true;
        public bool ScanLicenses { get; set; } = false;
        public bool ScanMalware { get; set; } = false;
    }

    public class OptionsPage : DialogPage
    {
        private static OptionsPage _instance;

        [Category("Connection")]
        [DisplayName("Server Endpoint")]
        [Description("O360 SAST server URL (e.g., https://your-server.com:1800)")]
        public string Endpoint { get; set; } = "";

        [Category("Connection")]
        [DisplayName("Access Token")]
        [Description("API access token generated from O360 SAST dashboard under Settings → Tokens")]
        [PasswordPropertyText(true)]
        public string AccessToken { get; set; } = "";

        [Category("Scan Options")]
        [DisplayName("Scan Dependencies (SCA)")]
        [Description("Include dependency vulnerability scanning")]
        public bool ScanDependencies { get; set; } = true;

        [Category("Scan Options")]
        [DisplayName("Scan Licenses")]
        [Description("Include open source license compliance scanning")]
        public bool ScanLicenses { get; set; } = false;

        [Category("Scan Options")]
        [DisplayName("Scan for Malware")]
        [Description("Include malware detection scanning")]
        public bool ScanMalware { get; set; } = false;

        protected override void OnActivate(CancelEventArgs e)
        {
            base.OnActivate(e);
            _instance = this;
        }

        public static O360Settings GetSettings()
        {
            if (_instance != null)
            {
                return new O360Settings
                {
                    Endpoint = _instance.Endpoint?.TrimEnd('/') ?? "",
                    AccessToken = _instance.AccessToken ?? "",
                    ScanDependencies = _instance.ScanDependencies,
                    ScanLicenses = _instance.ScanLicenses,
                    ScanMalware = _instance.ScanMalware
                };
            }

            // Fallback: try loading from package if not yet shown
            return new O360Settings();
        }

        internal static void SetInstance(OptionsPage page)
        {
            _instance = page;
        }
    }
}
