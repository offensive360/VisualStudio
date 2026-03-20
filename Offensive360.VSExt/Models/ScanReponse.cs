using System.Collections.Generic;

namespace SAST.VSExt.Models
{
    public class ScanResponse
    {
        public IEnumerable<VulnerabilityResponse> Vulnerabilities { get; set; }
    }
}