using System.Collections.Generic;
using Newtonsoft.Json;

namespace SAST.VSExt.Models
{
    public class ScanResponse
    {
        // Server-authoritative total — plugins should display this as the count
        // instead of re-counting or client-side deduplicating the array.
        // Introduced by the IDECO backend 2026-04-08 to prevent count drift.
        [JsonProperty("totalVulnerabilities")]
        public int? TotalVulnerabilities { get; set; }

        [JsonProperty("vulnerabilities")]
        public IEnumerable<VulnerabilityResponse> Vulnerabilities { get; set; }

        [JsonProperty("projectId")]
        public string ProjectId { get; set; }

        [JsonProperty("status")]
        public int? Status { get; set; }
    }
}
