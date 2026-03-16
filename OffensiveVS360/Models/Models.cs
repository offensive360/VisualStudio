using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OffensiveVS360.Models
{
    public enum RiskLevel { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

    public class Vulnerability
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("fileName")]
        public string FileName { get; set; }

        [JsonProperty("filePath")]
        public string FilePath { get; set; }

        [JsonProperty("lineNumber")]
        public string LineNumber { get; set; }

        [JsonProperty("columnNumber")]
        public string ColumnNumber { get; set; }

        [JsonProperty("codeSnippet")]
        public string CodeSnippet { get; set; }

        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("riskLevel")]
        public JToken RiskLevelRaw { get; set; }

        [JsonProperty("vulnerability")]
        public string VulnerabilityText { get; set; }

        [JsonProperty("title")]
        public string Title { get; set; }

        [JsonProperty("effect")]
        public string Effect { get; set; }

        [JsonProperty("references")]
        public string References { get; set; }

        [JsonProperty("recommendation")]
        public string Recommendation { get; set; }

        public RiskLevel GetRiskLevel()
        {
            if (RiskLevelRaw == null) return RiskLevel.Medium;
            if (RiskLevelRaw.Type == JTokenType.Integer)
                return (RiskLevel)RiskLevelRaw.Value<int>();
            if (RiskLevelRaw.Type == JTokenType.String &&
                System.Enum.TryParse<RiskLevel>(RiskLevelRaw.Value<string>(), true, out var r))
                return r;
            return RiskLevel.Medium;
        }

        public string DisplayTitle => !string.IsNullOrWhiteSpace(Title) ? Title : VulnerabilityText ?? "Unknown";

        public int GetLineNumberInt()
        {
            return int.TryParse(LineNumber, out var n) ? n : 1;
        }

        public int GetColumnNumberInt()
        {
            return int.TryParse(ColumnNumber, out var n) ? n : 1;
        }
    }

    public class DependencyVulnerability
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("packageName")]
        public string PackageName { get; set; }

        [JsonProperty("version")]
        public string Version { get; set; }

        [JsonProperty("severity")]
        public string Severity { get; set; }

        [JsonProperty("description")]
        public string Description { get; set; }

        [JsonProperty("fixVersion")]
        public string FixVersion { get; set; }

        [JsonProperty("cveId")]
        public string CveId { get; set; }
    }

    public class ScanResponse
    {
        [JsonProperty("projectId")]
        public string ProjectId { get; set; }

        [JsonProperty("status")]
        public JToken StatusRaw { get; set; }

        [JsonProperty("vulnerabilities")]
        public List<Vulnerability> Vulnerabilities { get; set; } = new List<Vulnerability>();

        [JsonProperty("dependencyVulnerabilities")]
        public List<DependencyVulnerability> DependencyVulnerabilities { get; set; } = new List<DependencyVulnerability>();

        [JsonProperty("malwares")]
        public List<JObject> Malwares { get; set; } = new List<JObject>();

        [JsonProperty("licenses")]
        public List<JObject> Licenses { get; set; } = new List<JObject>();
    }

    public class FindingViewModel
    {
        public Vulnerability Vulnerability { get; set; }
        public string SeverityLabel { get; set; }
        public string FileDisplay { get; set; }
        public string Location { get; set; }

        public FindingViewModel(Vulnerability v)
        {
            Vulnerability = v;
            SeverityLabel = v.GetRiskLevel().ToString();
            FileDisplay = System.IO.Path.GetFileName(v.FilePath ?? v.FileName ?? "");
            Location = $"Line {v.LineNumber}";
        }
    }
}
