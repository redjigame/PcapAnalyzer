namespace PcapAnalyzer.Models;

public class AnalysisResultModel
{
    public int TotalPackets { get; set; }
    public List<BruteForceModel> DetectedAttempts { get; set; } = new List<BruteForceModel>();
    public List<SqlManipulationModel> DetectedSqlChanges { get; set; } = new List<SqlManipulationModel>();
    public List<DirectoryEnumerationModel> DetectedDirBruteForces { get; set; } = new List<DirectoryEnumerationModel>();
    public List<ScriptInjectionModel> DetectedScripts { get; set; } = new List<ScriptInjectionModel>();
    public List<DataLeakModel> DetectedDataLeaks { get; set; } = new List<DataLeakModel> { };
}
