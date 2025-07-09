
namespace PcapAnalyzer.Models;

public class BruteForceModel
{
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int DestinationPort { get; set; }
    public int AttemptCount { get; set; }
    public DateTime FirstAttemptTime { get; set; }
    public DateTime LastAttemptTime { get; set; }
    public string Protocol { get; set; } // HTTP ou SSH
    public string TargetUrl { get; set; } // Pour HTTP uniquement
    public List<int> PacketNumbers { get; set; } = new List<int>();
}
