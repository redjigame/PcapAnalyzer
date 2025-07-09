
namespace PcapAnalyzer.Models;

public class DirectoryEnumerationModel
{
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int DestinationPort { get; set; }
    public int RequestCount { get; set; }
    public DateTime FirstRequestTime { get; set; }
    public DateTime LastRequestTime { get; set; }
    public string UserAgent { get; set; }
    public List<string> RequestedUrls { get; set; } = new List<string>();
    public List<int> PacketNumbers { get; set; } = new List<int>();
}
