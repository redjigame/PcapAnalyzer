
namespace PcapAnalyzer.Models;

public class NmapModel
{
    public string SourceIP { get; set; }
    public int PortCount { get; set; }
    public DateTime FirstPacketTime { get; set; }
    public DateTime LastPacketTime { get; set; }
}
