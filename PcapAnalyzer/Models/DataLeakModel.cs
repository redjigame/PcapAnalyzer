
namespace PcapAnalyzer.Models;

public class DataLeakModel
{
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int DestinationPort { get; set; }
    public string LeakType { get; set; }          
    public string SuspiciousContent { get; set; } 
    public int PacketNumber { get; set; }
    public DateTime PacketTime { get; set; }
}
