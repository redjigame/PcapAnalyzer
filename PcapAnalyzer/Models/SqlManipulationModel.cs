
namespace PcapAnalyzer.Models;

public class SqlManipulationModel
{
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int DestinationPort { get; set; }
    public string SqlCommand { get; set; }
    public DateTime PacketTime { get; set; }
    public int PacketNumber { get; set; }
}
