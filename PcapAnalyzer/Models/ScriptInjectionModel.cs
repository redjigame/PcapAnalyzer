
namespace PcapAnalyzer.Models;

public class ScriptInjectionModel
{
    public string SourceIP { get; set; }
    public string DestinationIP { get; set; }
    public int DestinationPort { get; set; }
    public string ScriptContent { get; set; }
    public int PacketNumber { get; set; }
    public DateTime PacketTime { get; set; }
    public string ScriptType { get; set; }
}
