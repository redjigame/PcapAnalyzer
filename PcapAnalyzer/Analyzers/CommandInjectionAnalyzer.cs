using PacketDotNet;
using PcapAnalyzer.Detectors;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Analyzers;

public class CommandInjectionAnalyzer
{
    private readonly CommandInjectionDetector _cmdInjecDetector = new CommandInjectionDetector();

    public void CmdInjecAnalyze(int packetCount, DateTime date,IPPacket ip, TcpPacket tcp, string payload, Dictionary<(string SrcIP, string DstIP, int DstPort), ScriptInjectionModel> detectedInjections)
    {
        if (tcp?.PayloadData != null && ip != null && tcp.PayloadData.Length > 0)
        {
            _cmdInjecDetector.DetectCmdInjecAttempts(payload, detectedInjections);
        }
    }
}
