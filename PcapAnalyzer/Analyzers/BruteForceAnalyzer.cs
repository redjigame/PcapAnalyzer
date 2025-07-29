using PacketDotNet;
using PcapAnalyzer.Detectors;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Analyzers;

public class BruteForceAnalyzer
{
    private readonly HashSet<int> knownSqlPorts = new() { 1433, 1434, 2433, 2434 };

    private readonly BruteForceDetector _bruteForceDetector = new BruteForceDetector();

    public void BruteForceAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker, TcpPacket tcp, string payload)
    {
        if (knownSqlPorts.Contains(srcPort) || knownSqlPorts.Contains(dstPort))
        {
            if ((tcp.Flags & 0x02) == 0x02 && (tcp.Flags & 0x10) == 0)
            {
                _bruteForceDetector.AnalyzeTdsTraffic(srcIP, srcPort, dstIP, dstPort, packetCount, date, attemptTracker);
            }
        }
        if (dstPort == 22 && (tcp.Flags & 0x02) == 0x02 && (tcp.Flags & 0x10) == 0)
        {
            _bruteForceDetector.AnalyzeSshTraffic(srcIP, srcPort, dstIP, dstPort, packetCount, date, attemptTracker);
        }
        if ((tcp.PayloadData.Length > 0 && (dstPort == 80 || dstPort == 80 || Analyzer.IsHttpRequest(tcp.PayloadData))))
        {
            _bruteForceDetector.AnalyzeHttpTraffic(srcIP, srcPort, dstIP, dstPort, packetCount, date, payload, attemptTracker);
        }
        else
        {
            _bruteForceDetector.AnalyzeOtherTraffic(srcIP, srcPort, dstIP, dstPort, packetCount, date, attemptTracker);
        }
    }
}
