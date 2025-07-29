using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class XxeAnalyzer
{
    public void XxeAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, List<ScriptInjectionModel> xxeTracker)
    {
        if (IsXxePattern(payload, out string matchedPattern))
        {
            xxeTracker.Add(new ScriptInjectionModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = srcPort,
                ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                PacketNumber = packetCount,
                PacketTime = date,
                ScriptType = $"XXE ({matchedPattern})"
            });
        }
    }

    private bool IsXxePattern(string payload, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string lowerPayload = payload.ToLowerInvariant();

        if (lowerPayload.Contains("<!doctype html"))
            return false;

        string[] patterns =
        {
                "<!DOCTYPE",
                "<!ENTITY",
                "SYSTEM \"file://",
                "SYSTEM \"http://",
                "SYSTEM \"ftp://",
                "><!ENTITY",
                "<!ELEMENT",
                "<!ATTLIST"
            };

        foreach (var pattern in patterns)
        {
            if (Regex.IsMatch(payload, pattern, RegexOptions.IgnoreCase))
            {
                matchedPattern = pattern;
                return true;
            }
        }
        return false;
    }
}
