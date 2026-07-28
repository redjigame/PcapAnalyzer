using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class PathTraversalAnalyzer
{
    public void PathTraversalAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, List<ScriptInjectionModel> detectedTraversals)
    {
        if (IsPathTraversalAttempt(payload, out string matchedPattern))
        {
            detectedTraversals.Add(new ScriptInjectionModel
            {
                SourceIP = ip.SourceAddress.ToString(),
                DestinationIP = ip.DestinationAddress.ToString(),
                DestinationPort = tcp.DestinationPort,
                ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                PacketNumber = packetCount,
                PacketTime = date,
                ScriptType = $"Path Traversal ({matchedPattern})"
            });
        }
    }

    private bool IsPathTraversalAttempt(string payload, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string decoded = Uri.UnescapeDataString(payload.ToLowerInvariant());

        string[] patterns =
        {
                @"\.\./", @"\.\.\\", // Unix et Windows traversal
                @"/etc/passwd", @"c:\\windows\\win.ini",
                @"\b(file|path|filename|filepath)=.*?\.\./", // paramètre typique
                @"\.\./[a-z0-9_\-]+/\.\./", // double traversal
                @"/\.git/", @"/\.svn/", @"/\.env", // fichiers cachés fréquents
            };

        foreach (var pattern in patterns)
        {
            if (Regex.IsMatch(decoded, pattern, RegexOptions.IgnoreCase))
            {
                matchedPattern = pattern;
                return true;
            }
        }

        return false;
    }
}
