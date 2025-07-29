using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class SsrfAnalyzer
{
    private readonly HashSet<int> SuspiciousPorts = new() { 22, 25, 80, 443, 3306, 6379, 8000, 8080, 8443, 5000, 5001, 27017, 11211 };
    private readonly string[] SuspiciousExtensions = { ".exe", ".bat", ".vbs", ".dll" };

    public void SsrfAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, List<ScriptInjectionModel> ssrfTracker)
    {
        if (IsSsrfAttempt(payload, tcp.DestinationPort, out string matchedPattern))
        {
            ssrfTracker.Add(new ScriptInjectionModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = srcPort,
                ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                PacketNumber = packetCount,
                PacketTime = date,
                ScriptType = $"SSRF ({matchedPattern})"
            });
        }
    }

    private bool IsSsrfAttempt(string payload, int dstPort, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string decoded = Uri.UnescapeDataString(payload.ToLowerInvariant());

        string[] patterns =
        {
                @"(localhost|127\.0\.0\.1|::1)",
                @"169\.254\.169\.254",               // AWS metadata
                @"metadata\.google\.internal",          // GCP metadata
                @"internal\..*?\.com",
                @"http://\d+\.\d+\.\d+\.\d+",
                @"url=http://",
                @"uri=http://",
                @"target=http://",
                @"dest=http://",
            };

        foreach (var pattern in patterns)
        {
            if (Regex.IsMatch(decoded, pattern, RegexOptions.IgnoreCase))
            {
                matchedPattern = pattern;
                return true;
            }
        }

        foreach (var ext in SuspiciousExtensions)
        {
            if (decoded.Contains(ext))
            {
                matchedPattern = $"suspicious_file:{ext}";
                return true;
            }
        }

        if (SuspiciousPorts.Contains(dstPort) && decoded.Contains("http"))
        {
            matchedPattern = $"port:{dstPort}";
            return true;
        }

        return false;
    }
}
