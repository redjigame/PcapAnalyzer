using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class FileInclusionAnalyzer
{
    public void FileInclusAnalyeze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, List<ScriptInjectionModel> detectedFileInclusion)
    {
        if (IsFileInclusionAttempt(payload, out string matchedPattern))
        {
            detectedFileInclusion.Add(new ScriptInjectionModel
            {
                SourceIP = ip.SourceAddress.ToString(),
                DestinationIP = ip.DestinationAddress.ToString(),
                DestinationPort = tcp.DestinationPort,
                ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                PacketNumber = packetCount,
                PacketTime = date,
                ScriptType = $"File Inclusion ({matchedPattern})"
            });
        }
    }

    private bool IsFileInclusionAttempt(string payload, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string decoded = Uri.UnescapeDataString(payload.ToLowerInvariant());

        string[] patterns =
        {
                // PHP patterns
                @"\.\./\.\./", @"/etc/passwd", @"c:\\windows\\win.ini",
                @"php://input", @"php://filter", @"data:text/plain", @"expect://",
                @"file=", @"include=", @"require=", @"page=", @"inc=", @"view=", @"template=",
                @"\.php", @"\.phtml",

                // JSP patterns
                @"jspfile=", @"\.jsp", @"\.jspx",

                // ASP.NET patterns
                @"\.asp", @"\.aspx", @"\.cshtml", @"\.vbhtml", @"web\.config"
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
