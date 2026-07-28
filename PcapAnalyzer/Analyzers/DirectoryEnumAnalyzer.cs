using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class DirectoryEnumAnalyzer
{
    public void DirEnumAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel> dirBruteEnumTracker, TcpPacket tcp, string payload)
    {
        if (tcp.PayloadData.Length > 0 && (dstPort == 80 || dstPort == 443 || Analyzer.IsHttpRequest(tcp.PayloadData)))
        {
            if (IsDirectoryBruteForceRequest(payload, out string userAgent, out string requestedUrl))
            {
                var key = (srcIP, dstIP, dstPort);
                if (!dirBruteEnumTracker.ContainsKey(key))
                {
                    dirBruteEnumTracker[key] = new DirectoryEnumerationModel
                    {
                        SourceIP = srcIP,
                        DestinationIP = dstIP,
                        DestinationPort = dstPort,
                        RequestCount = 0,
                        FirstRequestTime = date,
                        LastRequestTime = date,
                        UserAgent = userAgent
                    };
                }

                dirBruteEnumTracker[key].RequestCount++;
                dirBruteEnumTracker[key].LastRequestTime = date;
                dirBruteEnumTracker[key].RequestedUrls.Add(requestedUrl);
                dirBruteEnumTracker[key].PacketNumbers.Add(packetCount);
            }
        }
    }

    private bool IsDirectoryBruteForceRequest(string payload, out string userAgent, out string requestedUrl)
    {
        userAgent = null;
        requestedUrl = null;
        int suspicionScore = 0;

        string getPattern = @"^(GET|HEAD)\s+([^\s]+)\s+HTTP/";
        var match = Regex.Match(payload, getPattern, RegexOptions.IgnoreCase);
        if (!match.Success) return false;

        requestedUrl = match.Groups[2].Value;

        var userAgentMatch = Regex.Match(payload, @"User-Agent:\s*([^\r\n]+)", RegexOptions.IgnoreCase);
        if (userAgentMatch.Success)
        {
            userAgent = userAgentMatch.Groups[1].Value.Trim();

            if (userAgent.Contains("gobuster/", StringComparison.OrdinalIgnoreCase) ||
                userAgent.Contains("DirBuster-", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        string[] commonPaths = { "/admin", "/login", "/config", "/backup", "/test", "/phpinfo", ".php", ".txt", ".bak" };
        foreach (var path in commonPaths)
        {
            if (requestedUrl.Contains(path, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
