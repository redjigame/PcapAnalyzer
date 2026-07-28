using System.Text.RegularExpressions;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class BruteForceDetector
{
    public void AnalyzeTdsTraffic(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime packetTime, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        if (dstPort == 1433)
        {
            var key = (srcIP, dstIP, dstPort, "TDS");
            if (!attemptTracker.ContainsKey(key))
            {
                attemptTracker[key] = new BruteForceModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    AttemptCount = 0,
                    FirstAttemptTime = packetTime,
                    LastAttemptTime = packetTime,
                    Protocol = "TDS"
                };
            }

            attemptTracker[key].AttemptCount++;
            attemptTracker[key].LastAttemptTime = packetTime;
            attemptTracker[key].PacketNumbers.Add(packetCount);
        }
    }

    public void AnalyzeSshTraffic(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime packetTime, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        var key = (srcIP, dstIP, dstPort, "SSH");
        if (!attemptTracker.ContainsKey(key))
        {
            attemptTracker[key] = new BruteForceModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                AttemptCount = 0,
                FirstAttemptTime = packetTime,
                LastAttemptTime = packetTime,
                Protocol = "SSH"
            };
        }

        attemptTracker[key].AttemptCount++;
        attemptTracker[key].LastAttemptTime = packetTime;
        attemptTracker[key].PacketNumbers.Add(packetCount);
    }

    public void AnalyzeHttpTraffic(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime packetTime, string payload, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        if (IsLoginPostRequest(payload, out string targetUrl))
        {
            var key = (srcIP, dstIP, dstPort, "HTTP");
            if (!attemptTracker.ContainsKey(key))
            {
                attemptTracker[key] = new BruteForceModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    AttemptCount = 0,
                    FirstAttemptTime = packetTime,
                    LastAttemptTime = packetTime,
                    Protocol = "HTTP",
                    TargetUrl = targetUrl
                };
            }

            attemptTracker[key].AttemptCount++;
            attemptTracker[key].LastAttemptTime = packetTime;
            attemptTracker[key].PacketNumbers.Add(packetCount);
        }
    }

    public void AnalyzeOtherTraffic(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime packetTime, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        var key = (srcIP, dstIP, dstPort, "Other");
        if (!attemptTracker.ContainsKey(key))
        {
            attemptTracker[key] = new BruteForceModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                AttemptCount = 0,
                FirstAttemptTime = packetTime,
                LastAttemptTime = packetTime,
                Protocol = "Other"
            };
        }

        attemptTracker[key].AttemptCount++;
        attemptTracker[key].LastAttemptTime = packetTime;
        attemptTracker[key].PacketNumbers.Add(packetCount);
    }

    

    private bool IsLoginPostRequest(string payload, out string targetUrl)
    {
        string[] loginPaths = { "/login", "/signin", "/auth", "/authenticate" };
        string postPattern = @"^POST\s+([^\s]+)\s+HTTP/";
        var match = Regex.Match(payload, postPattern, RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string url = match.Groups[1].Value;
            foreach (var path in loginPaths)
            {
                if (url.Contains(path, StringComparison.OrdinalIgnoreCase))
                {
                    if (payload.Contains("username", StringComparison.OrdinalIgnoreCase) ||
                        payload.Contains("password", StringComparison.OrdinalIgnoreCase) ||
                        payload.Contains("user", StringComparison.OrdinalIgnoreCase) ||
                        payload.Contains("pass", StringComparison.OrdinalIgnoreCase))
                    {
                        targetUrl = url;
                        return true;
                    }
                }
            }
        }
        targetUrl = null;
        return false;
    }

    public List<BruteForceModel> DetectBruteForceAttempts(Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        var detectedAttempts = new List<BruteForceModel>();

        foreach (var attempt in attemptTracker.Values)
        {
            var duration = (attempt.LastAttemptTime - attempt.FirstAttemptTime).TotalSeconds;

            if (attempt.AttemptCount > 10 && duration > 0 && duration < 60)
            {
                detectedAttempts.Add(attempt);
            }
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de force brute ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de tentatives de force brute :\n");

        if (result.DetectedAttempts.Count == 0)
        {
            Console.WriteLine("Aucune tentative de force brute détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedAttempts)
            {
                var duration = (attempt.LastAttemptTime - attempt.FirstAttemptTime).TotalSeconds;
                double attemptsPerSecond = attempt.AttemptCount / duration;

                Console.WriteLine($"Tentative de force brute détectée ({attempt.Protocol}) :");
                Console.WriteLine($"IP Source : {attempt.SourceIP}");
                Console.WriteLine($"IP Destination : {attempt.DestinationIP}");
                Console.WriteLine($"Port Destination : {attempt.DestinationPort}");
                if (attempt.Protocol == "HTTP")
                    Console.WriteLine($"URL ciblée : {attempt.TargetUrl}");
                Console.WriteLine($"Nombre de tentatives : {attempt.AttemptCount}");
                Console.WriteLine($"Numéros des paquets : {string.Join(", ", attempt.PacketNumbers)}");
                Console.WriteLine($"Durée : {duration:F2} secondes");
                Console.WriteLine($"Taux : {attemptsPerSecond:F2} tentatives/seconde");
                Console.WriteLine($"Période : {attempt.FirstAttemptTime} - {attempt.LastAttemptTime}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
