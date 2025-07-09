using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using SharpPcap;
using PacketDotNet;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class DirectoryEnumDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        try
        {
            var dirEnumTracker = new Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel>();
            int packetCount = 0;

            using (var captureFileReader = new CaptureFileReaderDevice(pcapFile))
            {
                captureFileReader.Open();

                Console.WriteLine($"Analyse du fichier pour tentatives de force brute : {pcapFile}");

                captureFileReader.OnPacketArrival += new PacketArrivalEventHandler((sender, e) =>
                {
                    packetCount++;

                    var rawCapture = e.GetPacket();

                    var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                    var tcpPacket = packet.Extract<TcpPacket>();

                    if (tcpPacket != null)
                    {
                        var ipPacket = packet.Extract<IPPacket>();
                        string srcIP = ipPacket.SourceAddress.ToString();
                        string dstIP = ipPacket.DestinationAddress.ToString();
                        int dstPort = tcpPacket.DestinationPort;

                        if (tcpPacket.PayloadData.Length > 0 && (dstPort == 80 || dstPort == 443 || BruteForceDetector.IsHttpRequest(tcpPacket.PayloadData)))
                        {
                            string payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);

                            if (IsDirectoryBruteForceRequest(payload, out string userAgent, out string requestedUrl))
                            {
                                var key = (srcIP, dstIP, dstPort);
                                if (!dirEnumTracker.ContainsKey(key))
                                {
                                    dirEnumTracker[key] = new DirectoryEnumerationModel
                                    {
                                        SourceIP = srcIP,
                                        DestinationIP = dstIP,
                                        DestinationPort = dstPort,
                                        RequestCount = 0,
                                        FirstRequestTime = rawCapture.Timeval.Date,
                                        LastRequestTime = rawCapture.Timeval.Date,
                                        UserAgent = userAgent
                                    };
                                }

                                dirEnumTracker[key].RequestCount++;
                                dirEnumTracker[key].LastRequestTime = rawCapture.Timeval.Date;
                                dirEnumTracker[key].RequestedUrls.Add(requestedUrl);
                                dirEnumTracker[key].PacketNumbers.Add(packetCount);
                            }
                        }

                    }
                });

                captureFileReader.Capture();

                captureFileReader.Close();
            }

            var result = new AnalysisResultModel
            {
                TotalPackets = packetCount,
                DetectedDirBruteForces = DetectDirectoryBruteForceAttempts(dirEnumTracker)
            };

            DisplayResults(result);

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse des tentatives de force brute : {ex.Message}");
            return new AnalysisResultModel { TotalPackets = 0 };
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


    private List<DirectoryEnumerationModel> DetectDirectoryBruteForceAttempts(Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel> dirBruteEnumTracker)
    {
        var detectedAttempts = new List<DirectoryEnumerationModel>();

        foreach (var attempt in dirBruteEnumTracker.Values)
        {
            var duration = (attempt.LastRequestTime - attempt.FirstRequestTime).TotalSeconds;

            if (attempt.RequestCount > 50 && duration > 0 && duration < 60 || IsFuzzingPattern(attempt.RequestedUrls))
            {
                detectedAttempts.Add(attempt);
            }
        }

        return detectedAttempts;
    }

    private bool IsFuzzingPattern(List<string> urls)
    {
        var basePaths = urls
            .Select(url => Regex.Replace(url, @"\d+", ""))
            .GroupBy(path => path)
            .Where(g => g.Count() >= 5);

        return basePaths.Any();
    }

    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de directory enumeration :\n");

        if (result.DetectedDirBruteForces == null || result.DetectedAttempts.Count == 0)
        {
            Console.WriteLine("Aucune tentative de directory enumeration détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedDirBruteForces)
            {
                var duration = (attempt.LastRequestTime - attempt.FirstRequestTime).TotalSeconds;
                double attemptsPerSecond = duration > 0 ? attempt.RequestCount / duration : attempt.RequestCount;

                Console.WriteLine($"Tentative d'énumération de directory détectée :");
                Console.WriteLine($"IP Source : {attempt.SourceIP}");
                Console.WriteLine($"IP Destination : {attempt.DestinationIP}");
                Console.WriteLine($"Port Destination : {attempt.DestinationPort}");
                Console.WriteLine($"Nombre de tentatives : {attempt.UserAgent}");
                Console.WriteLine($"Nombre de requêtes : {attempt.RequestCount}");
                Console.WriteLine($"URLs demandées : {string.Join(", ", attempt.RequestedUrls)}");
                Console.WriteLine($"Numéros des paquets : {string.Join(", ", attempt.PacketNumbers)}");
                Console.WriteLine($"Durée : {duration:F2} secondes");
                Console.WriteLine($"Taux : {attemptsPerSecond:F2} tentatives/seconde");
                Console.WriteLine($"Période : {attempt.FirstRequestTime} - {attempt.LastRequestTime}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
