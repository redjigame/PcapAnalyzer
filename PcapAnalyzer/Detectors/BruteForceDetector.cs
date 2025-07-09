using SharpPcap.LibPcap;
using SharpPcap;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class BruteForceDetector
{
    private readonly HashSet<int> knownSqlPorts = new() { 1433, 1434, 2433, 2434 }; // Ports SQL Server courants

    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        try
        {
            var attemptTracker = new Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel>();
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
                        if (ipPacket != null)
                        {
                            string srcIP = ipPacket.SourceAddress.ToString();
                            string dstIP = ipPacket.DestinationAddress.ToString();
                            int dstPort = tcpPacket.DestinationPort;

                            if (dstPort == 22 && (tcpPacket.Flags & 0x02) == 0x02 && (tcpPacket.Flags & 0x10) == 0) // SYN sans ACK
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
                                        FirstAttemptTime = rawCapture.Timeval.Date,
                                        LastAttemptTime = rawCapture.Timeval.Date,
                                        Protocol = "SSH"
                                    };
                                }

                                attemptTracker[key].AttemptCount++;
                                attemptTracker[key].LastAttemptTime = rawCapture.Timeval.Date;
                                attemptTracker[key].PacketNumbers.Add(packetCount);
                            }

                            // Détection pour TDS (port 1433, paquets SYN)
                            if (dstPort == 1433)
                            {
                                if ((tcpPacket.Flags & 0x02) == 0x02 && (tcpPacket.Flags & 0x10) == 0)
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
                                            FirstAttemptTime = rawCapture.Timeval.Date,
                                            LastAttemptTime = rawCapture.Timeval.Date,
                                            Protocol = "TDS"
                                        };
                                    }

                                    attemptTracker[key].AttemptCount++;
                                    attemptTracker[key].LastAttemptTime = rawCapture.Timeval.Date;
                                    attemptTracker[key].PacketNumbers.Add(packetCount);
                                }
                            }

                            if (tcpPacket.PayloadData.Length > 0 && (dstPort == 80 || IsHttpRequest(tcpPacket.PayloadData)))
                            {
                                string payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);
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
                                            FirstAttemptTime = rawCapture.Timeval.Date,
                                            LastAttemptTime = rawCapture.Timeval.Date,
                                            Protocol = "HTTP",
                                            TargetUrl = targetUrl
                                        };
                                    }

                                    attemptTracker[key].AttemptCount++;
                                    attemptTracker[key].LastAttemptTime = rawCapture.Timeval.Date;
                                    attemptTracker[key].PacketNumbers.Add(packetCount);
                                }
                            }

                            if (tcpPacket.PayloadData.Length > 0 && (dstPort == 80 || dstPort == 443 || IsHttpRequest(tcpPacket.PayloadData)))
                            {
                                string payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);

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
                                            FirstAttemptTime = rawCapture.Timeval.Date,
                                            LastAttemptTime = rawCapture.Timeval.Date,
                                            Protocol = "HTTP",
                                            TargetUrl = targetUrl
                                        };
                                    }

                                    attemptTracker[key].AttemptCount++;
                                    attemptTracker[key].LastAttemptTime = rawCapture.Timeval.Date;
                                    attemptTracker[key].PacketNumbers.Add(packetCount);
                                }
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
                DetectedAttempts = DetectBruteForceAttempts(attemptTracker),
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

    public static bool IsHttpRequest(byte[] payload)
    {
        if (payload.Length < 4) return false;
        string header = Encoding.ASCII.GetString(payload, 0, Math.Min(4, payload.Length));
        return header.StartsWith("POST") || header.StartsWith("GET");
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

    private List<BruteForceModel> DetectBruteForceAttempts(Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
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

    private void DisplayResults(AnalysisResultModel result)
    {
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
