using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;


namespace PcapAnalyzer.Detectors;

public class SsrfDetector
{
    private readonly HashSet<int> SuspiciousPorts = new() { 22, 25, 80, 443, 3306, 6379, 8000, 8080, 8443, 5000, 5001, 27017, 11211 };
    private readonly string[] SuspiciousExtensions = { ".exe", ".bat", ".vbs", ".dll" };

    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedSsrf = new List<ScriptInjectionModel>();
        int packetCount = 0;

        using var reader = new CaptureFileReaderDevice(pcapFile);
        reader.Open();

        reader.OnPacketArrival += (sender, e) =>
        {
            packetCount++;

            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var tcp = packet.Extract<TcpPacket>();
            var ip = packet.Extract<IPPacket>();

            if (tcp?.PayloadData != null && ip != null && tcp.PayloadData.Length > 0)
            {
                string payload = System.Text.Encoding.UTF8.GetString(tcp.PayloadData);

                if (IsSsrfAttempt(payload, tcp.DestinationPort, out string matchedPattern))
                {
                    detectedSsrf.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"SSRF ({matchedPattern})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedSsrf
        };

        DisplayResults(result);
        return result;
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

    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection SSRF :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune tentative SSRF détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"SSRF détecté ({attempt.ScriptType}) :");
                Console.WriteLine($"IP Source : {attempt.SourceIP}");
                Console.WriteLine($"IP Destination : {attempt.DestinationIP}");
                Console.WriteLine($"Port Destination : {attempt.DestinationPort}");
                Console.WriteLine($"Contenu suspect : {attempt.ScriptContent}");
                Console.WriteLine($"Numéro du paquet : {attempt.PacketNumber}");
                Console.WriteLine($"Horodatage : {attempt.PacketTime}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
