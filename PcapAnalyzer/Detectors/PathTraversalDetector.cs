using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class PathTraversalDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedTraversals = new List<ScriptInjectionModel>();
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

                if (IsPathTraversalAttempt(payload, out string matchedPattern))
                {
                    detectedTraversals.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"Path Traversal ({matchedPattern})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedTraversals
        };

        DisplayResults(result);
        return result;
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

    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de path traversal :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune tentative de path traversal détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"Path traversal détecté ({attempt.ScriptType}) :");
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
