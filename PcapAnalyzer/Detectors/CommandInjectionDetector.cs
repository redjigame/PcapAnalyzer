using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;

namespace PcapAnalyzer.Detectors;

public class CommandInjectionDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedInjections = new List<ScriptInjectionModel>();
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
                string payload = Encoding.UTF8.GetString(tcp.PayloadData);

                if (IsCommandInjectionPayload(payload, out string pattern))
                {
                    detectedInjections.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"Command Injection ({pattern})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedInjections
        };

        DisplayResults(result);
        return result;
    }

    private bool IsCommandInjectionPayload(string payload, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string decoded = Uri.UnescapeDataString(payload.ToLowerInvariant());

        string[] patterns =
        {
            @";\s*(ls|whoami|id|pwd|dir|cat|ping|curl|wget)",
            @"&&\s*", @"\$\((.*?)\)",
            @"`.*?`",
            @"bash -i", @"sh -i", @"nc ", @"/bin/sh", @"python -c", @"perl -e"
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
        Console.WriteLine("Résultats de détection d'injection de commande :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune tentative d'injection de commande détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"Injection détectée ({attempt.ScriptType}) :");
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
