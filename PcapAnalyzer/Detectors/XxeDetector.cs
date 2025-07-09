using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;
using System.Text;

namespace PcapAnalyzer.Detectors;

public class XxeDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedXxe = new List<ScriptInjectionModel>();
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

                if (IsXxePattern(payload, out string matchedPattern))
                {
                    detectedXxe.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"XXE ({matchedPattern})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedXxe
        };

        DisplayResults(result);
        return result;
    }

    private bool IsXxePattern(string payload, out string matchedPattern)
    {
        matchedPattern = null;
        if (string.IsNullOrWhiteSpace(payload)) return false;

        string lowerPayload = payload.ToLowerInvariant();

        if (lowerPayload.Contains("<!doctype html"))
            return false;

        string[] patterns =
        {
                "<!DOCTYPE",
                "<!ENTITY",
                "SYSTEM \"file://",
                "SYSTEM \"http://",
                "SYSTEM \"ftp://",
                "><!ENTITY",
                "<!ELEMENT",
                "<!ATTLIST"
            };

        foreach (var pattern in patterns)
        {
            if (Regex.IsMatch(payload, pattern, RegexOptions.IgnoreCase))
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
        Console.WriteLine("Résultats de détection XXE :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune tentative XXE détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"XXE détecté ({attempt.ScriptType}) :");
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
