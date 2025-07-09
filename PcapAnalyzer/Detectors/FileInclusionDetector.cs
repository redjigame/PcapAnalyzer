using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class FileInclusionDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedInclusions = new List<ScriptInjectionModel>();
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

                if (IsFileInclusionAttempt(payload, out string matchedPattern))
                {
                    detectedInclusions.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"File Inclusion ({matchedPattern})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedInclusions
        };

        DisplayResults(result);
        return result;
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
    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection d'inclusion de fichier :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune tentative d'inclusion de fichier détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"Inclusion détectée ({attempt.ScriptType}) :");
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
