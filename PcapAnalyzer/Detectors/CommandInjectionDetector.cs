using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class CommandInjectionDetector
{
    public List<ScriptInjectionModel> DetectCmdInjecAttempts(string payload, Dictionary<(string SrcIP, string DstIP, int DstPort), ScriptInjectionModel> attemptTracker)
    {
        var detectedAttempts = new List<ScriptInjectionModel>();

        if (IsCommandInjectionPayload(payload, out string pattern))
        {
            foreach (var attempt in attemptTracker.Values)
            {
                detectedAttempts.Add(attempt);
            }
        }
        return detectedAttempts;
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

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des scripts injectés ===");
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
