using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class SsrfDetector
{
    public List<ScriptInjectionModel> DetectSsrfAttacks(int packetCount, List<ScriptInjectionModel> ssrfTracker)
    {
        var detectedAttempts = new List<ScriptInjectionModel>();

        foreach (var attempt in ssrfTracker)
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'injection SSRF' ===");
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
