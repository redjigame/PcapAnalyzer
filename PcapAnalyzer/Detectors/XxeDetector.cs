using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class XxeDetector
{
    public List<ScriptInjectionModel> DetectXxefAttacks(int packetCount, List<ScriptInjectionModel> xxeTracker)
    {
        var detectedAttempts = new List<ScriptInjectionModel>();

        foreach (var attempt in xxeTracker)
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'injection XXE' ===");
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
