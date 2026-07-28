using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class JwtAttackDetector
{
    public List<ScriptInjectionModel> DetectJwtAttacks(int packetCount, List<ScriptInjectionModel> attemptTracker)
    {
        var detectedAttempts = new List<ScriptInjectionModel>();

        foreach (var attempt in attemptTracker)
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'attaque JWT' ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection JWT :\n");

        if (result.DetectedScripts == null || result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucune attaque JWT détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedScripts)
            {
                Console.WriteLine($"JWT Attack détectée ({attempt.ScriptType}) :");
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
