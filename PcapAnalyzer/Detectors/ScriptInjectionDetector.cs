using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class ScriptInjectionDetector
{
    public List<ScriptInjectionModel> DetectScriptInjectionAttacks(int packetCount, List<ScriptInjectionModel> scriptInjectionTracker)
    {
        var detectedAttempts = new List<ScriptInjectionModel>();

        foreach (var attempt in scriptInjectionTracker)
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de script injection' ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de scripts injectés :\n");

        if (result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucun script injecté détecté dans le fichier PCAP.");
        }
        else
        {
            foreach (var script in result.DetectedScripts)
            {
                Console.WriteLine($"Script injecté potentiel détecté :");
                Console.WriteLine($"IP Source : {script.SourceIP}");
                Console.WriteLine($"IP Destination : {script.DestinationIP}");
                Console.WriteLine($"Port Destination : {script.DestinationPort}");
                Console.WriteLine($"Numéro du paquet : {script.PacketNumber}");
                Console.WriteLine($"Date : {script.PacketTime}");
                Console.WriteLine($"Contenu du script : {script.ScriptContent}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
