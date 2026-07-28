using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class SqlManipulationDetector
{
    public List<SqlManipulationModel> DetectSqlManipulationAttacks(int packetCount, List<SqlManipulationModel> sqlManipulationTracker)
    {
        var detectedAttempts = new List<SqlManipulationModel>();

        foreach (var attempt in sqlManipulationTracker)
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de manipulation SQL' ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de manipulations SQL sensibles :\n");

        if (result.DetectedSqlChanges == null || result.DetectedSqlChanges.Count == 0)
        {
            Console.WriteLine("Aucune manipulation SQL critique détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var change in result.DetectedSqlChanges)
            {
                Console.WriteLine("Changement de configuration SQL détecté :");
                Console.WriteLine($"IP Source : {change.SourceIP}");
                Console.WriteLine($"IP Destination : {change.DestinationIP}");
                Console.WriteLine($"Port Destination : {change.DestinationPort}");
                Console.WriteLine($"Commande SQL : {change.SqlCommand}");
                Console.WriteLine($"Heure : {change.PacketTime}");
                Console.WriteLine($"Numéro du paquet : {change.PacketNumber}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
