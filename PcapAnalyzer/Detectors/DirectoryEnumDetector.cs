using PcapAnalyzer.Models;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class DirectoryEnumDetector
{
    public List<DirectoryEnumerationModel> DetectDirectoryBruteForceAttempts(Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel> dirBruteEnumTracker)
    {
        var detectedAttempts = new List<DirectoryEnumerationModel>();

        foreach (var attempt in dirBruteEnumTracker.Values)
        {
            var duration = (attempt.LastRequestTime - attempt.FirstRequestTime).TotalSeconds;

            if (attempt.RequestCount > 50 && duration > 0 && duration < 60 || IsFuzzingPattern(attempt.RequestedUrls))
            {
                detectedAttempts.Add(attempt);
            }
        }

        return detectedAttempts;
    }

    private bool IsFuzzingPattern(List<string> urls)
    {
        var basePaths = urls
            .Select(url => Regex.Replace(url, @"\d+", ""))
            .GroupBy(path => path)
            .Where(g => g.Count() >= 5);

        return basePaths.Any();
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de enum directory ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de directory enumeration :\n");

        if (result.DetectedDirBruteForces == null || result.DetectedAttempts.Count == 0)
        {
            Console.WriteLine("Aucune tentative de directory enumeration détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedDirBruteForces)
            {
                var duration = (attempt.LastRequestTime - attempt.FirstRequestTime).TotalSeconds;
                double attemptsPerSecond = duration > 0 ? attempt.RequestCount / duration : attempt.RequestCount;

                Console.WriteLine($"Tentative d'énumération de directory détectée :");
                Console.WriteLine($"IP Source : {attempt.SourceIP}");
                Console.WriteLine($"IP Destination : {attempt.DestinationIP}");
                Console.WriteLine($"Port Destination : {attempt.DestinationPort}");
                Console.WriteLine($"Nombre de tentatives : {attempt.UserAgent}");
                Console.WriteLine($"Nombre de requêtes : {attempt.RequestCount}");
                Console.WriteLine($"URLs demandées : {string.Join(", ", attempt.RequestedUrls)}");
                Console.WriteLine($"Numéros des paquets : {string.Join(", ", attempt.PacketNumbers)}");
                Console.WriteLine($"Durée : {duration:F2} secondes");
                Console.WriteLine($"Taux : {attemptsPerSecond:F2} tentatives/seconde");
                Console.WriteLine($"Période : {attempt.FirstRequestTime} - {attempt.LastRequestTime}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }
}
