using PcapAnalyzer.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Detectors;

public class DataLeakDetector
{
    private readonly Dictionary<string, StringBuilder> tcpStreams = new();

    public List<DataLeakModel> DetectDataLeakAttempts(int packetCount, List<DataLeakModel> attemptTracker)
    {
        var detectedAttempts = new List<DataLeakModel>();

        foreach (var attempt in attemptTracker) // Corrected loop as well
        {
            detectedAttempts.Add(attempt);
        }

        return detectedAttempts;
    }

    public bool IsPotentialLeak(string content, out string matchType)
    {
        matchType = null;
        if (string.IsNullOrWhiteSpace(content)) return false;

        string decoded = Uri.UnescapeDataString(content);

        if (Regex.IsMatch(decoded, @"(?:\D|^)(4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?:\D|$)"))
        {
            matchType = "credit card";
            return true;
        }

        if (Regex.IsMatch(decoded, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"))
        {
            matchType = "email";
            return true;
        }

        if (Regex.IsMatch(decoded, @"(?i)(password|pwd|pass)\s*[=:]\s*[^\s&]{6,}", RegexOptions.IgnoreCase))
        {
            matchType = "password";
            return true;
        }

        if (Regex.IsMatch(decoded, @"(?i)(username|user|login)\s*[=:]\s*[^\s&]{3,}", RegexOptions.IgnoreCase))
        {
            matchType = "username";
            return true;
        }

        if (Regex.IsMatch(decoded, @"(?i)(token|api[_-]?key|secret|auth)\s*[=:]\s*[a-zA-Z0-9+/]{20,}", RegexOptions.IgnoreCase))
        {
            matchType = "API key/token";
            return true;
        }

        // Hashs MD5/SHA1/SHA256 typiques
        if (Regex.IsMatch(decoded, @"[a-f0-9]{32,64}", RegexOptions.IgnoreCase))
        {
            matchType = "hash";
            return true;
        }

        if (Regex.IsMatch(decoded, @"user(name)?=\w+&?(user(name)?=\w+)*", RegexOptions.IgnoreCase))
        {
            matchType = "username list";
            return true;
        }

        return false;
    }

    public void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'exfiltration des données' ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection d’exfiltration de données :\n");

        if (result.DetectedDataLeaks == null || result.DetectedDataLeaks.Count == 0)
        {
            Console.WriteLine("Aucune fuite de données détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DetectedDataLeaks)
            {
                Console.WriteLine($"Fuite potentielle détectée ({attempt.LeakType}) :");
                Console.WriteLine($"IP Source : {attempt.SourceIP}");
                Console.WriteLine($"IP Destination : {attempt.DestinationIP}");
                Console.WriteLine($"Port Destination : {attempt.DestinationPort}");
                Console.WriteLine($"Contenu suspect : {attempt.SuspiciousContent}");
                Console.WriteLine($"Numéro du paquet : {attempt.PacketNumber}");
                Console.WriteLine($"Horodatage : {attempt.PacketTime}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }

    public bool IsSensitiveSqlQuery(string sqlQuery)
    {
        if (string.IsNullOrWhiteSpace(sqlQuery)) return false;

        string query = sqlQuery.ToLowerInvariant();

        // Requêtes potentiellement sensibles
        string[] sensitivePatterns = {
            "select.*password",
            "select.*credit",
            "select.*ssn",
            "select.*social",
            "select.*account",
            "select.*users",
            "select.*admin",
            "union.*select",
            "information_schema",
            "sys.tables",
            "sys.columns"
        };

        return sensitivePatterns.Any(pattern =>
            Regex.IsMatch(query, pattern, RegexOptions.IgnoreCase));
    }

    
}
