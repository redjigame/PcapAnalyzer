using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using System.Text;
using System.Text.RegularExpressions;
using PacketDotNet;
using SharpPcap;
using PcapAnalyzer.Parsers;

namespace PcapAnalyzer.Detectors;

public class DataLeakDetector
{
    private readonly TdsParserLite parser = new();
    private readonly HashSet<int> knownSqlPorts = new() { 1433 , 1434, 2433, 2434 }; // Ports SQL Server courants
    private readonly Dictionary<string, StringBuilder> tcpStreams = new();

    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedLeaks = new List<DataLeakModel>();
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
                string srcIP = ip.SourceAddress.ToString();
                string dstIP = ip.DestinationAddress.ToString();
                int srcPort = tcp.SourcePort;
                int dstPort = tcp.DestinationPort;
                byte[] payload = tcp.PayloadData;

                if (knownSqlPorts.Contains(srcPort) || knownSqlPorts.Contains(dstPort))
                {
                    AnalyzeTdsTraffic(srcIP, srcPort, dstIP, dstPort, payload, packetCount, raw.Timeval.Date, detectedLeaks);
                }
                else
                {
                    // Analyse du trafic HTTP/HTTPS et autres protocoles
                    AnalyzeGenericTraffic(srcIP, srcPort, dstIP, dstPort, payload, packetCount, raw.Timeval.Date, detectedLeaks);
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DataLeaks = detectedLeaks
        };

        DisplayResults(result);
        return result;
    }

    private bool IsPotentialLeak(string content, out string matchType)
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

    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection d’exfiltration de données :\n");

        if (result.DataLeaks == null || result.DataLeaks.Count == 0)
        {
            Console.WriteLine("Aucune fuite de données détectée dans le fichier PCAP.");
        }
        else
        {
            foreach (var attempt in result.DataLeaks)
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

    private void AnalyzeTdsTraffic(string srcIP, int srcPort, string dstIP, int dstPort,
        byte[] payload, int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        try
        {
            parser.AddTcpPayloadFragment(srcIP, srcPort, dstIP, dstPort, payload);

            byte[] fullMessage = parser.GetCompleteMessage(srcIP, srcPort, dstIP, dstPort, out bool isComplete);

            byte[] messageToAnalyze = isComplete && fullMessage != null ? fullMessage : payload;

            var header = TdsParserLite.ParseHeader(messageToAnalyze);
            if (header != null)
            {
                switch (header.Type)
                {
                    case TdsPacketType.Login:
                        AnalyzeTdsLogin(messageToAnalyze, srcIP, dstIP, dstPort, packetCount, packetTime, detectedLeaks);
                        break;

                    case TdsPacketType.SQLBatch:
                        AnalyzeTdsSqlBatch(messageToAnalyze, srcIP, dstIP, dstPort, packetCount, packetTime, detectedLeaks);
                        break;

                    case TdsPacketType.TabularResult:
                        AnalyzeTdsTabularResult(messageToAnalyze, srcIP, dstIP, dstPort, packetCount, packetTime, detectedLeaks);
                        break;

                    default:
                        AnalyzeTdsGeneric(messageToAnalyze, header.Type, srcIP, dstIP, dstPort, packetCount, packetTime, detectedLeaks);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse TDS: {ex.Message}");
        }
    }

    private void AnalyzeTdsLogin(byte[] message, string srcIP, string dstIP, int dstPort,
        int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        var (username, password) = TdsParserLite.ExtractLoginCredentials(message);

        if (!string.IsNullOrWhiteSpace(username) || !string.IsNullOrWhiteSpace(password))
        {
            string data = $"User: {username ?? "N/A"}, Pass: {password ?? "N/A"}";

            detectedLeaks.Add(new DataLeakModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                PacketNumber = packetCount,
                PacketTime = packetTime,
                LeakType = "TDS Login Credentials",
                SuspiciousContent = data
            });
        }
    }

    private void AnalyzeTdsSqlBatch(byte[] message, string srcIP, string dstIP, int dstPort,
        int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        try
        {
            string sqlQuery = Encoding.UTF8.GetString(message).Trim();

            // Détection de requêtes SQL potentiellement sensibles
            if (IsSensitiveSqlQuery(sqlQuery))
            {
                detectedLeaks.Add(new DataLeakModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    PacketNumber = packetCount,
                    PacketTime = packetTime,
                    LeakType = "TDS Sensitive SQL Query",
                    SuspiciousContent = sqlQuery.Length > 150 ? sqlQuery[..150] + "..." : sqlQuery
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse SQL Batch: {ex.Message}");
        }
    }

    private void AnalyzeTdsTabularResult(byte[] message, string srcIP, string dstIP, int dstPort,
        int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        try
        {
            string resultData = Encoding.UTF8.GetString(message);

            // Recherche de données sensibles dans les résultats
            if (IsPotentialLeak(resultData, out string matchType))
            {
                detectedLeaks.Add(new DataLeakModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    PacketNumber = packetCount,
                    PacketTime = packetTime,
                    LeakType = $"TDS Result Data ({matchType})",
                    SuspiciousContent = resultData.Length > 150 ? resultData[..150] + "..." : resultData
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse des résultats tabulaires: {ex.Message}");
        }
    }

    private void AnalyzeTdsGeneric(byte[] message, TdsPacketType packetType, string srcIP, string dstIP,
        int dstPort, int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        try
        {
            string content = Encoding.UTF8.GetString(message);

            if (IsPotentialLeak(content, out string matchType))
            {
                detectedLeaks.Add(new DataLeakModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    PacketNumber = packetCount,
                    PacketTime = packetTime,
                    LeakType = $"TDS {packetType} ({matchType})",
                    SuspiciousContent = content.Length > 150 ? content[..150] + "..." : content
                });
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse TDS générique: {ex.Message}");
        }
    }

    private bool IsSensitiveSqlQuery(string sqlQuery)
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

    private void AnalyzeGenericTraffic(string srcIP, int srcPort, string dstIP, int dstPort,
        byte[] payload, int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        string content = Encoding.UTF8.GetString(payload);

        if (IsPotentialLeak(content, out string matchType))
        {
            detectedLeaks.Add(new DataLeakModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                SuspiciousContent = content.Length > 150 ? content[..150] + "..." : content,
                PacketNumber = packetCount,
                PacketTime = packetTime,
                LeakType = $"Generic Traffic ({matchType})"
            });
        }
    }
}
