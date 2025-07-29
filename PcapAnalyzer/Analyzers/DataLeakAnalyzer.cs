using PcapAnalyzer.Detectors;
using PcapAnalyzer.Models;
using PcapAnalyzer.Parsers;
using System.Text;

namespace PcapAnalyzer.Analyzers;

public class DataLeakAnalyzer
{
    private readonly DataLeakDetector _dataLeakDetector = new DataLeakDetector();

    private readonly HashSet<int> knownSqlPorts = new() { 1433, 1434, 2433, 2434 }; // Ports SQL Server courants
    private readonly TdsParserLite parser = new();

    public void DataLeakAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, byte[] bitPayload, List<DataLeakModel> detectedLeaks)
    {
        if (knownSqlPorts.Contains(srcPort) || knownSqlPorts.Contains(dstPort))
        {
            AnalyzeTdsTraffic(srcIP, srcPort, dstIP, dstPort, bitPayload, packetCount, date, detectedLeaks);
        }
        else
        {
            // Analyse du trafic HTTP/HTTPS et autres protocoles
            AnalyzeGenericTraffic(srcIP, srcPort, dstIP, dstPort, bitPayload, packetCount, date, detectedLeaks);
        }
    }

    private void AnalyzeGenericTraffic(string srcIP, int srcPort, string dstIP, int dstPort,
        byte[] payload, int packetCount, DateTime packetTime, List<DataLeakModel> detectedLeaks)
    {
        string content = Encoding.UTF8.GetString(payload);

        if (_dataLeakDetector.IsPotentialLeak(content, out string matchType))
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
            if (_dataLeakDetector.IsSensitiveSqlQuery(sqlQuery))
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
            if (_dataLeakDetector.IsPotentialLeak(resultData, out string matchType))
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

            if (_dataLeakDetector.IsPotentialLeak(content, out string matchType))
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


}
