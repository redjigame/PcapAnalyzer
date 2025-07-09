using SharpPcap.LibPcap;
using SharpPcap;
using PacketDotNet;
using PcapAnalyzer.Models;
using PcapAnalyzer.Parsers;

namespace PcapAnalyzer.Detectors;

public class SqlManipulationDetector
{
    private readonly TdsParserLite parser = new();

    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        try
        {
            var sqlChanges = new List<SqlManipulationModel>();
            int packetCount = 0;

            using (var captureFileReader = new CaptureFileReaderDevice(pcapFile))
            {
                captureFileReader.Open();

                Console.WriteLine($"Analyse du fichier pour tentatives de manipulation SQL : {pcapFile}");

                captureFileReader.OnPacketArrival += new PacketArrivalEventHandler((sender, e) =>
                {
                    packetCount++;

                    var rawCapture = e.GetPacket();
                    var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                    var tcpPacket = packet.Extract<TcpPacket>();
                    var ipPacket = packet.Extract<IPPacket>();

                    if (tcpPacket == null || ipPacket == null || tcpPacket.PayloadData.Length == 0)
                        return;

                    string srcIP = ipPacket.SourceAddress.ToString();
                    string dstIP = ipPacket.DestinationAddress.ToString();
                    int srcPort = tcpPacket.SourcePort;
                    int dstPort = tcpPacket.DestinationPort;
                    byte[] payload = tcpPacket.PayloadData;

                    if (TdsParserLite.IsTlsEncrypted(payload))
                        return;

                    parser.AddTcpPayloadFragment(srcIP, srcPort, dstIP, dstPort, payload);

                    bool isTdsMessageComplete;
                    byte[] message = parser.GetCompleteMessage(srcIP, srcPort, dstIP, dstPort, out isTdsMessageComplete);
                    if (!isTdsMessageComplete || message == null) return;

                    string sql = TdsParserLite.ExtractSqlBatch(message);
                    bool isInjection = IsSqlInjectionAttempt(sql);
                    if (IsConfigurationChange(sql) || IsSqlInjectionAttempt(sql))
                    {
                        sqlChanges.Add(new SqlManipulationModel
                        {
                            SourceIP = srcIP,
                            DestinationIP = dstIP,
                            DestinationPort = dstPort,
                            SqlCommand = (isInjection ? "[SQLi ?] " : "") + (sql.Length > 100 ? sql[..100] + "..." : sql),
                            PacketTime = rawCapture.Timeval.Date,
                            PacketNumber = packetCount
                        });
                    }

                    string rpc = TdsParserLite.ExtractRpcProcedure(message);
                    if (!string.IsNullOrWhiteSpace(rpc) && IsConfigurationChange(rpc))
                    {
                        bool isRpcInjection = IsSqlInjectionAttempt(rpc);
                        sqlChanges.Add(new SqlManipulationModel
                        {
                            SourceIP = srcIP,
                            DestinationIP = dstIP,
                            DestinationPort = dstPort,
                            SqlCommand = "[RPC] " + (isRpcInjection ? "[SQLi ?] " : "") + rpc,
                            PacketTime = rawCapture.Timeval.Date,
                            PacketNumber = packetCount
                        });
                    }
                });

                captureFileReader.Capture();

                captureFileReader.Close();
            }

            var result = new AnalysisResultModel
            {
                TotalPackets = packetCount,
                DetectedSqlChanges = sqlChanges,
            };

            DisplayResults(result);

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse des tentatives de force brute : {ex.Message}");
            return new AnalysisResultModel { TotalPackets = 0 };
        }
    }

    private bool IsConfigurationChange(string sqlCommand)
    {
        if (string.IsNullOrEmpty(sqlCommand)) return false;

        string[] configKeywords = { "sp_configure", "ALTER DATABASE", "ALTER SERVER", "RECONFIGURE", "CREATE DATABASE", "DROP DATABASE", "GRANT", "REVOKE", "CREATE LOGIN", "DROP LOGIN", "ALTER LOGIN", "UPDATE ", "DELETE ", "TRUNCATE " };
        foreach (var keyword in configKeywords)
        {
            if (sqlCommand.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private bool IsSqlInjectionAttempt(string sql)
    {
        if (string.IsNullOrWhiteSpace(sql))
            return false;

        // Normalisation
        string normalized = sql.ToLowerInvariant();

        // Motifs typiques d'injection
        string[] injectionPatterns =
        {
        "' or '1'='1", "\" or \"1\"=\"1", "' or 1=1--", "\" or 1=1--",
        "union select", "waitfor delay", "xp_cmdshell", "exec master..xp_",
        "--", "#", "'--", "'#", "\"--", "\"#", ";--", ";#"
    };

        foreach (var pattern in injectionPatterns)
        {
            if (normalized.Contains(pattern))
                return true;
        }

        // Heuristique simple : trop de quotes/points-virgules
        int quoteCount = normalized.Count(c => c == '\'' || c == '\"');
        int semiColonCount = normalized.Count(c => c == ';');

        if (quoteCount > 5 || semiColonCount > 3)
            return true;

        return false;
    }

    private void DisplayResults(AnalysisResultModel result)
    {
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
