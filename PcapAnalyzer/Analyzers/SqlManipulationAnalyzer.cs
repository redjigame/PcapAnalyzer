using PacketDotNet;
using PcapAnalyzer.Models;
using PcapAnalyzer.Parsers;

namespace PcapAnalyzer.Analyzers;

public class SqlManipulationAnalyzer
{
    private readonly TdsParserLite parser = new();

    public void SqlManipulationAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, byte[] payload, List<SqlManipulationModel> detectedManipulations)
    {
        var sqlChanges = new List<SqlManipulationModel>();

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
                PacketTime = date,
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
                PacketTime = date,
                PacketNumber = packetCount
            });
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
}
