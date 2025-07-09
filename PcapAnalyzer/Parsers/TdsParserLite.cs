using System.Text;

namespace PcapAnalyzer.Parsers;

public enum TdsPacketType : byte
{
    SQLBatch = 0x01,
    RPC = 0x03,
    Login = 0x02,
    PreLogin = 0x12,
    TabularResult = 0x04
}

public class TdsHeader
{
    public TdsPacketType Type { get; set; }
    public byte Status { get; set; }
    public ushort Length { get; set; }
    public ushort SPID { get; set; }
    public byte PacketID { get; set; }
    public byte Window { get; set; }
}

public class TdsParserLite
{
    private readonly Dictionary<(string SrcIP, int SrcPort, string DstIP, int DstPort), List<byte>> sessionBuffers = new();

    public static TdsHeader ParseHeader(byte[] payload)
    {
        if (payload == null || payload.Length < 8)
            return null;

        return new TdsHeader
        {
            Type = (TdsPacketType)payload[0],
            Status = payload[1],
            Length = (ushort)((payload[2] << 8) | payload[3]),
            SPID = (ushort)((payload[4] << 8) | payload[5]),
            PacketID = payload[6],
            Window = payload[7]
        };
    }

    public static bool IsTlsEncrypted(byte[] payload)
    {
        return payload.Length > 5 && payload[0] == 0x16 && payload[1] == 0x03;
    }

    public static string ExtractSqlBatch(byte[] payload)
    {
        var header = ParseHeader(payload);
        if (header == null || header.Type != TdsPacketType.SQLBatch)
            return null;

        int offset = 8;

        if (payload.Length >= offset + 4)
        {
            int allHeadersLen = (payload[offset] << 24) | (payload[offset + 1] << 16) |
                                (payload[offset + 2] << 8) | payload[offset + 3];
            offset += 4 + allHeadersLen;
        }

        if (offset >= payload.Length)
            return null;

        if (offset % 2 != 0)
            offset++;

        int sqlLength = payload.Length - offset;
        if (sqlLength <= 0 || sqlLength % 2 != 0)
            return null;

        try
        {
            return Encoding.Unicode.GetString(payload, offset, sqlLength).Trim();
        }
        catch
        {
            return null;
        }
    }

    public static string ExtractRpcProcedure(byte[] payload)
    {
        var header = ParseHeader(payload);
        if (header == null || header.Type != TdsPacketType.RPC)
            return null;

        int offset = 8;

        try
        {
            byte nameLen = payload[offset];
            offset++;

            int nameBytes = nameLen * 2;
            if (offset + nameBytes > payload.Length)
                return null;

            string rpcName = Encoding.Unicode.GetString(payload, offset, nameBytes);
            return rpcName.Trim();
        }
        catch
        {
            return null;
        }
    }

    public static bool IsEndOfMessage(byte status)
    {
        return (status & 0x01) != 0;
    }

    public void AddTcpPayloadFragment(string srcIP, int srcPort, string dstIP, int dstPort, byte[] fragment)
    {
        var key = (srcIP, srcPort, dstIP, dstPort);
        if (!sessionBuffers.ContainsKey(key))
            sessionBuffers[key] = new List<byte>();

        sessionBuffers[key].AddRange(fragment);
    }

    public byte[] GetCompleteMessage(string srcIP, int srcPort, string dstIP, int dstPort, out bool isComplete)
    {
        var key = (srcIP, srcPort, dstIP, dstPort);
        isComplete = false;

        if (!sessionBuffers.ContainsKey(key) || sessionBuffers[key].Count < 8)
            return null;

        var buffer = sessionBuffers[key].ToArray();
        var header = ParseHeader(buffer);
        if (header == null || buffer.Length < header.Length)
            return null;

        isComplete = IsEndOfMessage(header.Status);
        var message = buffer.Take(header.Length).ToArray();
        sessionBuffers[key].RemoveRange(0, header.Length);

        return message;
    }

    public static (string Username, string Password) ExtractLoginCredentials(byte[] payload)
    {
        var header = ParseHeader(payload);
        if (header == null || header.Type != TdsPacketType.Login)
            return (null, null);

        const int baseOffset = 8;

        if (payload.Length < baseOffset + 44)
            return (null, null);

        // Lire les offsets et longueurs en little-endian
        ushort usernameOffset = BitConverter.ToUInt16(payload, baseOffset + 36);
        ushort usernameLength = BitConverter.ToUInt16(payload, baseOffset + 38);
        ushort passwordOffset = BitConverter.ToUInt16(payload, baseOffset + 40);
        ushort passwordLength = BitConverter.ToUInt16(payload, baseOffset + 42);

        // Convertir en octets (UTF-16 = 2 bytes par caractère)
        int usernameByteOffset = baseOffset + (usernameOffset * 1); // déjà en octets
        int usernameByteLength = usernameLength * 2;

        int passwordByteOffset = baseOffset + (passwordOffset * 1); // déjà en octets
        int passwordByteLength = passwordLength * 2;

        try
        {
            // Vérifier que les tailles sont valides
            if (usernameByteOffset + usernameByteLength > payload.Length ||
                passwordByteOffset + passwordByteLength > payload.Length)
                return (null, null);

            // Extraire le nom d’utilisateur
            string username = Encoding.Unicode.GetString(payload, usernameByteOffset, usernameByteLength);

            // Extraire et désobfusquer le mot de passe
            byte[] obfuscatedPwd = payload.Skip(passwordByteOffset).Take(passwordByteLength).ToArray();
            for (int i = 0; i < obfuscatedPwd.Length; i++)
            {
                byte b = obfuscatedPwd[i];
                byte swapped = (byte)(((b & 0xF0) >> 4) | ((b & 0x0F) << 4));
                obfuscatedPwd[i] = (byte)(swapped ^ 0xA5);
            }

            string password = Encoding.Unicode.GetString(obfuscatedPwd);

            return (username.Trim(), password.Trim());
        }
        catch
        {
            return (null, null);
        }
    }
}
