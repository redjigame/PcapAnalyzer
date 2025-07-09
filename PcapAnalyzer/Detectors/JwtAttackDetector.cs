using PcapAnalyzer.Models;
using SharpPcap.LibPcap;
using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;
using System.Text;
using System.Text.Json;

namespace PcapAnalyzer.Detectors;

public class JwtAttackDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        var detectedJwtAttacks = new List<ScriptInjectionModel>();
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
                string payload = Encoding.UTF8.GetString(tcp.PayloadData);

                if (IsJwtAttack(payload, out string attackType))
                {
                    detectedJwtAttacks.Add(new ScriptInjectionModel
                    {
                        SourceIP = ip.SourceAddress.ToString(),
                        DestinationIP = ip.DestinationAddress.ToString(),
                        DestinationPort = tcp.DestinationPort,
                        ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                        PacketNumber = packetCount,
                        PacketTime = raw.Timeval.Date,
                        ScriptType = $"JWT ({attackType})"
                    });
                }
            }
        };

        reader.Capture();
        reader.Close();

        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = detectedJwtAttacks
        };

        DisplayResults(result);
        return result;
    }

    private bool IsJwtAttack(string payload, out string type)
    {
        type = null;

        var jwtRegex = new Regex("Authorization: Bearer ([a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]*)", RegexOptions.IgnoreCase);
        var match = jwtRegex.Match(payload);
        if (match.Success)
        {
            var token = match.Groups[1].Value;
            var parts = token.Split('.');
            if (parts.Length != 3) return false;

            try
            {
                var headerJson = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[0])));
                var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(parts[1])));

                var header = JsonDocument.Parse(headerJson).RootElement;
                var body = JsonDocument.Parse(payloadJson).RootElement;

                if (header.TryGetProperty("alg", out var alg) && alg.ToString().Equals("none", StringComparison.OrdinalIgnoreCase))
                {
                    type = "alg:none";
                    return true;
                }
                if (header.TryGetProperty("alg", out alg) && alg.ToString().Equals("HS256", StringComparison.OrdinalIgnoreCase))
                {
                    type = "HS256 public key as secret";
                    return true;
                }

                if (body.TryGetProperty("role", out var role))
                {
                    var roleVal = role.ToString().ToLowerInvariant();
                    if (roleVal.Contains("admin") || roleVal.Contains("superuser"))
                    {
                        type = "elevated role claim";
                        return true;
                    }
                }

                if (body.TryGetProperty("exp", out var exp))
                {
                    if (long.TryParse(exp.ToString(), out long expVal))
                    {
                        var expTime = DateTimeOffset.FromUnixTimeSeconds(expVal).UtcDateTime;
                        if (expTime > DateTime.UtcNow.AddYears(1))
                        {
                            type = "exp too far in future";
                            return true;
                        }
                    }
                }
                else
                {
                    type = "missing exp claim";
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }
        return false;
    }

    private string PadBase64(string input)
    {
        return input.PadRight(input.Length + (4 - input.Length % 4) % 4, '=');
    }

    private void DisplayResults(AnalysisResultModel result)
    {
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
