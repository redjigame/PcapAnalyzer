using PacketDotNet;
using PcapAnalyzer.Models;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace PcapAnalyzer.Analyzers;

public class JwtAttackAnalyzer
{
    public void JwtAttackAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, List<ScriptInjectionModel> detectedJwtAttacks)
    {
        if (IsJwtAttack(payload, out string attackType))
        {
            detectedJwtAttacks.Add(new ScriptInjectionModel
            {
                SourceIP = ip.SourceAddress.ToString(),
                DestinationIP = ip.DestinationAddress.ToString(),
                DestinationPort = tcp.DestinationPort,
                ScriptContent = payload.Length > 150 ? payload[..150] + "..." : payload,
                PacketNumber = packetCount,
                PacketTime = date,
                ScriptType = $"JWT ({attackType})"
            });
        }
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
}
