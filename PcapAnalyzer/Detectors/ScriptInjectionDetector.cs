using SharpPcap.LibPcap;
using SharpPcap;
using PacketDotNet;
using System.Text;
using System.Text.RegularExpressions;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class ScriptInjectionDetector
{
    public AnalysisResultModel AnalyzePcapFile(string pcapFile)
    {
        try
        {
            var detectedScripts = new List<ScriptInjectionModel>();
            int packetCount = 0;

            using (var captureFileReader = new CaptureFileReaderDevice(pcapFile))
            {
                captureFileReader.Open();

                Console.WriteLine($"Analyse du fichier pour scripts injectés : {pcapFile}");

                captureFileReader.OnPacketArrival += new PacketArrivalEventHandler((sender, e) =>
                {
                    packetCount++;

                    var rawCapture = e.GetPacket();

                    var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                    var tcpPacket = packet.Extract<TcpPacket>();

                    if (tcpPacket != null)
                    {
                        var ipPacket = packet.Extract<IPPacket>();
                        if (ipPacket != null && tcpPacket.PayloadData.Length > 0)
                        {
                            if (tcpPacket.DestinationPort == 80 || IsHttpResponse(tcpPacket.PayloadData))
                            {
                                string payload = Encoding.UTF8.GetString(tcpPacket.PayloadData);
                                DetectScripts(ipPacket.SourceAddress.ToString(),
                                            ipPacket.DestinationAddress.ToString(),
                                            tcpPacket.DestinationPort,
                                            payload,
                                            packetCount,
                                            rawCapture.Timeval.Date,
                                            detectedScripts);
                            }
                        }
                    }
                });

                captureFileReader.Capture();

                captureFileReader.Close();
            }

            var result = new AnalysisResultModel
            {
                TotalPackets = packetCount,
                DetectedScripts = detectedScripts
            };

            DisplayResults(result);

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse des scripts : {ex.Message}");
            return new AnalysisResultModel { TotalPackets = 0 };
        }
    }

    private void DisplayResults(AnalysisResultModel result)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {result.TotalPackets}");
        Console.WriteLine("Résultats de détection de scripts injectés :\n");

        if (result.DetectedScripts.Count == 0)
        {
            Console.WriteLine("Aucun script injecté détecté dans le fichier PCAP.");
        }
        else
        {
            foreach (var script in result.DetectedScripts)
            {
                Console.WriteLine($"Script injecté potentiel détecté :");
                Console.WriteLine($"IP Source : {script.SourceIP}");
                Console.WriteLine($"IP Destination : {script.DestinationIP}");
                Console.WriteLine($"Port Destination : {script.DestinationPort}");
                Console.WriteLine($"Numéro du paquet : {script.PacketNumber}");
                Console.WriteLine($"Date : {script.PacketTime}");
                Console.WriteLine($"Contenu du script : {script.ScriptContent}");
                Console.WriteLine("-----------------------------------");
            }
        }
    }

    private bool IsHttpResponse(byte[] payload)
    {
        if (payload.Length < 5) return false;
        string header = Encoding.ASCII.GetString(payload, 0, Math.Min(5, payload.Length));
        return header.StartsWith("HTTP/");
    }

    private void DetectScripts(string srcIP, string dstIP, int dstPort, string payload, int packetNumber, DateTime packetTime, List<ScriptInjectionModel> detectedScripts)
    {
        var inlineMatches = Regex.Matches(payload, @"<script\b[^>]*>(.*?)</script>", RegexOptions.IgnoreCase | RegexOptions.Singleline);

        foreach (Match match in inlineMatches)
        {
            string scriptContent = match.Value;
            string scriptType = IsSuspiciousScript(scriptContent);

            if (scriptType != null)
            {
                detectedScripts.Add(new ScriptInjectionModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    ScriptContent = scriptContent.Length > 100 ? scriptContent.Substring(0, 100) + "..." : scriptContent,
                    PacketNumber = packetNumber,
                    PacketTime = packetTime,
                    ScriptType = scriptType
                });
            }
        }

        var externalMatches = Regex.Matches(payload, @"<script\b[^>]*src\s*=\s*['""][^'""]+['""]", RegexOptions.IgnoreCase);

        foreach (Match match in externalMatches)
        {
            string scriptContent = match.Value;
            string scriptType = IsSuspiciousScript(scriptContent);

            if (scriptType != null)
            {
                detectedScripts.Add(new ScriptInjectionModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    ScriptContent = scriptContent,
                    PacketNumber = packetNumber,
                    PacketTime = packetTime,
                    ScriptType = scriptType
                });
            }
        }

        string[] scriptExtensions = { ".ps1", ".js", ".php", ".rs", ".sh", ".bash", ".py" };
        foreach (var ext in scriptExtensions)
        {
            var extPattern = @$"\b\S+{Regex.Escape(ext)}\b";

            if (Regex.IsMatch(payload, extPattern, RegexOptions.IgnoreCase))
            {
                string scriptType = ext switch
                {
                    ".ps1" => "PowerShell",
                    ".js" => "JavaScript",
                    ".php" => "PHP",
                    ".rs" => "Rust",
                    ".sh" => "Shell",
                    ".bash" => "Bash",
                    ".py" => "Python",
                    _ => "Unknown"
                };
                string snippet = payload.Length > 100 ? payload.Substring(0, 100) + "..." : payload;
                detectedScripts.Add(new ScriptInjectionModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    ScriptContent = $"Fichier {ext} détecté : {snippet}",
                    PacketTime = packetTime,
                    PacketNumber = packetNumber,
                    ScriptType = scriptType
                });
            }
        }

        var xssAttributes = new[] { "onerror=", "onload=", "onclick=", "onmouseover=", "onfocus=" };
        foreach (var attr in xssAttributes)
        {
            if (payload.IndexOf(attr, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                detectedScripts.Add(new ScriptInjectionModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    ScriptContent = $"Attribut XSS détecté: {attr}",
                    PacketTime = packetTime,
                    PacketNumber = packetNumber,
                    ScriptType = "XSS Inline Attribute"
                });
            }
        }

        if (Regex.IsMatch(payload, @"javascript:", RegexOptions.IgnoreCase))
        {
            detectedScripts.Add(new ScriptInjectionModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                ScriptContent = "URI javascript: détecté",
                PacketTime = packetTime,
                PacketNumber = packetNumber,
                ScriptType = "XSS JavaScript URI"
            });
        }

        string decodedPayload = Uri.UnescapeDataString(payload);
        if (Regex.IsMatch(decodedPayload, @"<script\b", RegexOptions.IgnoreCase))
        {
            detectedScripts.Add(new ScriptInjectionModel
            {
                SourceIP = srcIP,
                DestinationIP = dstIP,
                DestinationPort = dstPort,
                ScriptContent = "Script encodé détecté dans le payload",
                PacketTime = packetTime,
                PacketNumber = packetNumber,
                ScriptType = "Encoded Script"
            });
        }

        var dangerousJsFuncs = new[] { "eval(", "alert(", "prompt(", "confirm(", "document.cookie", "window.location" };
        foreach (var func in dangerousJsFuncs)
        {
            if (payload.IndexOf(func, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                detectedScripts.Add(new ScriptInjectionModel
                {
                    SourceIP = srcIP,
                    DestinationIP = dstIP,
                    DestinationPort = dstPort,
                    ScriptContent = $"Fonction JavaScript dangereuse détectée: {func}",
                    PacketTime = packetTime,
                    PacketNumber = packetNumber,
                    ScriptType = "Dangerous JavaScript Function"
                });
            }
        }
    }

    private static readonly Dictionary<string, string[]> ScriptSignatures = new()
    {
        ["JavaScript"] = new[]
    {
        "eval\\(", "document\\.write", "unescape\\(", "execScript",
        "Function\\(", "setTimeout\\(", "setInterval\\(", "atob\\(", "btoa\\("
    },
        ["PowerShell"] = new[]
    {
        "Invoke-Expression", "iex", "Invoke-Command", "Start-Process",
        "Get-Command", "New-Object", "Add-Type", "DownloadString",
        "FromBase64String", "\\$\\w+"
    },
        ["PHP"] = new[]
    {
        "<\\?php", "eval\\(", "exec\\(", "system\\(", "shell_exec\\(",
        "passthru\\(", "assert\\(", "base64_decode\\(", "\\$\\w+"
    },
        ["Rust"] = new[]
    {
        "\\bfn\\b", "\\blet\\b", "\\bstruct\\b", "::", "\\buse\\b",
        "\\bmod\\b", "println!"
    },
        ["Shell/Bash"] = new[]
    {
        "#!/bin/bash", "#!/bin/sh", "\\bcurl\\b", "\\bwget\\b",
        "\\bnc\\b", "\\beval\\b", "\\bexec\\b", "\\bbase64\\b", "bash -i", "\\$\\w+"
    },
        ["Python"] = new[]
    {
        "import\\s+", "def\\s+", "os\\.", "sys\\.", "subprocess\\.",
        "eval\\(", "exec\\(", "__import__", "open\\(", "base64\\.b64decode", "\\bclass\\b"
    }
    };

    private string IsSuspiciousScript(string script)
    {
        // Vérifie si le script contient un mot-clé suspect d'un langage donné
        foreach (var kvp in ScriptSignatures)
        {
            foreach (var pattern in kvp.Value)
            {
                if (Regex.IsMatch(script, pattern, RegexOptions.IgnoreCase))
                    return kvp.Key;
            }
        }

        // Vérifie si c'est un script JavaScript externe
        string jsSrcPattern = @"src\s*=\s*['""](http[s]?://[^'""]*\.js)['""]";
        if (Regex.IsMatch(script, jsSrcPattern, RegexOptions.IgnoreCase))
            return "JavaScript (External Source)";

        return null;
    }
}
