using PcapAnalyzer.Models;

namespace PcapAnalyzer.Detectors;

public class NmapScanDetector
{
    public void DisplayResults(int packetCount, Dictionary<string, NmapModel> scanTracker)
    {
        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Résultats de détection de scans Nmap' ===");
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {packetCount}");

        bool scanDetected = false;

        foreach (var scan in scanTracker)
        {
            var info = scan.Value;
            var duration = (info.LastPacketTime - info.FirstPacketTime).TotalSeconds;

            if (info.PortCount > 50 && duration > 0)
            {
                double portsPerSecond = info.PortCount / duration;

                if (portsPerSecond > 1)
                {
                    scanDetected = true;
                    Console.WriteLine($"Scan Nmap potentiel détecté :");
                    Console.WriteLine($"IP Source : {info.SourceIP}");
                    Console.WriteLine($"Nombre de ports scannés : {info.PortCount}");
                    Console.WriteLine($"Durée : {duration:F2} secondes");
                    Console.WriteLine($"Taux : {portsPerSecond:F2} ports/seconde");
                    Console.WriteLine($"Période : {info.FirstPacketTime} - {info.LastPacketTime}");
                    Console.WriteLine("-----------------------------------");
                }
            }
        }

        if (!scanDetected)
        {
            Console.WriteLine("Aucun scan Nmap détecté dans le fichier PCAP.");
        }
    }
}
