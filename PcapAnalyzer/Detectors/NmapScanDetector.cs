using PacketDotNet;
using SharpPcap.LibPcap;
using SharpPcap;

namespace PcapAnalyzer.Detectors;

public class NmapScanDetector
{
    public void AnalyzePcapFile(string pcapFile)
    {
        try
        {
            var scanTracker = new Dictionary<string, Models.NmapModel>();
            int packetCount = 0;

            using (var captureFileReader = new CaptureFileReaderDevice(pcapFile))
            {
                captureFileReader.Open();

                Console.WriteLine($"Analyse du fichier : {pcapFile}");

                captureFileReader.OnPacketArrival += new PacketArrivalEventHandler((sender, e) =>
                {
                    packetCount++;

                    var rawCapture = e.GetPacket();

                    var packet = Packet.ParsePacket(rawCapture.LinkLayerType, rawCapture.Data);
                    var tcpPacket = packet.Extract<TcpPacket>();

                    if (tcpPacket != null)
                    {
                        var ipPacket = packet.Extract<IPPacket>();
                        if (ipPacket != null)
                        {
                            string srcIP = ipPacket.SourceAddress.ToString();
                            int dstPort = tcpPacket.DestinationPort;

                            const ushort SYN_FLAG = 0x02; // SYN flag (bit 2)
                            const ushort ACK_FLAG = 0x10; // ACK flag (bit 5)
                            if ((tcpPacket.Flags & SYN_FLAG) == SYN_FLAG && (tcpPacket.Flags & ACK_FLAG) == 0)
                            {
                                if (!scanTracker.ContainsKey(srcIP))
                                {
                                    scanTracker[srcIP] = new Models.NmapModel
                                    {
                                        SourceIP = srcIP,
                                        PortCount = 0,
                                        FirstPacketTime = rawCapture.Timeval.Date,
                                        LastPacketTime = rawCapture.Timeval.Date
                                    };
                                }

                                scanTracker[srcIP].PortCount++;
                                scanTracker[srcIP].LastPacketTime = rawCapture.Timeval.Date;
                            }
                        }
                    }
                });

                captureFileReader.Capture();

                captureFileReader.Close();
            }

            DetectNmapScans(scanTracker, packetCount);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Erreur lors de l'analyse : {ex.Message}");
        }
    }

    private void DetectNmapScans(Dictionary<string, Models.NmapModel> scanTracker, int totalPackets)
    {
        Console.WriteLine($"\nAnalyse terminée. Paquets analysés : {totalPackets}");
        Console.WriteLine("Résultats de détection de scans Nmap :\n");

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
