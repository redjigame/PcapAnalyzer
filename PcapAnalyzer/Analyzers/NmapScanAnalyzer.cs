using PacketDotNet;
using PcapAnalyzer.Models;

namespace PcapAnalyzer.Analyzers
{
    public class NmapScanAnalyzer
    {
        public void NmapScanAnalyze(string srcIP, int srcPort, string dstIP, int dstPort, int packetCount, DateTime date, TcpPacket tcp, IPPacket ip, string payload, Dictionary<string , NmapModel> scanTracker)
        {
            const ushort SYN_FLAG = 0x02; // SYN flag (bit 2)
            const ushort ACK_FLAG = 0x10; // ACK flag (bit 5)
            if ((tcp.Flags & SYN_FLAG) == SYN_FLAG && (tcp.Flags & ACK_FLAG) == 0)
            {
                if (!scanTracker.ContainsKey(srcIP))
                {
                    scanTracker[srcIP] = new Models.NmapModel
                    {
                        SourceIP = srcIP,
                        PortCount = 0,
                        FirstPacketTime = date,
                        LastPacketTime = date
                    };
                }

                scanTracker[srcIP].PortCount++;
                scanTracker[srcIP].LastPacketTime = date;
            }
        }
    }
}
