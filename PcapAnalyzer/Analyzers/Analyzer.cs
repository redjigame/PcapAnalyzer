using SharpPcap.LibPcap;
using SharpPcap;
using System.Text;
using PacketDotNet;
using PcapAnalyzer.Models;
using PcapAnalyzer.Detectors;

namespace PcapAnalyzer.Analyzers;

public class Analyzer
{
    private readonly BruteForceDetector _bruteForceDetector = new BruteForceDetector();
    private readonly BruteForceAnalyzer _bruteForceAnalyzer = new BruteForceAnalyzer();

    private readonly CommandInjectionDetector _commandInjectionDetector = new CommandInjectionDetector();
    private readonly CommandInjectionAnalyzer _commandInjectionAnalyzer = new CommandInjectionAnalyzer();

    private readonly DataLeakDetector _dataLeakDetector = new DataLeakDetector();
    private readonly DataLeakAnalyzer _dataLeakAnalyzer = new DataLeakAnalyzer();

    private readonly DirectoryEnumDetector _directoryEnumDetector = new DirectoryEnumDetector();
    private readonly DirectoryEnumAnalyzer _directoryEnumAnalyzer = new DirectoryEnumAnalyzer();

    private readonly FileInclusionDetector _fileInclusionDetector = new FileInclusionDetector();
    private readonly FileInclusionAnalyzer _fileInclusionAnalyzer = new FileInclusionAnalyzer();

    private readonly JwtAttackDetector _jwtAttackDetector = new JwtAttackDetector();
    private readonly JwtAttackAnalyzer _jwtAttackAnalyzer = new JwtAttackAnalyzer();

    private readonly NmapScanDetector _nmapScanDetector = new NmapScanDetector();
    private readonly NmapScanAnalyzer _nmapScanAnalyzer = new NmapScanAnalyzer();

    private readonly PathTraversalDetector _pathTraversalDetector = new PathTraversalDetector();
    private readonly PathTraversalAnalyzer _pathTraversalAnalyzer = new PathTraversalAnalyzer();

    private readonly ScriptInjectionDetector _scriptInjectionDetector = new ScriptInjectionDetector();
    private readonly ScriptInjectionAnalyzer _scriptInjectionAnalyzer = new ScriptInjectionAnalyzer();

    private readonly SqlManipulationDetector _sqlManipulationDetector = new SqlManipulationDetector();
    private readonly SqlManipulationAnalyzer _sqlManipulationAnalyzer = new SqlManipulationAnalyzer();

    private readonly SsrfDetector _ssrfDetector = new SsrfDetector();
    private readonly SsrfAnalyzer _ssrfAnalyzer = new SsrfAnalyzer();

    private readonly XxeDetector _xxeDetector = new XxeDetector();
    private readonly XxeAnalyzer _xxeAnalyzer = new XxeAnalyzer();

    public void AnalyzePcapFile(string pcapFile)
    {
        var bruteForceTracker = new Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel>();
        var detectedCmdInjections = new Dictionary<(string SrcIP, string DstIP, int DstPort), ScriptInjectionModel>();
        var detectedScriptInjections = new List<ScriptInjectionModel>();
        var DetectFileInclusions = new List<ScriptInjectionModel>();
        var jwtAttackTracker = new List<ScriptInjectionModel>();
        var pathTraversalTracker = new List<ScriptInjectionModel>();
        var ssrfTracker = new List<ScriptInjectionModel>();
        var xxeTracker = new List<ScriptInjectionModel>();
        var sqlManipulationTracker = new List<SqlManipulationModel>();
        var dataLeakTracker = new List<DataLeakModel>();
        var dirEnumTracker = new Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel>();
        var scanTracker = new Dictionary<string, NmapModel>();

        int packetCount = 0;

        string charge = "";

        using var reader = new CaptureFileReaderDevice(pcapFile);
        reader.Open();

        reader.OnPacketArrival += (sender, e) =>
        {
            packetCount++;

            var raw = e.GetPacket();
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            var tcp = packet.Extract<TcpPacket>();
            var ip = packet.Extract<IPPacket>();

            if (tcp != null)
            {
                string srcIP = ip.SourceAddress.ToString();
                string dstIP = ip.DestinationAddress.ToString();
                int srcPort = tcp.SourcePort;
                int dstPort = tcp.DestinationPort;
                byte[] bitPayload = tcp.PayloadData;
                string payload = Encoding.UTF8.GetString(tcp.PayloadData);
                charge = payload;

                _bruteForceAnalyzer.BruteForceAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, bruteForceTracker, tcp, payload);
                _commandInjectionAnalyzer.CmdInjecAnalyze(packetCount, raw.Timeval.Date, ip, tcp, payload, detectedCmdInjections);
                _dataLeakAnalyzer.DataLeakAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, bitPayload, dataLeakTracker);
                _directoryEnumAnalyzer.DirEnumAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, dirEnumTracker, tcp, payload);
                _fileInclusionAnalyzer.FileInclusAnalyeze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, DetectFileInclusions);
                _jwtAttackAnalyzer.JwtAttackAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, jwtAttackTracker);
                _nmapScanAnalyzer.NmapScanAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, scanTracker);
                _pathTraversalAnalyzer.PathTraversalAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, pathTraversalTracker);
                _scriptInjectionAnalyzer.ScriptInjecAnalyze(srcIP, dstIP, dstPort, packetCount, raw.Timeval.Date, ip, tcp, payload, detectedScriptInjections);
                _sqlManipulationAnalyzer.SqlManipulationAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, bitPayload, sqlManipulationTracker);
                _ssrfAnalyzer.SsrfAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, ssrfTracker);
                _xxeAnalyzer.XxeAnalyze(srcIP, srcPort, dstIP, dstPort, packetCount, raw.Timeval.Date, tcp, ip, payload, xxeTracker);
            }
        };

        reader.Capture();
        reader.Close();

        BruteForceResult(packetCount, bruteForceTracker);
        CmdInjecResult(packetCount, charge, detectedCmdInjections);
        DataLeakResult(packetCount, dataLeakTracker);
        DirEnumResult(packetCount, dirEnumTracker);
        FileInclusionResult(packetCount, DetectFileInclusions);
        JwtAttackResult(packetCount, jwtAttackTracker);
        NmapResult(packetCount, scanTracker);
        PathTraversalResult(packetCount, pathTraversalTracker);
        ScriptInjectionResult(packetCount, detectedScriptInjections);
        SqlManipulationResult(packetCount, sqlManipulationTracker);
        SsrfResult(packetCount, ssrfTracker);
        XxeResult(packetCount, xxeTracker);
    }

    private AnalysisResultModel XxeResult(int packetCount, List<ScriptInjectionModel> xxeTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _xxeDetector.DetectXxefAttacks(packetCount, xxeTracker),
        };

        _xxeDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel SsrfResult(int packetCount, List<ScriptInjectionModel> ssrfTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _ssrfDetector.DetectSsrfAttacks(packetCount, ssrfTracker),
        };

        _ssrfDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel SqlManipulationResult(int packetCount, List<SqlManipulationModel> sqlManipulationTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedSqlChanges = _sqlManipulationDetector.DetectSqlManipulationAttacks(packetCount, sqlManipulationTracker),
        };

        _sqlManipulationDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel ScriptInjectionResult(int packetCount, List<ScriptInjectionModel> detectedScriptInjections)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _scriptInjectionDetector.DetectScriptInjectionAttacks(packetCount, detectedScriptInjections),
        };

        _scriptInjectionDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel PathTraversalResult(int packetCount, List<ScriptInjectionModel> pathTraversalTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _pathTraversalDetector.DetectPathTraversalAttacks(packetCount, pathTraversalTracker),
        };

        _pathTraversalDetector.DisplayResults(result);
        return result;
    }

    private void NmapResult(int packetCount, Dictionary<string, NmapModel> scanTracker)
    {
        _nmapScanDetector.DisplayResults(packetCount, scanTracker);
    }

    private AnalysisResultModel JwtAttackResult(int packetCount, List<ScriptInjectionModel> jwtAttackTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _jwtAttackDetector.DetectJwtAttacks(packetCount, jwtAttackTracker),
        };

        _jwtAttackDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel FileInclusionResult(int packetCount, List<ScriptInjectionModel> attemptTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _fileInclusionDetector.DetectFileInclusion(packetCount, attemptTracker),
        };

        _fileInclusionDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel DataLeakResult(int packetCount, List<DataLeakModel> attemptTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedDataLeaks = _dataLeakDetector.DetectDataLeakAttempts(packetCount, attemptTracker),
        };

        _dataLeakDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel BruteForceResult(int packetCount, Dictionary<(string SrcIP, string DstIP, int DstPort, string Protocol), BruteForceModel> attemptTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedAttempts = _bruteForceDetector.DetectBruteForceAttempts(attemptTracker),
        };

        _bruteForceDetector.DisplayResults(result);
        return result;
    }

    private AnalysisResultModel CmdInjecResult(int packetCount, string payload, Dictionary<(string SrcIP, string DstIP, int DstPort), ScriptInjectionModel> attemptTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedScripts = _commandInjectionDetector.DetectCmdInjecAttempts(payload, attemptTracker),
        };

        _commandInjectionDetector.DisplayResults(result);

        return result;
    }

    private AnalysisResultModel DirEnumResult(int packetCount, Dictionary<(string SrcIP, string DstIP, int DstPort), DirectoryEnumerationModel> attemptTracker)
    {
        var result = new AnalysisResultModel
        {
            TotalPackets = packetCount,
            DetectedDirBruteForces = _directoryEnumDetector.DetectDirectoryBruteForceAttempts(attemptTracker)
        };

        _directoryEnumDetector.DisplayResults(result);

        return result;
    }
    public static bool IsHttpRequest(byte[] payload)
    {
        if (payload.Length < 4) return false;
        string header = Encoding.ASCII.GetString(payload, 0, Math.Min(4, payload.Length));
        return header.StartsWith("POST") || header.StartsWith("GET");
    }
}
