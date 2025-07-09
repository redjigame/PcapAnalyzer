using PcapAnalyzer.Detectors;

class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        Console.WriteLine(@"


 ____                   _                _                    
|  _ \ ___ __ _ _ __   / \   _ __   __ _| |_   _ _______ _ __ 
| |_) / __/ _` | '_ \ / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
|  __/ (_| (_| | |_) / ___ \| | | | (_| | | |_| |/ /  __/ |   
|_|   \___\__,_| .__/_/   \_\_| |_|\__,_|_|\__, /___\___|_|   
               |_|                         |___/              


               Détection de scans Nmap
");

        Console.WriteLine("Entrez le chemin du ficher pcap á analiser");

        string pcapFile = Console.ReadLine();

        if (!File.Exists(pcapFile))
        {
            Console.WriteLine($"Erreur : Le fichier {pcapFile} n'existe pas.");
            return;
        }

        FinalReport(pcapFile);
    }

    private static void FinalReport(string pcapFile)
    {
        /*Console.WriteLine("\n=== Analyse des scans Nmap ===");
        var nmapDetector = new NmapScanDetector();
        nmapDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des scripts injectés ===");
        var scriptDetector = new ScriptInjectionDetector();
        scriptDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de force brute ===");
        var bruteForceDetector = new BruteForceDetector();
        bruteForceDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de enum directory ===");
        var enumDirectoryDetector = new DirectoryEnumDetector();
        enumDirectoryDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de manipulation SQL ===");
        var sqlManipDetector = new SqlManipulationDetector();
        sqlManipDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de file inclusion' ===");
        var fileInclusionDetector = new FileInclusionDetector();
        fileInclusionDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives de path traversal' ===");
        var pathTraversalDetector = new PathTraversalDetector();
        pathTraversalDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'injection SSRF' ===");
        var ssrfDetector = new SsrfDetector();
        ssrfDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'injection XXE' ===");
        var xxeDetector = new XxeDetector();
        xxeDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'attaque JWT' ===");
        var jwtDetector = new JwtAttackDetector();
        jwtDetector.AnalyzePcapFile(pcapFile);*/

        Console.WriteLine("\n========================================================================\n========================================================================");

        Console.WriteLine("\n=== Analyse des tentatives d'exfiltration des données' ===");
        var leakDetector = new DataLeakDetector();
        leakDetector.AnalyzePcapFile(pcapFile);

        Console.WriteLine("\n========================================================================\n========================================================================");
        /*Console.WriteLine("\n=== Analyse des tentatives d'injection de commande' ===");
        var smdInjectionDetector = new CommandInjectionDetector();
        smdInjectionDetector.AnalyzePcapFile(pcapFile);*/

    }
}
