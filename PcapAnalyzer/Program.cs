using PcapAnalyzer.Analyzers;

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
        var scriptDetector = new Analyzer();
        scriptDetector.AnalyzePcapFile(pcapFile);
    }
}
