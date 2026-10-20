<h1>🛡️ PcapAnalyzer<h1>
    <br*>
O PcapAnalyzer é uma aplicação de console desenvolvida em C# (.NET 9.0) projetada para analisar arquivos de captura de rede (formatos .pcap e .pcapng) e detectar automaticamente uma variedade de ataques cibernéticos, vetores de exploração e atividades suspeitas no tráfego de rede.
🚀 Funcionalidades
O projeto é capaz de identificar os seguintes tipos de ameaças e anomalias:
    🔑 Ataques de Força Bruta (Brute Force)
    💻 Injeção de Comandos (Command Injection)
    📤 Vazamento de Dados (Data Leaks)
    📁 Enumeração de Diretórios (Directory Enumeration)
    📂 Inclusão de Arquivos (File Inclusion - LFI/RFI)
    🎫 Ataques a Tokens JWT (JWT Attacks)
    🗺️ Varreduras de Rede (Nmap Scans)
    🗂️ Path Traversal
    📜 Injeção de Scripts (Script Injection / XSS)
    🗄️ Manipulação de SQL (SQL Injection)
    🌐 Falsificação de Solicitação do Lado do Servidor (SSRF)
    📄 Entidade Externa XML (XXE)

📋 Pré-requisitos:
    .NET 9.0 SDK
     ou superior instalado.
    Um arquivo de captura de rede (.pcap ou .pcapng) para análise (ex: gerado pelo Wireshark, tcpdump ou ferramentas similares)

⚙️ Instalação e Uso
  1-Clone o repositório:
      git clone https://github.com/redjigame/PcapAnalyzer.git
      cd PcapAnalyzer/PcapAnalyzer

  2-Restaure as dependências do projeto:
      dotnet restore
      
  3-Compile o projeto:
      dotnet build

  4-Execute a aplicação:
      dotnet run 

  O aplicativo solicitará o caminho do arquivo de captura (Nota: O prompt atual está em francês no código original). Digite o caminho completo ou relativo e pressione Enter.

Visualize o relatório:
  A ferramenta processará os pacotes e exibirá um relatório consolidado no console com as ameaças detectadas, endereços IP de origem/destino, portas e contagem de pacotes.

📦 Dependências Principais
O projeto utiliza bibliotecas robustas e consagradas para a manipulação e análise de pacotes de rede que vocês deverão instalar:

  SharpPcap
     (v6.3.1): Para leitura e processamento de arquivos de captura de rede.
  PacketDotNet
     (v1.4.8): Para análise e dissecação profunda dos pacotes de rede.
    
