<!DOCTYPE html>
<html lang="pt-BR">
<body>

<div class="container">
    <header>
        <h1>🛡️ PcapAnalyzer</h1>
        <p><strong>PcapAnalyzer</strong> é uma aplicação de console desenvolvida em C# (.NET 9.0) projetada para analisar arquivos de captura de rede (formatos <code>.pcap</code> e <code>.pcapng</code>) e detectar automaticamente uma variedade de ataques cibernéticos, vetores de exploração e anomalias no tráfego de rede.</p>
    </header>

    <main>
        <section>
            <h2>🚀 Funcionalidades</h2>
            <p>O projeto é capaz de identificar os seguintes tipos de ameaças e anomalias:</p>
            <ul>
                <li>🔑 <strong>Ataques de Força Bruta</strong> (Brute Force)</li>
                <li>💻 <strong>Injeção de Comandos</strong> (Command Injection)</li>
                <li>📤 <strong>Vazamento de Dados</strong> (Data Leaks)</li>
                <li>📁 <strong>Enumeração de Diretórios</strong> (Directory Enumeration)</li>
                <li>📂 <strong>Inclusão de Arquivos</strong> (File Inclusion - LFI/RFI)</li>
                <li>🎫 <strong>Ataques a Tokens JWT</strong> (JWT Attacks)</li>
                <li>🗺️ <strong>Varreduras de Rede</strong> (Nmap Scans)</li>
                <li>🗂️ <strong>Path Traversal</strong> (Caminho de Diretório)</li>
                <li>📜 <strong>Injeção de Scripts</strong> (Script Injection / XSS)</li>
                <li>🗄️ <strong>Manipulação de SQL</strong> (SQL Injection)</li>
                <li>🌐 <strong>Falsificação de Solicitação do Lado do Servidor</strong> (SSRF)</li>
                <li>📄 <strong>Entidade Externa XML</strong> (XXE)</li>
            </ul>
        </section>

        <section>
            <h2>🏗️ Estrutura do Projeto</h2>
            <div class="tree">PcapAnalyzer/
├── Analyzers/       # Lógica principal que orquestra a análise e consolidação dos resultados
├── Detectors/       # Implementações específicas de detecção para cada tipo de ataque
├── Models/          # Modelos de dados que representam os ataques detectados e relatórios
├── Parsers/         # Utilitários para processamento e análise de payloads de rede
├── Program.cs       # Ponto de entrada da aplicação de console
└── PcapAnalyzer.csproj # Arquivo de configuração do projeto .NET</div>
        </section>

        <section>
            <h2>📋 Pré-requisitos</h2>
            <ul>
                <li><a href="https://dotnet.microsoft.com/download/dotnet/9.0" target="_blank">.NET 9.0 SDK</a> ou superior instalado.</li>
                <li>Um arquivo de captura de rede (<code>.pcap</code> ou <code>.pcapng</code>) para análise (ex: gerado pelo Wireshark, tcpdump ou ferramentas similares).</li>
            </ul>
        </section>

        <section>
            <h2>⚙️ Instalação e Uso</h2>
            
            <h3>1. Clonar o repositório</h3>
            <pre><code>git clone https://github.com/redjigame/PcapAnalyzer.git
cd PcapAnalyzer/PcapAnalyzer</code></pre>

            <h3>2. Restaurar as dependências</h3>
            <pre><code>dotnet restore</code></pre>

            <h3>3. Compilar o projeto</h3>
            <pre><code>dotnet build</code></pre>

            <h3>4. Executar a aplicação</h3>
            <pre><code>dotnet run</code></pre>

            <h3>5. Inserir o caminho do arquivo</h3>
            <p>O aplicativo solicitará o caminho do arquivo de captura <em>(Nota: o prompt original no código está em francês, mas funciona da mesma forma)</em>. Digite o caminho completo ou relativo e pressione <code>Enter</code>.</p>

            <h3>5. Visualizar o relatório</h3>
            <p>A ferramenta processará os pacotes e exibirá um relatório consolidado no console, detalhando as ameaças detectadas, endereços IP de origem/destino, portas e a contagem de pacotes.</p>
        </section>

        <section>
            <h2>📦 Dependências Principais</h2>
            <p>O projeto utiliza bibliotecas robustas e consagradas para a manipulação e análise de pacotes de rede:</p>
            <ul>
                <li><a href="https://github.com/chmorgan/sharppcap" target="_blank">SharpPcap</a> (v6.3.1): Para leitura e processamento de arquivos de captura de rede.</li>
                <li><a href="https://github.com/chmorgan/packetnet" target="_blank">PacketDotNet</a> (v1.4.8): Para análise e dissecação profunda dos pacotes de rede.</li>
            </ul>
        </section>

        <section>
            <h2>📄 Licença</h2>
            <p>Este projeto está sob a licença <a href="#">MIT</a>.</p>
        </section>

        <div class="warning-box">
            <strong>⚠️ Aviso Legal</strong>
            Esta ferramenta é destinada estritamente para fins educacionais, de pesquisa e de análise defensiva de segurança (Blue Team). Certifique-se de ter autorização explícita para analisar os arquivos de captura de rede que você possui.
        </div>
    </main>
</div>

</body>
</html>
