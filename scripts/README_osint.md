# 🕵️ OSINT Collector — Documentação Completa

**Autor:** Felipe Diassis  
**GitHub:** [github.com/felipeds-cdc](https://github.com/felipeds-cdc)  
**Versão:** 1.0  
**Linguagem:** Python 3  

> ⚠️ **AVISO LEGAL:** Este script é estritamente educacional.  
> Use apenas em domínios próprios ou com autorização expressa.  
> Coleta não autorizada pode configurar crime —  
> **Lei 12.737/2012** e **Art. 171 CP (Estelionato)**.

---

## 📋 Índice

- [O que é o script](#-o-que-é-o-script)
- [O que é OSINT](#-o-que-é-osint)
- [Requisitos](#-requisitos)
- [Como instalar](#-como-instalar)
- [Como rodar](#-como-rodar)
- [Estrutura do código](#-estrutura-do-código)
- [Módulos explicados](#-módulos-explicados)
- [Arquivos gerados](#-arquivos-gerados)
- [Como manter o código](#-como-manter-o-código)
- [Exemplos reais](#-exemplos-reais)
- [Solução de problemas](#-solução-de-problemas)

---

## 🔍 O que é o script

O `osint_collector.py` automatiza a coleta de informações públicas sobre
um domínio — exatamente o que um atacante faria antes de tentar um ataque
de engenharia social ou um pentest.

**Fluxo completo:**
```
Domínio informado
        ↓
Módulo 1: IP, Reverse DNS, WHOIS
        ↓
Módulo 2: Registros DNS (A, MX, NS, TXT...)
        ↓
Módulo 3: Subdomínios por força bruta
        ↓
Módulo 4: Headers HTTP e tecnologias
        ↓
Módulo 5: Emails e contatos públicos
        ↓
Módulo 6: Geolocalização e ASN
        ↓
Módulo 7: Arquivos públicos expostos
        ↓
Módulo 8: Redes sociais e Google Dorks
        ↓
Módulo 9: Análise de segurança (SPF, DMARC, HTTPS)
        ↓
Relatório completo salvo em .txt
```

---

## 🧠 O que é OSINT

**OSINT** (Open Source Intelligence) é a coleta de informações a partir
de fontes públicas e abertas — sem invadir nenhum sistema.

**Por que é fundamental para pentest e Red Team:**

| Fase do Pentest    | O que OSINT fornece                          |
|--------------------|----------------------------------------------|
| Reconhecimento     | IPs, subdomínios, tecnologias, emails        |
| Engenharia Social  | Nomes de funcionários, cargos, contatos      |
| Exploração         | Versões de software com CVEs conhecidos      |
| Relatório          | Superfície de ataque documentada             |

**Regra de ouro:** Quanto mais informação coletada na fase de OSINT,
maior a chance de sucesso nas fases seguintes — e menos ruído gerado.

---

## 🖥️ Requisitos

| Requisito | Versão mínima | Como verificar      |
|-----------|---------------|---------------------|
| Python    | 3.6+          | `python3 --version` |
| whois     | Qualquer      | `whois --version`   |
| dig       | Qualquer      | `dig -v`            |
| Conexão   | Necessária    | Para APIs e DNS     |

### Bibliotecas Python — todas nativas
```
socket        → Resolução de DNS e conexões TCP
subprocess    → Executa whois e dig no terminal
sys           → Argumentos da linha de comando
json          → Processa resposta da API de Geo-IP
datetime      → Timestamp no relatório
urllib        → Requisições HTTP
re            → Expressões regulares para emails e URLs
os            → Operações de arquivo
```

---

## 🔧 Como instalar

```bash
# 1. Clonar o repositório
git clone https://github.com/felipeds-cdc/cybersecurity-studies.git
cd cybersecurity-studies/engenharia-social/scripts

# 2. Instalar dependências do sistema
sudo apt update
sudo apt install whois dnsutils -y

# 3. Verificar instalação
python3 --version
whois --version
dig -v
```

---

## 🚀 Como rodar

### Sintaxe
```bash
python3 osint_collector.py <dominio>
```

### Exemplos
```bash
# Domínio simples
python3 osint_collector.py exemplo.com

# Domínio .com.br
python3 osint_collector.py meusite.com.br

# URL completa (o script limpa automaticamente)
python3 osint_collector.py https://exemplo.com/pagina

# Seu próprio domínio para testar
python3 osint_collector.py seudominio.com
```

> 💡 **Para testar sem alvo real:** Use `scanme.nmap.org` —
> servidor público autorizado para testes.

---

## 🏗️ Estrutura do código

```
osint_collector.py
│
├── Constantes de cor              (linhas ~15-22)
│   └── RED, GREEN, YELLOW, CYAN, BLUE, BOLD, RESET
│
├── banner()                       (linhas ~25-36)
│   └── Cabeçalho visual do script
│
├── Funções de output              (linhas ~39-43)
│   ├── titulo() → cabeçalho de seção
│   ├── ok()     → resultado positivo [+] verde
│   ├── info()   → informação neutra [*] amarelo
│   ├── erro()   → erro [!] vermelho
│   └── dado()   → dado coletado [→] azul
│
├── class Relatorio                (linhas ~46-80)
│   ├── __init__()  → inicializa com alvo e timestamp
│   ├── adicionar() → adiciona seção ao relatório
│   └── salvar()    → gera arquivo .txt formatado
│
├── modulo_dominio()               (linhas ~83-125)
│   └── MÓDULO 1: IP, Reverse DNS, WHOIS
│
├── modulo_dns()                   (linhas ~128-162)
│   └── MÓDULO 2: Registros DNS por tipo
│
├── modulo_subdominios()           (linhas ~165-210)
│   └── MÓDULO 3: Força bruta de subdomínios
│
├── modulo_http()                  (linhas ~213-278)
│   └── MÓDULO 4: Headers HTTP, tecnologias, cookies
│
├── modulo_emails()                (linhas ~281-330)
│   └── MÓDULO 5: Emails corporativos e WHOIS
│
├── modulo_geoip()                 (linhas ~333-375)
│   └── MÓDULO 6: Localização e provedor (ASN)
│
├── modulo_arquivos()              (linhas ~378-435)
│   └── MÓDULO 7: Arquivos sensíveis expostos
│
├── modulo_redes_sociais()         (linhas ~438-478)
│   └── MÓDULO 8: Perfis sociais e Google Dorks
│
├── modulo_seguranca()             (linhas ~481-525)
│   └── MÓDULO 9: SPF, DMARC, DKIM, HTTPS
│
└── main()                         (linhas ~528-fim)
    └── Valida argumento e executa todos os módulos
```

---

## 📦 Módulos explicados

### Módulo 1 — Domínio e WHOIS
```python
def modulo_dominio(dominio, relatorio):
    ip = socket.gethostbyname(dominio)
    reverse = socket.gethostbyaddr(ip)[0]
    resultado = subprocess.run(["whois", dominio], ...)
```
**O que coleta:** IP do servidor, Reverse DNS e dados do WHOIS
filtrados por campos relevantes.  
**Por que importa para ES:** O WHOIS pode expor emails de contato
do administrador — alvo primário de engenharia social.

---

### Módulo 2 — DNS Enumeration
```python
tipos = {"A": "IPv4", "MX": "Email", "NS": "Nameserver", ...}
subprocess.run(["dig", "+short", tipo, dominio], ...)
```
**O que coleta:** 7 tipos de registros DNS.  
**Por que importa para ES:** O registro MX revela o provedor de
email (Google Workspace, Microsoft 365, etc.) — útil para
construir pretextos convincentes.

---

### Módulo 3 — Subdomínios
```python
for sub in subdomínios:
    ip = socket.gethostbyname(f"{sub}.{dominio}")
```
**O que coleta:** Testa 65+ subdomínios comuns por resolução DNS.  
**Por que importa para ES:** Subdomínios como `intranet.`, `git.`,
`jenkins.` revelam ferramentas internas da empresa — informação
valiosa para construir pretextos de suporte técnico.

---

### Módulo 4 — Headers HTTP
```python
resp = urllib.request.urlopen(req, timeout=10)
resp.headers.get("Server")           # tecnologia do servidor
resp.headers.get("X-Powered-By")     # linguagem backend
resp.headers.get("Set-Cookie")       # flags de segurança
```
**O que coleta:** Servidor web, linguagem backend, headers de
segurança presentes/ausentes e flags de cookies.  
**Por que importa para ES:** `X-Powered-By: PHP/7.2.0` revela
versão específica com CVEs conhecidos — usado em pretextos de
"atualização urgente de segurança".

---

### Módulo 5 — Emails
```python
padroes = [f"contato@{dominio}", f"admin@{dominio}", ...]
emails_whois = re.findall(r'[a-zA-Z0-9._%+-]+@...', whois_output)
```
**O que coleta:** Padrões corporativos comuns + emails expostos
no WHOIS + formatos de email para construção de lista.  
**Por que importa para ES:** Email do administrador é o vetor
mais comum de spear phishing corporativo.

---

### Módulo 6 — Geo-IP e ASN
```python
url = f"https://ipinfo.io/{ip}/json"
dados = json.loads(resp.read().decode())
```
**O que coleta:** Cidade, país, provedor, ASN e detecção de CDN.  
**Por que importa para ES:** Detectar Cloudflare revela que o
IP real está oculto — importante para não atacar o CDN e sim
o servidor de origem.

---

### Módulo 7 — Arquivos Expostos
```python
caminhos = ["/robots.txt", "/.git/config", "/.env", ...]
resp = urllib.request.urlopen(url, timeout=5)
if resp.status == 200:
    # arquivo exposto publicamente
```
**O que coleta:** Verifica 15 caminhos sensíveis comuns.  
**Por que importa para ES:** `/.env` exposto pode conter
credenciais de banco de dados. `/.git/config` pode revelar
repositórios internos. `robots.txt` lista caminhos que a
empresa não quer que buscadores indexem.

---

### Módulo 8 — Redes Sociais e Dorks
```python
redes = {"LinkedIn": f"linkedin.com/company/{nome}", ...}
dorks = [f'site:linkedin.com "{dominio}"', ...]
```
**O que coleta:** URLs prováveis de perfis + Google Dorks
prontos para pesquisa manual.  
**Por que importa para ES:** LinkedIn é a principal fonte para
mapear funcionários, cargos e estrutura organizacional —
base do spear phishing.

---

### Módulo 9 — Análise de Segurança
```python
subprocess.run(["dig", "+short", "TXT", f"_dmarc.{dominio}"])
```
**O que coleta:** SPF, DMARC, DKIM e disponibilidade de HTTPS.  
**Por que importa para ES:** Ausência de SPF/DMARC significa
que qualquer um pode enviar emails se passando pelo domínio
da empresa — vetor direto de phishing.

---

### Classe Relatorio
```python
class Relatorio:
    def __init__(self, alvo):
        self.dados = {}           # dicionário com todos os módulos

    def adicionar(self, secao, conteudo):
        self.dados[secao] = conteudo   # cada módulo adiciona aqui

    def salvar(self):
        # gera arquivo .txt formatado com timestamp
```
**Por que usar classe:** Centraliza todos os dados coletados
durante a execução e gera o relatório final de uma vez, sem
precisar salvar arquivo em cada módulo separado.

---

## 📁 Arquivos gerados

Após executar, um arquivo é criado automaticamente:

```
osint_exemplo.com_20260322_102412.txt
```

**Estrutura do relatório:**
```
╔══════════════════════════════════════════════════╗
║              OSINT COLLECTOR — RELATÓRIO         ║
╚══════════════════════════════════════════════════╝

Alvo    : exemplo.com
Início  : 2026-03-22 10:24:12
Fim     : 2026-03-22 10:31:45
════════════════════════════════════════════════════

[DOMÍNIO]
────────────────────────────────────────
  Domínio: exemplo.com
  IP: 93.184.216.34
  Reverse DNS: 93.184.216.34.in-addr.arpa
  Registrar: ICANN
  ...

[DNS]
────────────────────────────────────────
  A: 93.184.216.34
  MX: mail.exemplo.com
  ...

[SUBDOMÍNIOS]
────────────────────────────────────────
  www.exemplo.com → 93.184.216.34
  mail.exemplo.com → 93.184.216.35
  ...
```

---

## 🔧 Como manter o código

### Adicionar novo módulo
```python
# 1. Criar função seguindo o padrão
def modulo_meu_novo(dominio, relatorio):
    titulo("MÓDULO X — NOME DO MÓDULO")
    resultados = []

    # sua lógica aqui
    ok(f"Dado coletado: {valor}")
    resultados.append(f"Campo: {valor}")

    relatorio.adicionar("NOME_SECAO", resultados)
    return resultados

# 2. Chamar no main() após os outros módulos
modulo_meu_novo(dominio, relatorio)
```

---

### Adicionar subdomínios à lista
```python
# Em modulo_subdominios(), adicione na lista subdomínios:
subdomínios = [
    # ... existentes ...
    "sonarqube",    # ferramenta de análise de código
    "vault",        # HashiCorp Vault
    "consul",       # HashiCorp Consul
    "k8s",          # Kubernetes dashboard
    "rancher",      # gerenciador de containers
]
```

---

### Adicionar arquivos para verificar
```python
# Em modulo_arquivos(), adicione na lista caminhos:
caminhos = [
    # ... existentes ...
    "/server-status",        # Apache status page
    "/nginx_status",         # Nginx status
    "/.DS_Store",            # macOS metadata
    "/web.config",           # IIS config
    "/application.wadl",     # REST API descriptor
]
```

---

### Trocar API de Geo-IP
```python
# Atual: ipinfo.io (gratuita, 50k req/mês)
url = f"https://ipinfo.io/{ip}/json"

# Alternativa 1: ip-api.com (gratuita, sem chave)
url = f"http://ip-api.com/json/{ip}"

# Alternativa 2: ipgeolocation.io (chave gratuita)
url = f"https://api.ipgeolocation.io/ipgeo?apiKey=CHAVE&ip={ip}"
```

---

## 💡 Exemplos reais

### Testar no seu próprio domínio
```bash
python3 osint_collector.py seudominio.com
```

### Integrar com outros scripts do portfólio
```bash
# Passo 1: OSINT para coletar informações gerais
python3 osint_collector.py alvo.com

# Passo 2: Footprinting detalhado
python3 footprinting_tool.py alvo.com

# Passo 3: Varredura ativa com Nmap
sudo ./nmap_recon.sh <ip-encontrado> full
```

### Usar em lab do TryHackMe
```bash
# Conecte na VPN do TryHackMe
# Use o domínio ou IP da máquina alvo
python3 osint_collector.py 10.10.x.x
```

---

## 🛠️ Solução de problemas

**Erro: `whois: command not found`**
```bash
sudo apt install whois -y
```

**Erro: `dig: command not found`**
```bash
sudo apt install dnsutils -y
```

**Módulo de subdomínios muito lento**
```python
# Reduza o timeout em modulo_subdominios():
ip = socket.gethostbyname(host)
socket.setdefaulttimeout(0.5)    # de padrão para 0.5s
```

**Geo-IP retornando erro**
```
A API ipinfo.io tem limite de 50.000 requisições/mês.
Se atingir o limite, troque pela ip-api.com conforme
explicado na seção "Como manter o código".
```

**Script interrompido no meio**
```bash
# O relatório só é gerado no final.
# Para salvar parcialmente, adicione Ctrl+C handler no main():
try:
    # módulos aqui
except KeyboardInterrupt:
    print("\nInterrompido — salvando relatório parcial...")
    arquivo = relatorio.salvar()
```

---

## 📚 Referências

- [OSINT Framework](https://osintframework.com)
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)
- [ipinfo.io API](https://ipinfo.io/developers)
- [Google Dorks Database](https://www.exploit-db.com/google-hacking-database)
- [OWASP — Testing for Information Leakage](https://owasp.org/www-project-web-security-testing-guide)

---

## ⚠️ Aviso Legal

```
Este script coleta APENAS informações públicas disponíveis
em fontes abertas (OSINT). Ainda assim, o uso deve ser
responsável e ético.

Ambientes autorizados para prática:
  • Seus próprios domínios e servidores
  • HackTheBox e TryHackMe (dentro da VPN)
  • scanme.nmap.org (autorizado pelo Nmap)
  • Empresas com programa de Bug Bounty ativo

NUNCA use em:
  • Domínios de terceiros sem autorização
  • Pessoas físicas sem consentimento
  • Infraestrutura governamental

Lei nº 12.737/2012 — Delitos Informáticos
Art. 171 CP — Estelionato
```
