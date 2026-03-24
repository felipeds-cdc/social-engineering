#!/usr/bin/env python3
# ============================================
# OSINT Collector - Engenharia Social
# Autor: Felipe Diassis
# GitHub: github.com/felipeds-cdc
# ============================================
# AVISO: Use apenas para fins educacionais
# e em pessoas que autorizaram a coleta.
# Lei 12.737/2012 — Lei Carolina Dieckmann
# Art. 171 CP — Estelionato
# ============================================

import socket
import subprocess
import sys
import json
import datetime
import urllib.request
import urllib.parse
import urllib.error
import re
import os

# ============================================
# CORES
# ============================================
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ============================================
# BANNER
# ============================================
def banner():
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════╗
║            OSINT COLLECTOR v1.0                  ║
║         github.com/felipeds-cdc                  ║
║   ⚠  Apenas para fins educacionais  ⚠            ║
╚══════════════════════════════════════════════════╝
{RESET}""")

# ============================================
# UTILITÁRIOS
# ============================================
def titulo(texto):
    print(f"\n{CYAN}{BOLD}{'═'*52}")
    print(f"  {texto}")
    print(f"{'═'*52}{RESET}")

def ok(texto):    print(f"  {GREEN}[+]{RESET} {texto}")
def info(texto):  print(f"  {YELLOW}[*]{RESET} {texto}")
def erro(texto):  print(f"  {RED}[!]{RESET} {texto}")
def dado(texto):  print(f"  {BLUE}[→]{RESET} {texto}")

# ============================================
# RELATÓRIO
# ============================================
class Relatorio:
    def __init__(self, alvo):
        self.alvo    = alvo
        self.dados   = {}
        self.inicio  = datetime.datetime.now()

    def adicionar(self, secao, conteudo):
        self.dados[secao] = conteudo

    def salvar(self):
        timestamp   = self.inicio.strftime("%Y%m%d_%H%M%S")
        nome        = f"osint_{self.alvo.replace(' ', '_')}_{timestamp}.txt"

        with open(nome, "w", encoding="utf-8") as f:
            f.write("╔══════════════════════════════════════════════════╗\n")
            f.write("║              OSINT COLLECTOR — RELATÓRIO         ║\n")
            f.write("╚══════════════════════════════════════════════════╝\n\n")
            f.write(f"Alvo    : {self.alvo}\n")
            f.write(f"Início  : {self.inicio.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Fim     : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"{'═'*52}\n")

            for secao, itens in self.dados.items():
                f.write(f"\n\n[{secao}]\n")
                f.write(f"{'─'*40}\n")
                if isinstance(itens, list):
                    for item in itens:
                        f.write(f"  {item}\n")
                else:
                    f.write(f"  {itens}\n")

            f.write(f"\n\n{'═'*52}\n")
            f.write("⚠  Este relatório é confidencial e educacional.\n")
            f.write("⚠  Lei 12.737/2012 — Uso não autorizado é crime.\n")

        return nome

# ============================================
# MÓDULO 1 — INFORMAÇÕES BÁSICAS DE DOMÍNIO
# ============================================
def modulo_dominio(dominio, relatorio):
    titulo("MÓDULO 1 — INFORMAÇÕES DO DOMÍNIO")
    resultados = []

    # Resolve IP
    try:
        ip = socket.gethostbyname(dominio)
        ok(f"Domínio  : {dominio}")
        ok(f"IP       : {ip}")
        resultados.append(f"Domínio: {dominio}")
        resultados.append(f"IP: {ip}")

        # Reverse DNS
        try:
            reverse = socket.gethostbyaddr(ip)[0]
            ok(f"Reverse  : {reverse}")
            resultados.append(f"Reverse DNS: {reverse}")
        except:
            info("Reverse DNS: não encontrado")

    except socket.gaierror:
        erro(f"Não foi possível resolver: {dominio}")
        return []

    # WHOIS
    try:
        resultado = subprocess.run(
            ["whois", dominio],
            capture_output=True, text=True, timeout=15
        )
        campos = [
            "registrar", "creation date", "expiration date",
            "updated date", "registrant", "org:", "country",
            "name server", "admin email", "tech email"
        ]
        info("Dados WHOIS:")
        for linha in resultado.stdout.splitlines():
            for campo in campos:
                if campo.lower() in linha.lower() and linha.strip():
                    dado(linha.strip())
                    resultados.append(linha.strip())
                    break
    except FileNotFoundError:
        erro("whois não instalado: sudo apt install whois")
    except subprocess.TimeoutExpired:
        erro("WHOIS timeout")

    relatorio.adicionar("DOMÍNIO", resultados)
    return resultados

# ============================================
# MÓDULO 2 — ENUMERAÇÃO DNS
# ============================================
def modulo_dns(dominio, relatorio):
    titulo("MÓDULO 2 — ENUMERAÇÃO DNS")
    resultados = []
    tipos = {
        "A"    : "Endereço IPv4 do servidor",
        "AAAA" : "Endereço IPv6",
        "MX"   : "Servidores de email",
        "NS"   : "Nameservers",
        "TXT"  : "Verificações SPF/DKIM/outros",
        "CNAME": "Aliases de domínio",
        "SOA"  : "Autoridade da zona DNS",
    }

    for tipo, descricao in tipos.items():
        try:
            resultado = subprocess.run(
                ["dig", "+short", tipo, dominio],
                capture_output=True, text=True, timeout=10
            )
            saida = resultado.stdout.strip()
            if saida:
                ok(f"{tipo:<6} ({descricao})")
                for linha in saida.splitlines():
                    dado(linha)
                    resultados.append(f"{tipo}: {linha}")
            else:
                info(f"{tipo:<6} → sem registro")
        except FileNotFoundError:
            erro("dig não instalado: sudo apt install dnsutils")
            break
        except subprocess.TimeoutExpired:
            erro(f"Timeout no tipo {tipo}")

    relatorio.adicionar("DNS", resultados)
    return resultados

# ============================================
# MÓDULO 3 — SUBDOMÍNIOS
# ============================================
def modulo_subdominios(dominio, relatorio):
    titulo("MÓDULO 3 — FORÇA BRUTA DE SUBDOMÍNIOS")
    resultados  = []
    encontrados = 0

    subdomínios = [
        # Infraestrutura
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
        "mx", "ns1", "ns2", "dns", "vpn", "remote", "gateway",
        # Administração
        "admin", "administrator", "portal", "painel", "cpanel",
        "plesk", "whm", "dashboard", "manage", "management",
        # Desenvolvimento
        "dev", "development", "staging", "homolog", "uat",
        "test", "testing", "beta", "alpha", "sandbox",
        # Aplicações
        "api", "app", "mobile", "ws", "web", "cdn", "static",
        "media", "assets", "upload", "downloads", "files",
        # Serviços internos
        "intranet", "internal", "corp", "corporate", "office",
        "git", "gitlab", "github", "jenkins", "jira", "confluence",
        "kibana", "grafana", "prometheus", "monitor", "nagios",
        # Banco de dados
        "db", "database", "mysql", "pgsql", "redis", "mongo",
        # Segurança
        "secure", "security", "auth", "login", "sso", "oauth",
        # E-commerce
        "shop", "store", "loja", "pay", "payment", "checkout",
        # Blog / Conteúdo
        "blog", "news", "forum", "support", "help", "docs",
    ]

    info(f"Testando {len(subdomínios)} subdomínios...")

    for sub in subdomínios:
        host = f"{sub}.{dominio}"
        try:
            ip = socket.gethostbyname(host)
            ok(f"{host:<45} → {ip}")
            resultados.append(f"{host} → {ip}")
            encontrados += 1
        except socket.gaierror:
            pass

    if encontrados == 0:
        info("Nenhum subdomínio encontrado")
    else:
        info(f"Total encontrado: {encontrados} subdomínios")

    relatorio.adicionar("SUBDOMÍNIOS", resultados)
    return resultados

# ============================================
# MÓDULO 4 — HEADERS HTTP E TECNOLOGIAS
# ============================================
def modulo_http(dominio, relatorio):
    titulo("MÓDULO 4 — HEADERS HTTP E TECNOLOGIAS")
    resultados = []

    for protocolo in ["https", "http"]:
        url = f"{protocolo}://{dominio}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
            )
            resp = urllib.request.urlopen(req, timeout=10)

            ok(f"URL    : {url}")
            ok(f"Status : {resp.status}")
            resultados.append(f"URL: {url}")
            resultados.append(f"Status: {resp.status}")

            # Headers de tecnologia
            tech_headers = [
                "Server", "X-Powered-By", "X-Generator",
                "X-Drupal-Cache", "X-WordPress", "X-Shopify-Stage"
            ]
            info("Tecnologias detectadas:")
            for h in tech_headers:
                v = resp.headers.get(h)
                if v:
                    ok(f"{h}: {v}")
                    resultados.append(f"Tecnologia — {h}: {v}")

            # Headers de segurança
            sec_headers = [
                "X-Frame-Options", "Content-Security-Policy",
                "Strict-Transport-Security", "X-XSS-Protection",
                "X-Content-Type-Options", "Referrer-Policy",
                "Permissions-Policy"
            ]
            info("Headers de segurança:")
            for h in sec_headers:
                v = resp.headers.get(h)
                status = ok if v else info
                msg    = v if v else "AUSENTE ← possível vulnerabilidade"
                print(f"  {'✓' if v else '✗'} {h}: {msg}")
                resultados.append(f"Segurança — {h}: {msg}")

            # Cookies
            cookies = resp.headers.get("Set-Cookie")
            if cookies:
                info("Cookies:")
                dado(cookies)
                resultados.append(f"Cookies: {cookies}")

                # Verifica flags de segurança
                if "HttpOnly" not in cookies:
                    dado("  ⚠ HttpOnly ausente — cookie acessível via JS")
                if "Secure" not in cookies:
                    dado("  ⚠ Secure ausente — cookie enviado por HTTP")
                if "SameSite" not in cookies:
                    dado("  ⚠ SameSite ausente — vulnerável a CSRF")

            break

        except urllib.error.URLError as e:
            info(f"{protocolo.upper()} falhou: {e.reason}")
        except Exception as e:
            info(f"{protocolo.upper()} erro: {e}")

    relatorio.adicionar("HTTP", resultados)
    return resultados

# ============================================
# MÓDULO 5 — EMAILS E CONTATOS PÚBLICOS
# ============================================
def modulo_emails(dominio, relatorio):
    titulo("MÓDULO 5 — EMAILS E CONTATOS PÚBLICOS")
    resultados = []

    # Padrões comuns de email corporativo
    padroes = [
        f"contato@{dominio}",
        f"contact@{dominio}",
        f"admin@{dominio}",
        f"suporte@{dominio}",
        f"support@{dominio}",
        f"rh@{dominio}",
        f"hr@{dominio}",
        f"ti@{dominio}",
        f"it@{dominio}",
        f"security@{dominio}",
        f"abuse@{dominio}",
        f"postmaster@{dominio}",
        f"webmaster@{dominio}",
        f"info@{dominio}",
        f"financeiro@{dominio}",
    ]

    info("Padrões de email corporativo comuns:")
    for email in padroes:
        dado(email)
        resultados.append(email)

    # Verifica WHOIS email
    try:
        resultado = subprocess.run(
            ["whois", dominio],
            capture_output=True, text=True, timeout=10
        )
        emails_whois = re.findall(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            resultado.stdout
        )
        if emails_whois:
            info("Emails encontrados no WHOIS:")
            for e in set(emails_whois):
                ok(e)
                resultados.append(f"WHOIS: {e}")
    except:
        pass

    # Formato de email corporativo
    info("Formatos corporativos mais comuns para construir emails:")
    nomes_exemplo = ["joao.silva", "j.silva", "joaosilva", "silva.joao"]
    for formato in nomes_exemplo:
        dado(f"{formato}@{dominio}")

    relatorio.adicionar("EMAILS", resultados)
    return resultados

# ============================================
# MÓDULO 6 — GEOLOCALIZAÇÃO E ASN
# ============================================
def modulo_geoip(dominio, relatorio):
    titulo("MÓDULO 6 — GEOLOCALIZAÇÃO E ASN")
    resultados = []

    try:
        ip = socket.gethostbyname(dominio)
        url = f"https://ipinfo.io/{ip}/json"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        resp  = urllib.request.urlopen(req, timeout=10)
        dados = json.loads(resp.read().decode())

        campos = {
            "IP"       : dados.get("ip", "N/A"),
            "Hostname" : dados.get("hostname", "N/A"),
            "Cidade"   : dados.get("city", "N/A"),
            "Região"   : dados.get("region", "N/A"),
            "País"     : dados.get("country", "N/A"),
            "Org/ASN"  : dados.get("org", "N/A"),
            "Timezone" : dados.get("timezone", "N/A"),
            "Localização": dados.get("loc", "N/A"),
        }

        for chave, valor in campos.items():
            ok(f"{chave:<12}: {valor}")
            resultados.append(f"{chave}: {valor}")

        # Análise do ASN
        org = dados.get("org", "")
        info("Análise da infraestrutura:")
        provedores = {
            "Amazon"    : "AWS — Hospedagem em nuvem",
            "Google"    : "Google Cloud — Hospedagem em nuvem",
            "Microsoft" : "Azure — Hospedagem em nuvem",
            "Cloudflare": "CDN Cloudflare — IP real pode estar oculto",
            "Akamai"    : "CDN Akamai — IP real pode estar oculto",
            "Fastly"    : "CDN Fastly — IP real pode estar oculto",
        }
        for provedor, descricao in provedores.items():
            if provedor.lower() in org.lower():
                dado(descricao)
                resultados.append(f"Infraestrutura: {descricao}")
                break

    except Exception as e:
        erro(f"Geo-IP falhou: {e}")

    relatorio.adicionar("GEOLOCALIZAÇÃO", resultados)
    return resultados

# ============================================
# MÓDULO 7 — METADADOS DE ARQUIVOS PÚBLICOS
# ============================================
def modulo_arquivos(dominio, relatorio):
    titulo("MÓDULO 7 — ARQUIVOS PÚBLICOS EXPOSTOS")
    resultados = []

    # Caminhos comuns expostos
    caminhos = [
        "/robots.txt",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/crossdomain.xml",
        "/humans.txt",
        "/readme.txt",
        "/README.md",
        "/CHANGELOG.md",
        "/.git/config",
        "/.env",
        "/wp-config.php.bak",
        "/config.php.bak",
        "/backup.zip",
        "/dump.sql",
        "/phpinfo.php",
    ]

    info(f"Verificando {len(caminhos)} caminhos sensíveis...")

    for caminho in caminhos:
        for protocolo in ["https", "http"]:
            url = f"{protocolo}://{dominio}{caminho}"
            try:
                req  = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                resp = urllib.request.urlopen(req, timeout=5)

                if resp.status == 200:
                    tamanho = resp.headers.get("Content-Length", "?")
                    ok(f"ENCONTRADO [{resp.status}] {url} ({tamanho} bytes)")
                    resultados.append(f"Exposto: {url} [{resp.status}]")

                    # Lê conteúdo de arquivos de texto pequenos
                    tipo = resp.headers.get("Content-Type", "")
                    if "text" in tipo and tamanho != "?" and int(tamanho or 0) < 10000:
                        conteudo = resp.read().decode("utf-8", errors="ignore")
                        # Busca emails no conteúdo
                        emails = re.findall(
                            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                            conteudo
                        )
                        if emails:
                            for e in set(emails):
                                dado(f"  Email encontrado: {e}")
                                resultados.append(f"  Email em {caminho}: {e}")
                break
            except urllib.error.HTTPError as e:
                if e.code not in [404, 403, 401]:
                    info(f"[{e.code}] {caminho}")
            except:
                pass

    if not resultados:
        info("Nenhum arquivo sensível encontrado publicamente")

    relatorio.adicionar("ARQUIVOS EXPOSTOS", resultados)
    return resultados

# ============================================
# MÓDULO 8 — REDES SOCIAIS
# ============================================
def modulo_redes_sociais(dominio, relatorio):
    titulo("MÓDULO 8 — PRESENÇA EM REDES SOCIAIS")
    resultados = []

    # Extrai nome da empresa do domínio
    nome = dominio.split(".")[0]

    redes = {
        "LinkedIn"  : f"https://linkedin.com/company/{nome}",
        "GitHub"    : f"https://github.com/{nome}",
        "Twitter/X" : f"https://twitter.com/{nome}",
        "Instagram" : f"https://instagram.com/{nome}",
        "Facebook"  : f"https://facebook.com/{nome}",
        "YouTube"   : f"https://youtube.com/@{nome}",
    }

    info(f"Perfis prováveis para '{nome}':")
    for rede, url in redes.items():
        dado(f"{rede:<12}: {url}")
        resultados.append(f"{rede}: {url}")

    # Google Dorks sugeridos
    info("Google Dorks para investigação adicional:")
    dorks = [
        f'site:linkedin.com "{dominio}"',
        f'site:linkedin.com/in "{nome}"',
        f'"@{dominio}" filetype:pdf',
        f'site:{dominio} filetype:pdf',
        f'site:{dominio} inurl:admin',
        f'site:{dominio} intitle:"index of"',
        f'"{dominio}" "senha" OR "password" OR "leak"',
    ]
    for dork in dorks:
        dado(dork)
        resultados.append(f"Dork: {dork}")

    relatorio.adicionar("REDES SOCIAIS", resultados)
    return resultados

# ============================================
# MÓDULO 9 — ANÁLISE DE SEGURANÇA
# ============================================
def modulo_seguranca(dominio, relatorio):
    titulo("MÓDULO 9 — ANÁLISE DE SEGURANÇA")
    resultados = []

    # Verifica registros de segurança DNS
    registros_seg = {
        "SPF"  : f"dig +short TXT {dominio} | grep spf",
        "DMARC": f"dig +short TXT _dmarc.{dominio}",
        "DKIM" : f"dig +short TXT default._domainkey.{dominio}",
    }

    for nome_reg, comando in registros_seg.items():
        try:
            partes   = comando.split()
            resultado = subprocess.run(
                partes[:4], capture_output=True, text=True, timeout=10
            )
            saida = resultado.stdout.strip()

            if saida and nome_reg.lower() in saida.lower():
                ok(f"{nome_reg} configurado: {saida[:80]}...")
                resultados.append(f"{nome_reg}: Configurado")
            else:
                dado(f"{nome_reg}: ⚠ Não encontrado — vulnerável a email spoofing")
                resultados.append(f"{nome_reg}: AUSENTE")
        except:
            pass

    # Verifica HTTPS
    info("Verificando HTTPS...")
    try:
        url = f"https://{dominio}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        urllib.request.urlopen(req, timeout=5)
        ok("HTTPS disponível")
        resultados.append("HTTPS: Disponível")
    except:
        dado("⚠ HTTPS indisponível ou certificado inválido")
        resultados.append("HTTPS: Indisponível")

    # Score de exposição
    info("Score de exposição estimado:")
    score = len([r for r in resultados if "AUSENTE" in r or "⚠" in r])
    if score == 0:
        ok("Baixa exposição — boas práticas de segurança")
    elif score <= 2:
        dado(f"Exposição moderada — {score} problema(s) encontrado(s)")
    else:
        erro(f"Alta exposição — {score} problema(s) encontrado(s)")

    relatorio.adicionar("SEGURANÇA", resultados)
    return resultados

# ============================================
# MAIN
# ============================================
def main():
    banner()

    if len(sys.argv) < 2:
        print(f"  {BOLD}USO:{RESET}")
        print(f"    python3 osint_collector.py <dominio>")
        print(f"\n  {BOLD}EXEMPLOS:{RESET}")
        print(f"    python3 osint_collector.py exemplo.com")
        print(f"    python3 osint_collector.py meusite.com.br\n")
        sys.exit(1)

    dominio = sys.argv[1]
    dominio = dominio.replace("https://","").replace("http://","").rstrip("/")

    relatorio = Relatorio(dominio)

    print(f"\n  {BOLD}Alvo   :{RESET} {dominio}")
    print(f"  {BOLD}Início :{RESET} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n  {YELLOW}⚠  Use apenas em domínios autorizados{RESET}")

    # Executa módulos
    modulo_dominio       (dominio, relatorio)
    modulo_dns           (dominio, relatorio)
    modulo_subdominios   (dominio, relatorio)
    modulo_http          (dominio, relatorio)
    modulo_emails        (dominio, relatorio)
    modulo_geoip         (dominio, relatorio)
    modulo_arquivos      (dominio, relatorio)
    modulo_redes_sociais (dominio, relatorio)
    modulo_seguranca     (dominio, relatorio)

    # Salva relatório
    titulo("RELATÓRIO FINAL")
    arquivo = relatorio.salvar()
    ok(f"Relatório salvo: {arquivo}")
    print(f"\n  {YELLOW}⚠  Lei 12.737/2012 — Use apenas em ambientes autorizados{RESET}\n")

if __name__ == "__main__":
    main()
