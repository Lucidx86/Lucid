import socket
import requests
import whois
import dns.resolver
import ssl
import os
import time
import json
import re
import sys
import shodan
from datetime import datetime
from colorama import Fore, Style, init
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Inicialização do Colorama
init(autoreset=True)

# Configuração de Cores
class Cores:
    VERMELHO = Fore.RED
    VERDE = Fore.GREEN
    AMARELO = Fore.YELLOW
    CIANO = Fore.CYAN
    BRANCO = Fore.WHITE
    AZUL = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    DESTAQUE = Style.BRIGHT
    NEGRITO = Style.BRIGHT
    NORMAL = Style.NORMAL
    RESET = Style.RESET_ALL

# Arte ASCII Premium - Design Profissional
BANNER_LUCID = f"""
{Cores.CIANO}
▓█████▄  █    ██  ██▀███   ██▓███  ▄▄▄█████▓
▒██▀ ██▌ ██  ▓██▒▓██ ▒ ██▒▓██░  ██▒▓  ██▒ ▓▒
░██   █▌▓██  ▒██░▓██ ░▄█ ▒▓██░ ██▓▒▒ ▓██░ ▒░
░▓█▄   ▌▓▓█  ░██░▒██▀▀█▄  ▒██▄█▓▒ ▒░ ▓██▓ ░ 
░▒████▓ ▒▒█████▓ ░██▓ ▒██▒▒██▒ ░  ░  ▒██▒ ░ 
 ▒▒▓  ▒ ░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░  ▒ ░░   
 ░ ▒  ▒ ░░▒░ ░ ░   ░▒ ░ ▒░░▒ ░         ░    
 ░ ░  ░  ░░░ ░ ░   ░░   ░ ░░         ░      
   ░       ░        ░                      
 ░                                          
{Cores.RESET}
"""

# Informações da Versão
VERSAO = "5.0 PRO"
AUTOR = "Equipe LUCID"
DATA_LANCAMENTO = "2024"
CONTATO = "contato@lucidsecurity.com.br"

# Configurações Globais
TEMPO_ESPERA = 10
USER_AGENT = "LUCID-Scanner/5.0 (Professional Security Tool)"
SUBDOMINIOS_COMUNS = ["www", "mail", "ftp", "webmail", "cpanel", "blog", "shop", 
                     "smtp", "api", "dev", "test", "admin", "secure", "vpn", "ns1",
                     "ns2", "mx", "web", "app", "cloud", "dashboard", "api2", "cdn",
                     "static", "backup", "db", "mysql", "phpmyadmin", "teste"]

# Inicialização da API Shodan (opcional)
SHODAN_API_KEY = None
try:
    from config import SHODAN_API_KEY
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
except:
    shodan_api = None

# Funções de Utilidade
def limpar_tela():
    """Limpa a tela do terminal de forma multiplataforma."""
    os.system("cls" if os.name == "nt" else "clear")

def efeito_digitacao(texto, delay=0.015, cor=Cores.BRANCO):
    """Exibe texto com efeito de digitação."""
    print(cor, end='')
    for char in texto:
        print(char, end='', flush=True)
        time.sleep(delay)
    print(Cores.RESET)

def mostrar_status(mensagem, status="info"):
    """Exibe mensagens de status formatadas."""
    if status == "sucesso":
        print(f"{Cores.VERDE}[✓] {mensagem}{Cores.RESET}")
    elif status == "erro":
        print(f"{Cores.VERMELHO}[✗] {mensagem}{Cores.RESET}")
    elif status == "alerta":
        print(f"{Cores.AMARELO}[!] {mensagem}{Cores.RESET}")
    elif status == "info":
        print(f"{Cores.CIANO}[i] {mensagem}{Cores.RESET}")
    elif status == "destaque":
        print(f"{Cores.AZUL}{Cores.NEGRITO}[*] {mensagem}{Cores.RESET}")

def validar_dominio(dominio):
    """Valida o formato do domínio."""
    padrao = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
    return re.match(padrao, dominio) is not None

def formatar_data_hora():
    """Retorna a data e hora formatadas."""
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")

def cabecalho_secao(titulo, caractere="=", cor=Cores.CIANO):
    """Cria um cabeçalho de seção formatado."""
    print(f"\n{cor}{titulo.center(60, caractere)}{Cores.RESET}")

def aguardar_enter():
    """Aguarda pressionamento da tecla Enter."""
    input(f"\n{Cores.AMARELO}[Pressione ENTER para continuar...]{Cores.RESET}")

def verificar_conexao():
    """Verifica se há conexão com a internet."""
    try:
        requests.get("https://google.com", timeout=3)
        return True
    except:
        return False

# Funções de Análise
def scan_ip(dominio):
    """Realiza análise completa de endereço IP."""
    cabecalho_secao(" ANÁLISE DE IP ", "=")
    
    try:
        ip = socket.gethostbyname(dominio)
        mostrar_status(f"Domínio: {dominio}", "sucesso")
        mostrar_status(f"Endereço IP: {ip}", "info")
        
        # Obter nome do host reverso
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            mostrar_status(f"Host Reverso: {hostname}", "info")
        except:
            pass
        
        # Geolocalização
        try:
            resposta = requests.get(f"http://ip-api.com/json/{ip}", timeout=TEMPO_ESPERA)
            dados_geo = resposta.json()
            
            if dados_geo['status'] == 'success':
                cabecalho_secao(" GEOLOCALIZAÇÃO ", "-", Cores.AZUL)
                print(f"{Cores.BRANCO}País: {Cores.VERDE}{dados_geo.get('country', 'N/A')}")
                print(f"{Cores.BRANCO}Região: {Cores.VERDE}{dados_geo.get('regionName', 'N/A')}")
                print(f"{Cores.BRANCO}Cidade: {Cores.VERDE}{dados_geo.get('city', 'N/A')}")
                print(f"{Cores.BRANCO}Provedor: {Cores.VERDE}{dados_geo.get('isp', 'N/A')}")
                print(f"{Cores.BRANCO}ASN: {Cores.VERDE}{dados_geo.get('as', 'N/A')}")
                print(f"{Cores.BRANCO}Organização: {Cores.VERDE}{dados_geo.get('org', 'N/A')}")
        except Exception as e:
            mostrar_status(f"Erro na geolocalização: {str(e)}", "erro")
        
        # Consulta Shodan (se disponível)
        if shodan_api:
            try:
                resultado = shodan_api.host(ip)
                cabecalho_secao(" DADOS SHODAN ", "-", Cores.MAGENTA)
                
                if 'ports' in resultado:
                    print(f"{Cores.BRANCO}Portas Abertas: {Cores.VERDE}{', '.join(map(str, resultado['ports']))}")
                
                if 'vulns' in resultado:
                    print(f"{Cores.BRANCO}Vulnerabilidades: {Cores.VERMELHO}{', '.join(resultado['vulns'])}")
                
                if 'os' in resultado:
                    print(f"{Cores.BRANCO}Sistema Operacional: {Cores.VERDE}{resultado['os']}")
                
            except shodan.APIError as e:
                mostrar_status(f"Shodan: {str(e)}", "alerta")
            except Exception as e:
                mostrar_status(f"Erro na API Shodan: {str(e)}", "erro")
                
    except socket.gaierror:
        mostrar_status("Não foi possível resolver o endereço IP", "erro")
    except Exception as e:
        mostrar_status(f"Erro na análise de IP: {str(e)}", "erro")

def whois_avancado(dominio):
    """Realiza consulta WHOIS detalhada."""
    cabecalho_secao(" WHOIS AVANÇADO ", "=")
    
    try:
        dados = whois.whois(dominio)
        mostrar_status(f"Informações WHOIS para {dominio}:", "sucesso")
        
        # Formatação dos dados WHOIS
        cabecalho_secao(" INFORMAÇÕES REGISTRO ", "-", Cores.AZUL)
        if dados.domain_name:
            print(f"{Cores.CIANO}Domínio: {Cores.BRANCO}{dados.domain_name}")
        
        if dados.registrar:
            print(f"{Cores.CIANO}Registrante: {Cores.BRANCO}{dados.registrar}")
        
        if dados.creation_date:
            data_criacao = dados.creation_date[0] if isinstance(dados.creation_date, list) else dados.creation_date
            idade_dominio = (datetime.now() - data_criacao).days
            print(f"{Cores.CIANO}Criação: {Cores.BRANCO}{data_criacao.strftime('%d/%m/%Y')} ({idade_dominio} dias atrás)")
        
        if dados.expiration_date:
            data_exp = dados.expiration_date[0] if isinstance(dados.expiration_date, list) else dados.expiration_date
            dias_restantes = (data_exp - datetime.now()).days
            print(f"{Cores.CIANO}Expiração: {Cores.BRANCO}{data_exp.strftime('%d/%m/%Y')} ({dias_restantes} dias restantes)")
        
        if dados.updated_date:
            data_atualizacao = dados.updated_date[0] if isinstance(dados.updated_date, list) else dados.updated_date
            print(f"{Cores.CIANO}Última Atualização: {Cores.BRANCO}{data_atualizacao.strftime('%d/%m/%Y')}")
        
        # Informações de contato
        cabecalho_secao(" CONTATOS ", "-", Cores.AZUL)
        if dados.emails:
            emails = dados.emails if isinstance(dados.emails, list) else [dados.emails]
            print(f"{Cores.CIANO}E-mails:{Cores.BRANCO}")
            for email in emails:
                print(f"  - {email}")
        
        if dados.phone:
            print(f"{Cores.CIANO}Telefone: {Cores.BRANCO}{dados.phone}")
        
        # Servidores DNS
        if dados.name_servers:
            cabecalho_secao(" SERVIDORES DNS ", "-", Cores.AZUL)
            for ns in set(dados.name_servers):
                print(f"{Cores.BRANCO}- {ns}")
        
    except Exception as e:
        mostrar_status(f"Erro na consulta WHOIS: {str(e)}", "erro")

def analise_dns(dominio):
    """Realiza análise completa de registros DNS."""
    cabecalho_secao(" ANÁLISE DNS ", "=")
    
    tipos_registros = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']
    
    for tipo in tipos_registros:
        try:
            resposta = dns.resolver.resolve(dominio, tipo)
            mostrar_status(f"Registros {tipo}:", "sucesso")
            
            for dado in resposta:
                print(f"{Cores.BRANCO}- {dado.to_text()}")
                
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            mostrar_status(f"Domínio {dominio} não existe", "erro")
            break
        except Exception as e:
            mostrar_status(f"Erro ao buscar {tipo}: {str(e)}", "erro")

def scan_subdominios(dominio):
    """Varredura avançada de subdomínios."""
    cabecalho_secao(" VARREURA DE SUBDOMÍNIOS ", "=")
    
    encontrados = False
    total = len(SUBDOMINIOS_COMUNS)
    atual = 0
    
    for sub in SUBDOMINIOS_COMUNS:
        atual += 1
        sub_completo = f"{sub}.{dominio}"
        progresso = f"[{atual}/{total}]"
        
        try:
            ip = socket.gethostbyname(sub_completo)
            mostrar_status(f"{progresso} Encontrado: {sub_completo.ljust(30)} → {ip}", "sucesso")
            encontrados = True
        except socket.gaierror:
            continue
        except Exception as e:
            mostrar_status(f"Erro verificando {sub_completo}: {str(e)}", "erro")
    
    if not encontrados:
        mostrar_status("Nenhum subdomínio comum encontrado", "alerta")
    
    # Verificação de wildcard DNS
    try:
        ip_wildcard = socket.gethostbyname(f"teste123456.{dominio}")
        mostrar_status(f"Possível wildcard DNS configurado: {ip_wildcard}", "alerta")
    except:
        pass

def analise_headers(dominio):
    """Análise detalhada de cabeçalhos HTTP."""
    cabecalho_secao(" ANÁLISE DE CABEÇALHOS ", "=")
    
    try:
        url = f"https://{dominio}" if not dominio.startswith(('http://', 'https://')) else dominio
        resposta = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=TEMPO_ESPERA, verify=False)
        
        mostrar_status(f"Cabeçalhos para {dominio}:", "sucesso")
        
        # Cabeçalhos de segurança importantes
        cab_seguranca = {
            'strict-transport-security': 'HSTS (Proteção HTTPS)',
            'x-frame-options': 'Proteção contra Clickjacking',
            'x-content-type-options': 'Prevenção MIME Sniffing',
            'content-security-policy': 'Política de Segurança de Conteúdo',
            'x-xss-protection': 'Proteção XSS',
            'referrer-policy': 'Política de Referência',
            'permissions-policy': 'Política de Permissões'
        }
        
        # Exibir todos os cabeçalhos
        for cab, valor in resposta.headers.items():
            cor = Cores.VERDE if cab.lower() in cab_seguranca else Cores.BRANCO
            print(f"{Cores.CIANO}{cab}: {cor}{valor}")
        
        # Verificar cabeçalhos de segurança ausentes
        ausentes = []
        for sec_cab in cab_seguranca:
            if sec_cab not in map(str.lower, resposta.headers.keys()):
                ausentes.append(sec_cab)
        
        if ausentes:
            cabecalho_secao(" CABEÇALHOS DE SEGURANÇA AUSENTES ", "-", Cores.AMARELO)
            for cab in ausentes:
                print(f"{Cores.VERMELHO}- {cab}: {cab_seguranca[cab]}")
        
        # Verificar servidor web
        if 'server' in resposta.headers:
            cabecalho_secao(" SERVIDOR WEB ", "-", Cores.AZUL)
            print(f"{Cores.BRANCO}Servidor: {resposta.headers['server']}")
        
    except Exception as e:
        mostrar_status(f"Erro na análise de cabeçalhos: {str(e)}", "erro")

def analise_ssl(dominio):
    """Análise avançada de certificado SSL/TLS."""
    cabecalho_secao(" ANÁLISE SSL/TLS ", "=")
    
    try:
        contexto = ssl.create_default_context()
        with socket.create_connection((dominio, 443)) as sock:
            with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                
                mostrar_status(f"Certificado SSL para {dominio}:", "sucesso")
                
                # Informações básicas do certificado
                cabecalho_secao(" INFORMAÇÕES BÁSICAS ", "-", Cores.AZUL)
                print(f"{Cores.CIANO}Emissor: {Cores.BRANCO}{cert['issuer'][0][0][1]}")
                print(f"{Cores.CIANO}Assunto: {Cores.BRANCO}{cert['subject'][0][0][1]}")
                
                # Datas de validade
                data_validade = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                dias_restantes = (data_validade - datetime.now()).days
                print(f"{Cores.CIANO}Válido até: {Cores.BRANCO}{data_validade.strftime('%d/%m/%Y')} ({dias_restantes} dias restantes)")
                
                # Verificação de validade
                if dias_restantes < 0:
                    mostrar_status("CERTIFICADO EXPIRADO!", "erro")
                elif dias_restantes < 30:
                    mostrar_status("Certificado prestes a expirar!", "alerta")
                else:
                    mostrar_status("Certificado válido", "sucesso")
                
                # Cifras suportadas (simplificado)
                cabecalho_secao(" DETALHES TÉCNICOS ", "-", Cores.AZUL)
                print(f"{Cores.CIANO}Versão: {Cores.BRANCO}{cert.get('version', 'N/A')}")
                print(f"{Cores.CIANO}Número de Série: {Cores.BRANCO}{cert.get('serialNumber', 'N/A')}")
                
                # SANs (Subject Alternative Names)
                if 'subjectAltName' in cert:
                    print(f"\n{Cores.CIANO}Nomes Alternativos (SANs):{Cores.BRANCO}")
                    for tipo, nome in cert['subjectAltName']:
                        print(f"  - {tipo}: {nome}")
                
    except Exception as e:
        mostrar_status(f"Erro na análise SSL: {str(e)}", "erro")

def scan_portas(dominio):
    """Varredura de portas avançada."""
    cabecalho_secao(" VARREURA DE PORTAS ", "=")
    
    portas_comuns = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP Alt",
        8443: "HTTPS Alt"
    }
    
    try:
        ip = socket.gethostbyname(dominio)
        mostrar_status(f"Varrendo {dominio} ({ip})", "info")
        
        for porta, servico in portas_comuns.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            resultado = sock.connect_ex((ip, porta))
            if resultado == 0:
                mostrar_status(f"Porta {porta} ({servico}) ABERTA", "sucesso")
            sock.close()
            
    except Exception as e:
        mostrar_status(f"Erro na varredura de portas: {str(e)}", "erro")

def deteccao_tecnologias(dominio):
    """Detecção de tecnologias utilizadas no website."""
    cabecalho_secao(" DETECÇÃO DE TECNOLOGIAS ", "=")
    
    try:
        url = f"https://{dominio}" if not dominio.startswith(('http://', 'https://')) else dominio
        resposta = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=TEMPO_ESPERA, verify=False)
        soup = BeautifulSoup(resposta.text, 'html.parser')
        
        # Detecção básica de tecnologias
        tecnologias = []
        
        # Verificar CMS
        if 'wp-content' in resposta.text or 'wp-includes' in resposta.text:
            tecnologias.append("WordPress")
        elif 'Joomla' in resposta.text:
            tecnologias.append("Joomla")
        elif 'Drupal' in resposta.text:
            tecnologias.append("Drupal")
        
        # Verificar frameworks JavaScript
        if 'react' in resposta.text.lower() or 'react-dom' in resposta.text.lower():
            tecnologias.append("React")
        elif 'angular' in resposta.text.lower():
            tecnologias.append("Angular")
        elif 'vue' in resposta.text.lower():
            tecnologias.append("Vue.js")
        
        # Verificar linguagens de programação
        if '.php' in resposta.text.lower():
            tecnologias.append("PHP")
        elif 'asp.net' in resposta.text.lower():
            tecnologias.append("ASP.NET")
        
        # Verificar bibliotecas JavaScript
        if 'jquery' in resposta.text.lower():
            tecnologias.append("jQuery")
        
        # Verificar servidor web
        servidor = resposta.headers.get('Server', '').lower()
        if 'apache' in servidor:
            tecnologias.append("Apache")
        elif 'nginx' in servidor:
            tecnologias.append("Nginx")
        elif 'iis' in servidor:
            tecnologias.append("Microsoft IIS")
        
        # Exibir resultados
        if tecnologias:
            mostrar_status("Tecnologias detectadas:", "sucesso")
            for tech in tecnologias:
                print(f"{Cores.BRANCO}- {tech}")
        else:
            mostrar_status("Nenhuma tecnologia comum detectada", "alerta")
        
        # Verificar arquivos comuns
        arquivos_comuns = ['robots.txt', 'sitemap.xml', '.env', 'wp-config.php']
        encontrados = []
        
        for arquivo in arquivos_comuns:
            try:
                url_arquivo = f"{url}/{arquivo}"
                resposta_arquivo = requests.get(url_arquivo, timeout=TEMPO_ESPERA)
                if resposta_arquivo.status_code == 200:
                    encontrados.append(arquivo)
            except:
                continue
        
        if encontrados:
            cabecalho_secao(" ARQUIVOS ENCONTRADOS ", "-", Cores.AZUL)
            for arquivo in encontrados:
                print(f"{Cores.BRANCO}- {arquivo}")
        
    except Exception as e:
        mostrar_status(f"Erro na detecção de tecnologias: {str(e)}", "erro")

def scan_completo(dominio):
    """Executa todas as análises disponíveis."""
    cabecalho_secao(f" SCAN COMPLETO: {dominio.upper()} ", "#", Cores.MAGENTA)
    
    funcoes = [
        ("Análise de IP", scan_ip),
        ("WHOIS Avançado", whois_avancado),
        ("Análise DNS", analise_dns),
        ("Varredura de Subdomínios", scan_subdominios),
        ("Análise de Cabeçalhos", analise_headers),
        ("Análise SSL/TLS", analise_ssl),
        ("Varredura de Portas", scan_portas),
        ("Detecção de Tecnologias", deteccao_tecnologias)
    ]
    
    for nome, funcao in funcoes:
        cabecalho_secao(f" {nome} ", "~", Cores.AZUL)
        funcao(dominio)
        time.sleep(1)  # Evitar rate limiting
    
    cabecalho_secao(" SCAN CONCLUÍDO ", "#", Cores.MAGENTA)

def gerar_relatorio(dominio):
    """Gera um relatório completo em arquivo."""
    cabecalho_secao(" GERAR RELATÓRIO ", "=")
    
    data_hora = datetime.now().strftime("%Y%m%d_%H%M%S")
    nome_arquivo = f"lucid_relatorio_{dominio}_{data_hora}.txt"
    
    try:
        # Redirecionar saída padrão para o arquivo
        original_stdout = sys.stdout
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            sys.stdout = f
            
            # Executar scan completo
            print(f"Relatório LUCID para {dominio}")
            print(f"Gerado em: {formatar_data_hora()}\n")
            scan_completo(dominio)
            
            # Restaurar saída padrão
            sys.stdout = original_stdout
        
        mostrar_status(f"Relatório salvo como: {nome_arquivo}", "sucesso")
    except Exception as e:
        mostrar_status(f"Erro ao gerar relatório: {str(e)}", "erro")
        sys.stdout = original_stdout

def mostrar_menu_ajuda():
    """Exibe o menu de ajuda detalhado."""
    limpar_tela()
    print(BANNER_LUCID)
    print(f"{Cores.CIANO}{' MENU DE AJUDA ':=^60}")
    print(f"""
{Cores.AMARELO}1. Análise de IP{Cores.BRANCO}
  - Resolução de domínio para IP
  - Geolocalização aproximada
  - Consulta Shodan (se disponível)

{Cores.AMARELO}2. WHOIS Avançado{Cores.BRANCO}
  - Informações de registro do domínio
  - Datas de criação e expiração
  - Contatos do registrante

{Cores.AMARELO}3. Análise DNS{Cores.BRANCO}
  - Consulta múltiplos registros (A, MX, NS, etc.)
  - Identificação de configurações DNS

{Cores.AMARELO}4. Varredura de Subdomínios{Cores.BRANCO}
  - Verificação de subdomínios comuns
  - Detecção de wildcard DNS

{Cores.AMARELO}5. Análise de Cabeçalhos{Cores.BRANCO}
  - Inspeção de cabeçalhos HTTP
  - Verificação de cabeçalhos de segurança
  - Identificação do servidor web

{Cores.AMARELO}6. Análise SSL/TLS{Cores.BRANCO}
  - Validade do certificado
  - Informações do emissor
  - Nomes alternativos (SANs)

{Cores.AMARELO}7. Varredura de Portas{Cores.BRANCO}
  - Verificação de portas comuns
  - Identificação de serviços expostos

{Cores.AMARELO}8. Detecção de Tecnologias{Cores.BRANCO}
  - CMS (WordPress, Joomla, Drupal)
  - Frameworks JavaScript
  - Linguagens de programação

{Cores.AMARELO}9. Scan Completo{Cores.BRANCO}
  - Executa todas as análises disponíveis

{Cores.AMARELO}R. Gerar Relatório{Cores.BRANCO}
  - Salva os resultados em arquivo

{Cores.AMARELO}0. Sair{Cores.BRANCO}
  - Encerra o programa
""")
    aguardar_enter()

def sequencia_inicial():
    """Exibe a sequência inicial do programa."""
    limpar_tela()
    efeito_digitacao(f"{Cores.CIANO}Inicializando LUCID {VERSAO}...", 0.02)
    time.sleep(0.3)
    efeito_digitacao(f"{Cores.CIANO}Carregando módulos de segurança...", 0.02)
    time.sleep(0.3)
    efeito_digitacao(f"{Cores.CIANO}Verificando credenciais...", 0.02)
    time.sleep(0.3)
    efeito_digitacao(f"{Cores.CIANO}Conectando aos servidores...", 0.02)
    time.sleep(0.3)
    
    if shodan_api:
        efeito_digitacao(f"{Cores.VERDE}API Shodan conectada com sucesso!", 0.02)
    else:
        efeito_digitacao(f"{Cores.AMARELO}API Shodan não configurada", 0.02)
    
    efeito_digitacao(f"{Cores.VERDE}Sistema pronto. Bem-vindo ao LUCID!", 0.02)
    time.sleep(1)

def menu_principal():
    """Exibe e gerencia o menu principal."""
    if not verificar_conexao():
        mostrar_status("Sem conexão com a internet. Algumas funcionalidades podem não funcionar.", "alerta")
        aguardar_enter()
    
    while True:
        limpar_tela()
        print(BANNER_LUCID)
        print(f"{Cores.CIANO}{' MENU PRINCIPAL ':=^60}")
        print(f"""
{Cores.AMARELO}1.{Cores.BRANCO} Análise de IP
{Cores.AMARELO}2.{Cores.BRANCO} WHOIS Avançado
{Cores.AMARELO}3.{Cores.BRANCO} Análise DNS
{Cores.AMARELO}4.{Cores.BRANCO} Varredura de Subdomínios
{Cores.AMARELO}5.{Cores.BRANCO} Análise de Cabeçalhos
{Cores.AMARELO}6.{Cores.BRANCO} Análise SSL/TLS
{Cores.AMARELO}7.{Cores.BRANCO} Varredura de Portas
{Cores.AMARELO}8.{Cores.BRANCO} Detecção de Tecnologias
{Cores.AMARELO}9.{Cores.BRANCO} Scan Completo
{Cores.AMARELO}R.{Cores.BRANCO} Gerar Relatório
{Cores.AMARELO}H.{Cores.BRANCO} Ajuda
{Cores.AMARELO}0.{Cores.BRANCO} Sair
""")
        
        opcao = input(f"{Cores.AMARELO}>>> {Cores.BRANCO}").strip().lower()
        
        if opcao == '0':
            efeito_digitacao(f"{Cores.VERDE}Obrigado por usar o LUCID. Até logo!", 0.03)
            sys.exit(0)
        elif opcao == 'h':
            mostrar_menu_ajuda()
            continue
        
        try:
            if opcao in ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'r']:
                dominio = input(f"{Cores.AZUL}Informe o domínio (ex: exemplo.com): {Cores.BRANCO}").strip()
                if not validar_dominio(dominio):
                    mostrar_status("Formato de domínio inválido. Use: exemplo.com", "erro")
                    aguardar_enter()
                    continue
                
                if opcao == '1':
                    scan_ip(dominio)
                elif opcao == '2':
                    whois_avancado(dominio)
                elif opcao == '3':
                    analise_dns(dominio)
                elif opcao == '4':
                    scan_subdominios(dominio)
                elif opcao == '5':
                    analise_headers(dominio)
                elif opcao == '6':
                    analise_ssl(dominio)
                elif opcao == '7':
                    scan_portas(dominio)
                elif opcao == '8':
                    deteccao_tecnologias(dominio)
                elif opcao == '9':
                    scan_completo(dominio)
                elif opcao == 'r':
                    gerar_relatorio(dominio)
                
                aguardar_enter()
            else:
                mostrar_status("Opção inválida. Tente novamente.", "erro")
                time.sleep(1)
        except KeyboardInterrupt:
            mostrar_status("\nOperação cancelada pelo usuário.", "alerta")
            aguardar_enter()
        except Exception as e:
            mostrar_status(f"Erro: {str(e)}", "erro")
            aguardar_enter()

if __name__ == "__main__":
    try:
        sequencia_inicial()
        menu_principal()
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}Programa encerrado pelo usuário.{Cores.RESET}")
        sys.exit(0)
    except Exception as e:
        mostrar_status(f"Erro crítico: {str(e)}", "erro")
        sys.exit(1)
