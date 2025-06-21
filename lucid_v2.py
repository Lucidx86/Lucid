
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
import random
import platform
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Inicialização do Colorama
init(autoreset=True)

# =============================================
# CONFIGURAÇÕES GLOBAIS AVANÇADAS
# =============================================

class Config:
    VERSAO = "6.0 PRO"
    AUTOR = "Equipe LUCID"
    DATA_LANCAMENTO = "2024"
    CONTATO = "contato@lucidsecurity.com.br"
    TEMPO_ESPERA = 10
    USER_AGENT = "LUCID-Scanner/6.0 (Professional Security Tool)"
    TIMEOUT_PADRAO = 15
    MAX_THREADS = 10
    
    # Lista aprimorada de subdomínios
    SUBDOMINIOS_COMUNS = [
        "www", "mail", "ftp", "webmail", "cpanel", "blog", "shop", 
        "smtp", "api", "dev", "test", "admin", "secure", "vpn", "ns1",
        "ns2", "mx", "web", "app", "cloud", "dashboard", "api2", "cdn",
        "static", "backup", "db", "mysql", "phpmyadmin", "teste", "staging",
        "old", "new", "beta", "alpha", "git", "svn", "monitor", "status",
        "support", "help", "wiki", "docs", "portal", "manager", "host", "server"
    ]
    
    # Portas para scan aprimorado
    PORTAS_COMUNS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS", 
        587: "SMTP Submission", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 
        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP Alt", 8443: "HTTPS Alt",
        27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached", 
        2049: "NFS", 5900: "VNC", 6379: "Redis", 27015: "Steam", 10000: "Webmin"
    }

# =============================================
# SISTEMA DE CORES AVANÇADAS
# =============================================

class Cores:
    # Cores básicas
    VERMELHO = Fore.RED
    VERDE = Fore.GREEN
    AMARELO = Fore.YELLOW
    CIANO = Fore.CYAN
    BRANCO = Fore.WHITE
    AZUL = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    PRETO = Fore.BLACK
    
    # Estilos
    DESTAQUE = Style.BRIGHT
    NEGRITO = Style.BRIGHT
    NORMAL = Style.NORMAL
    RESET = Style.RESET_ALL
    
    # Cores personalizadas
    LARANJA = "\033[38;5;208m"
    ROXO = "\033[38;5;93m"
    ROSA = "\033[38;5;205m"
    VERDE_CLARO = "\033[38;5;46m"
    AZUL_CLARO = "\033[38;5;39m"
    CINZA = "\033[38;5;240m"
    
    # Cores de gradiente
    @staticmethod
    def gradiente(texto, cor1, cor2):
        """Aplica um efeito de gradiente ao texto"""
        resultado = ""
        tamanho = len(texto)
        for i, char in enumerate(texto):
            ratio = i / tamanho
            r = int(cor1[0] + ratio * (cor2[0] - cor1[0]))
            g = int(cor1[1] + ratio * (cor2[1] - cor1[1]))
            b = int(cor1[2] + ratio * (cor2[2] - cor1[2]))
            resultado += f"\033[38;2;{r};{g};{b}m{char}"
        return resultado + Cores.RESET

# =============================================
# BANNER E ARTE ASCII PREMIUM
# =============================================

BANNER_LUCID = f"""
{Cores.AZUL_CLARO}
▓█████▄  ██▓    ▄▄▄     ▄▄▄█████▓ ██░ ██ ▓█████     ██▓     ██▓ ███▄    █  ██░ ██  ▒█████   ███▄    █ 
▒██▀ ██▌▓██▒   ▒████▄   ▓  ██▒ ▓▒▓██░ ██▒▓█   ▀    ▓██▒    ▓██▒ ██ ▀█   █ ▓██░ ██▒▒██▒  ██▒ ██ ▀█   █ 
░██   █▌▒██░   ▒██  ▀█▄ ▒ ▓██░ ▒░▒██▀▀██░▒███      ▒██░    ▒██▒▓██  ▀█ ██▒▒██▀▀██░▒██░  ██▒▓██  ▀█ ██▒
░▓█▄   ▌▒██░   ░██▄▄▄▄██░ ▓██▓ ░ ░▓█ ░██ ▒▓█  ▄    ▒██░    ░██░▓██▒  ▐▌██▒░▓█ ░██ ▒██   ██░▓██▒  ▐▌██▒
░▒████▓ ░██████▒▓█   ▓██▒ ▒██▒ ░ ░▓█▒░██▓░▒████▒   ░██████▒░██░▒██░   ▓██░░▓█▒░██▓░ ████▓▒░▒██░   ▓██░
 ▒▒▓  ▒ ░ ▒░▓  ░▒▒   ▓▒█░ ▒ ░░    ▒ ░░▒░▒░░ ▒░ ░   ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
 ░ ▒  ▒ ░ ░ ▒  ░ ▒   ▒▒ ░   ░     ▒ ░▒░ ░ ░ ░  ░   ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░ ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
 ░ ░  ░   ░ ░    ░   ▒    ░       ░  ░░ ░   ░        ░ ░    ▒ ░   ░   ░ ░  ░  ░░ ░░ ░ ░ ▒     ░   ░ ░ 
   ░        ░  ░     ░  ░         ░  ░  ░   ░  ░       ░  ░ ░           ░  ░  ░  ░    ░ ░           ░ 
 ░                                                                                                    
{Cores.RESET}
"""

BANNER_SECUNDARIO = f"""
{Cores.ROXO}
╦  ╦╔═╗╔╦╗╔═╗╦═╗  ╔═╗╔═╗╔╦╗╔═╗╔╗╔╔═╗╦═╗
╚╗╔╝╠═╣║║║║╣ ╠╦╝  ║  ║ ║║║║║╣ ║║║║ ╦╠╦╝
 ╚╝ ╩ ╩╩ ╩╚═╝╩╚═  ╚═╝╚═╝╩ ╩╚═╝╝╚╝╚═╝╩╚═
{Cores.VERDE_CLARO}Versão: {Config.VERSAO} | Autor: {Config.AUTOR} | Contato: {Config.CONTATO}
{Cores.RESET}
"""

# =============================================
# FUNÇÕES UTILITÁRIAS AVANÇADAS
# =============================================

class Utilitarios:
    @staticmethod
    def limpar_tela():
        """Limpa a tela do terminal de forma multiplataforma."""
        os.system("cls" if os.name == "nt" else "clear")
    
    @staticmethod
    def efeito_digitacao(texto, delay=0.01, cor=Cores.BRANCO, random_delay=False):
        """Exibe texto com efeito de digitação realista."""
        print(cor, end='', flush=True)
        for char in texto:
            print(char, end='', flush=True)
            if random_delay:
                time.sleep(delay * random.uniform(0.5, 1.5))
            else:
                time.sleep(delay)
        print(Cores.RESET, end='', flush=True)
    
    @staticmethod
    def mostrar_status(mensagem, status="info", detalhe=""):
        """Exibe mensagens de status formatadas com ícones personalizados."""
        icones = {
            "sucesso": f"{Cores.VERDE}✓",
            "erro": f"{Cores.VERMELHO}✗",
            "alerta": f"{Cores.AMARELO}⚠",
            "info": f"{Cores.AZUL_CLARO}ℹ",
            "destaque": f"{Cores.CIANO}⚡",
            "debug": f"{Cores.ROXO}⚙"
        }
        
        cor = {
            "sucesso": Cores.VERDE,
            "erro": Cores.VERMELHO,
            "alerta": Cores.AMARELO,
            "info": Cores.AZUL_CLARO,
            "destaque": Cores.CIANO,
            "debug": Cores.ROXO
        }.get(status, Cores.BRANCO)
        
        if detalhe:
            print(f"{icones.get(status, '')} {cor}{mensagem}{Cores.CINZA} {detalhe}{Cores.RESET}")
        else:
            print(f"{icones.get(status, '')} {cor}{mensagem}{Cores.RESET}")
    
    @staticmethod
    def validar_dominio(dominio):
        """Valida o formato do domínio com expressão regular aprimorada."""
        padrao = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(padrao, dominio) is not None
    
    @staticmethod
    def formatar_data_hora():
        """Retorna a data e hora formatadas com fuso horário."""
        return datetime.now().strftime("%d/%m/%Y %H:%M:%S %Z")
    
    @staticmethod
    def cabecalho_secao(titulo, caractere="=", cor=Cores.AZUL_CLARO, largura=80):
        """Cria um cabeçalho de seção formatado com gradiente."""
        titulo_centralizado = f" {titulo} ".center(largura, caractere)
        print(f"\n{cor}{Cores.DESTAQUE}{titulo_centralizado}{Cores.RESET}")
    
    @staticmethod
    def aguardar_enter(mensagem="Pressione ENTER para continuar..."):
        """Aguarda pressionamento da tecla Enter com estilo."""
        input(f"\n{Cores.AMARELO}{Cores.DESTAQUE}[{mensagem}]{Cores.RESET}")
    
    @staticmethod
    def verificar_conexao():
        """Verifica se há conexão com a internet de forma robusta."""
        try:
            resposta = requests.get("https://www.google.com", timeout=5)
            return resposta.status_code == 200
        except:
            return False
    
    @staticmethod
    def animacao_carregamento(duracao=3, mensagem="Carregando"):
        """Exibe uma animação de carregamento estilizada."""
        chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        start_time = time.time()
        
        print(f"\n{Cores.AZUL_CLARO}{mensagem}...{Cores.RESET}", end='')
        
        while time.time() - start_time < duracao:
            for char in chars:
                print(f"\r{Cores.AZUL_CLARO}{mensagem}... {char}{Cores.RESET}", end='', flush=True)
                time.sleep(0.1)
        
        print("\r" + " " * (len(mensagem) + 10) + "\r", end='')
    
    @staticmethod
    def calcular_tempo_execucao(inicio):
        """Calcula e formata o tempo de execução."""
        segundos = time.time() - inicio
        if segundos < 60:
            return f"{segundos:.2f} segundos"
        else:
            minutos = segundos // 60
            segundos = segundos % 60
            return f"{int(minutos)} minutos e {segundos:.2f} segundos"

# =============================================
# FUNÇÕES DE ANÁLISE AVANÇADAS
# =============================================

class AnalisadorSeguranca:
    def __init__(self):
        self.shodan_api = self._inicializar_shodan()
        self.user_agent = Config.USER_AGENT
        self.timeout = Config.TIMEOUT_PADRAO
    
    def _inicializar_shodan(self):
        """Inicializa a API Shodan de forma segura."""
        try:
            from config import SHODAN_API_KEY
            if SHODAN_API_KEY:
                return shodan.Shodan(SHODAN_API_KEY)
        except:
            return None
    
    def scan_ip(self, dominio):
        """Análise avançada de endereço IP com geolocalização e dados Shodan."""
        Utilitarios.cabecalho_secao(" ANÁLISE DE IP ", "=")
        
        try:
            # Resolução de DNS
            ip = socket.gethostbyname(dominio)
            Utilitarios.mostrar_status(f"Domínio resolvido", f"{dominio} → {ip}")
            
            # Host reverso
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                Utilitarios.mostrar_status("Host reverso encontrado", hostname)
            except:
                Utilitarios.mostrar_status("Host reverso não encontrado", status="alerta")
            
            # Geolocalização avançada
            self._geolocalizar_ip(ip)
            
            # Consulta Shodan
            if self.shodan_api:
                self._consultar_shodan(ip)
            else:
                Utilitarios.mostrar_status("API Shodan não configurada", status="alerta")
            
            # Verificação de blacklists
            self._verificar_blacklists(ip)
            
        except socket.gaierror:
            Utilitarios.mostrar_status("Não foi possível resolver o endereço IP", status="erro")
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na análise de IP: {str(e)}", status="erro")
    
    def _geolocalizar_ip(self, ip):
        """Realiza geolocalização detalhada do IP."""
        try:
            resposta = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=self.timeout)
            dados_geo = resposta.json()
            
            if dados_geo['status'] == 'success':
                Utilitarios.cabecalho_secao(" GEOLOCALIZAÇÃO ", "-", Cores.AZUL)
                
                dados_formatados = {
                    "Localização": f"{dados_geo.get('city', 'N/A')}, {dados_geo.get('regionName', 'N/A')}, {dados_geo.get('country', 'N/A')}",
                    "Coordenadas": f"{dados_geo.get('lat', 'N/A')}, {dados_geo.get('lon', 'N/A')}",
                    "Provedor": dados_geo.get('isp', 'N/A'),
                    "ASN": dados_geo.get('as', 'N/A'),
                    "Organização": dados_geo.get('org', 'N/A'),
                    "Código Postal": dados_geo.get('zip', 'N/A'),
                    "Fuso Horário": dados_geo.get('timezone', 'N/A'),
                    "Proxy/VPN": "Sim" if dados_geo.get('proxy', False) else "Não"
                }
                
                for chave, valor in dados_formatados.items():
                    print(f"{Cores.CIANO}{chave}:{Cores.RESET} {Cores.VERDE}{valor}{Cores.RESET}")
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na geolocalização: {str(e)}", status="erro")
    
    def _consultar_shodan(self, ip):
        """Consulta detalhada da API Shodan."""
        try:
            resultado = self.shodan_api.host(ip)
            Utilitarios.cabecalho_secao(" DADOS SHODAN ", "-", Cores.MAGENTA)
            
            # Informações básicas
            if 'os' in resultado:
                Utilitarios.mostrar_status("Sistema Operacional", resultado['os'])
            
            # Portas abertas
            if 'ports' in resultado:
                Utilitarios.mostrar_status("Portas Abertas", ", ".join(map(str, resultado['ports'])))
            
            # Vulnerabilidades
            if 'vulns' in resultado:
                Utilitarios.cabecalho_secao(" VULNERABILIDADES ", "-", Cores.VERMELHO)
                for vuln in resultado['vulns']:
                    print(f"{Cores.VERMELHO}- {vuln}{Cores.RESET}")
            
            # Serviços detectados
            if 'data' in resultado:
                Utilitarios.cabecalho_secao(" SERVIÇOS DETECTADOS ", "-", Cores.AZUL)
                for servico in resultado['data']:
                    if 'product' in servico:
                        print(f"{Cores.BRANCO}- {servico['product']} ({servico['port']}){Cores.RESET}")
            
        except shodan.APIError as e:
            Utilitarios.mostrar_status(f"Erro na API Shodan: {str(e)}", status="erro")
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro ao processar dados Shodan: {str(e)}", status="erro")
    
    def _verificar_blacklists(self, ip):
        """Verifica se o IP está em listas de bloqueio conhecidas."""
        blacklists = [
            "zen.spamhaus.org",
            "b.barracudacentral.org",
            "bl.spamcop.net",
            "dnsbl.sorbs.net"
        ]
        
        Utilitarios.cabecalho_secao(" VERIFICAÇÃO DE BLACKLISTS ", "-", Cores.AMARELO)
        
        for bl in blacklists:
            try:
                query = f"{'.'.join(reversed(ip.split('.')))}.{bl}"
                socket.gethostbyname(query)
                Utilitarios.mostrar_status(f"{bl}", "LISTADO", status="erro")
            except:
                Utilitarios.mostrar_status(f"{bl}", "Não listado", status="sucesso")
    
    def whois_avancado(self, dominio):
        """Consulta WHOIS detalhada com análise de domínio."""
        Utilitarios.cabecalho_secao(" WHOIS AVANÇADO ", "=")
        
        try:
            dados = whois.whois(dominio)
            Utilitarios.mostrar_status(f"Informações WHOIS para {dominio}", status="sucesso")
            
            # Informações básicas do domínio
            self._exibir_dados_whois(dados)
            
            # Análise de segurança do domínio
            self._analisar_seguranca_dominio(dados)
            
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na consulta WHOIS: {str(e)}", status="erro")
    
    def _exibir_dados_whois(self, dados):
        """Exibe os dados WHOIS de forma formatada."""
        Utilitarios.cabecalho_secao(" INFORMAÇÕES REGISTRO ", "-", Cores.AZUL)
        
        # Domínio
        if dados.domain_name:
            dominio = dados.domain_name[0] if isinstance(dados.domain_name, list) else dados.domain_name
            Utilitarios.mostrar_status("Domínio", dominio)
        
        # Registrante
        if dados.registrar:
            Utilitarios.mostrar_status("Registrante", dados.registrar)
        
        # Datas importantes
        if dados.creation_date:
            data_criacao = dados.creation_date[0] if isinstance(dados.creation_date, list) else dados.creation_date
            idade_dominio = (datetime.now() - data_criacao).days
            Utilitarios.mostrar_status("Criação", f"{data_criacao.strftime('%d/%m/%Y')} ({idade_dominio} dias atrás)")
        
        if dados.expiration_date:
            data_exp = dados.expiration_date[0] if isinstance(dados.expiration_date, list) else dados.expiration_date
            dias_restantes = (data_exp - datetime.now()).days
            Utilitarios.mostrar_status("Expiração", f"{data_exp.strftime('%d/%m/%Y')} ({dias_restantes} dias restantes)")
        
        if dados.updated_date:
            data_atualizacao = dados.updated_date[0] if isinstance(dados.updated_date, list) else dados.updated_date
            Utilitarios.mostrar_status("Última Atualização", data_atualizacao.strftime('%d/%m/%Y'))
        
        # Contatos
        Utilitarios.cabecalho_secao(" CONTATOS ", "-", Cores.AZUL)
        if dados.emails:
            emails = dados.emails if isinstance(dados.emails, list) else [dados.emails]
            Utilitarios.mostrar_status("E-mails", "")
            for email in emails:
                print(f"  {Cores.BRANCO}- {email}{Cores.RESET}")
        
        if dados.phone:
            Utilitarios.mostrar_status("Telefone", dados.phone)
        
        # Servidores DNS
        if dados.name_servers:
            Utilitarios.cabecalho_secao(" SERVIDORES DNS ", "-", Cores.AZUL)
            for ns in set(dados.name_servers):
                print(f"{Cores.BRANCO}- {ns}{Cores.RESET}")
    
    def _analisar_seguranca_dominio(self, dados):
        """Realiza análise de segurança baseada nos dados WHOIS."""
        Utilitarios.cabecalho_secao(" ANÁLISE DE SEGURANÇA ", "-", Cores.ROXO)
        
        # Verificação de privacidade
        privado = False
        if dados.emails:
            emails = dados.emails if isinstance(dados.emails, list) else [dados.emails]
            for email in emails:
                if "whois" in email.lower() or "privacy" in email.lower():
                    privado = True
                    break
        
        if privado:
            Utilitarios.mostrar_status("Proteção de Privacidade", "Ativada", status="sucesso")
        else:
            Utilitarios.mostrar_status("Proteção de Privacidade", "Desativada", status="alerta")
        
        # Idade do domínio
        if dados.creation_date:
            data_criacao = dados.creation_date[0] if isinstance(dados.creation_date, list) else dados.creation_date
            idade = (datetime.now() - data_criacao).days
            
            if idade < 30:
                Utilitarios.mostrar_status("Idade do Domínio", f"{idade} dias (Recém-criado)", status="alerta")
            elif idade < 365:
                Utilitarios.mostrar_status("Idade do Domínio", f"{idade} dias (~{idade//30} meses)", status="info")
            else:
                Utilitarios.mostrar_status("Idade do Domínio", f"{idade} dias (~{idade//365} anos)", status="sucesso")
    
    def analise_dns(self, dominio):
        """Análise completa de registros DNS com verificação de configurações."""
        Utilitarios.cabecalho_secao(" ANÁLISE DNS ", "=")
        
        tipos_registros = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'DMARC', 'DKIM', 'SPF']
        
        for tipo in tipos_registros:
            try:
                resposta = dns.resolver.resolve(dominio, tipo)
                Utilitarios.mostrar_status(f"Registros {tipo} encontrados", status="sucesso")
                
                for dado in resposta:
                    print(f"{Cores.BRANCO}- {dado.to_text()}{Cores.RESET}")
                
                # Análise específica para cada tipo de registro
                if tipo == 'MX':
                    self._analisar_mx(resposta)
                elif tipo == 'TXT':
                    self._analisar_txt(resposta)
                elif tipo == 'DMARC':
                    self._analisar_dmarc(resposta)
                
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                Utilitarios.mostrar_status(f"Domínio {dominio} não existe", status="erro")
                break
            except Exception as e:
                Utilitarios.mostrar_status(f"Erro ao buscar {tipo}: {str(e)}", status="erro")
    
    def _analisar_mx(self, registros):
        """Analisa registros MX para configurações de email."""
        Utilitarios.cabecalho_secao(" ANÁLISE MX ", "-", Cores.AZUL)
        
        prioridades = [mx.preference for mx in registros]
        if len(prioridades) > 1 and min(prioridades) == 0:
            Utilitarios.mostrar_status("Configuração MX", "Prioridade 0 encontrada (pode ser problemático)", status="alerta")
        
        for mx in registros:
            if "google" in mx.exchange.to_text().lower():
                Utilitarios.mostrar_status("Serviço de Email", "Google Workspace/Gmail detectado", status="info")
            elif "outlook" in mx.exchange.to_text().lower() or "office365" in mx.exchange.to_text().lower():
                Utilitarios.mostrar_status("Serviço de Email", "Microsoft 365 detectado", status="info")
    
    def _analisar_txt(self, registros):
        """Analisa registros TXT para configurações de segurança."""
        Utilitarios.cabecalho_secao(" ANÁLISE TXT ", "-", Cores.ROXO)
        
        spf_encontrado = False
        for txt in registros:
            txt_str = txt.to_text().lower()
            
            if "v=spf1" in txt_str:
                spf_encontrado = True
                if "~all" in txt_str or "-all" in txt_str:
                    Utilitarios.mostrar_status("SPF", "Configurado corretamente", status="sucesso")
                else:
                    Utilitarios.mostrar_status("SPF", "Configurado mas sem política rigorosa", status="alerta")
            
            if "google-site-verification" in txt_str:
                Utilitarios.mostrar_status("Verificação Google", "Domínio verificado no Google Search Console", status="info")
        
        if not spf_encontrado:
            Utilitarios.mostrar_status("SPF", "Não encontrado (recomendado para email)", status="erro")
    
    def _analisar_dmarc(self, registros):
        """Analisa registros DMARC para políticas de email."""
        for dmarc in registros:
            dmarc_str = dmarc.to_text().lower()
            
            if "p=none" in dmarc_str:
                Utilitarios.mostrar_status("DMARC", "Política: nenhuma (apenas monitoramento)", status="alerta")
            elif "p=quarantine" in dmarc_str:
                Utilitarios.mostrar_status("DMARC", "Política: quarentena", status="sucesso")
            elif "p=reject" in dmarc_str:
                Utilitarios.mostrar_status("DMARC", "Política: rejeição", status="sucesso")
            else:
                Utilitarios.mostrar_status("DMARC", "Política não especificada", status="alerta")
    
    def scan_subdominios(self, dominio):
        """Varredura avançada de subdomínios com multi-threading."""
        Utilitarios.cabecalho_secao(" VARREURA DE SUBDOMÍNIOS ", "=")
        
        encontrados = []
        total = len(Config.SUBDOMINIOS_COMUNS)
        
        # Usando ThreadPoolExecutor para varredura mais rápida
        with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
            futures = []
            
            for sub in Config.SUBDOMINIOS_COMUNS:
                sub_completo = f"{sub}.{dominio}"
                futures.append(executor.submit(self._verificar_subdominio, sub_completo, dominio))
            
            # Barra de progresso
            with tqdm(total=total, desc=f"{Cores.AZUL}Varrendo subdomínios{Cores.RESET}", unit="sub") as pbar:
                for future in futures:
                    resultado = future.result()
                    if resultado:
                        encontrados.append(resultado)
                    pbar.update(1)
        
        # Resultados
        if encontrados:
            Utilitarios.cabecalho_secao(" SUBDOMÍNIOS ENCONTRADOS ", "-", Cores.VERDE)
            for sub, ip in encontrados:
                print(f"{Cores.BRANCO}- {sub.ljust(30)} → {Cores.VERDE}{ip}{Cores.RESET}")
        else:
            Utilitarios.mostrar_status("Nenhum subdomínio comum encontrado", status="alerta")
        
        # Verificação de wildcard DNS
        self._verificar_wildcard(dominio)
    
    def _verificar_subdominio(self, subdominio, dominio_principal):
        """Verifica se um subdomínio existe."""
        try:
            ip = socket.gethostbyname(subdominio)
            return (subdominio, ip)
        except:
            return None
    
    def _verificar_wildcard(self, dominio):
        """Verifica se há wildcard DNS configurado."""
        try:
            sub_teste = f"teste-{random.randint(100000, 999999)}.{dominio}"
            ip = socket.gethostbyname(sub_teste)
            Utilitarios.mostrar_status(f"Wildcard DNS detectado: {sub_teste} → {ip}", status="alerta")
        except:
            pass
    
    def analise_headers(self, dominio):
        """Análise detalhada de cabeçalhos HTTP com verificação de segurança."""
        Utilitarios.cabecalho_secao(" ANÁLISE DE CABEÇALHOS ", "=")
        
        try:
            url = f"https://{dominio}" if not dominio.startswith(('http://', 'https://')) else dominio
            resposta = requests.get(url, headers={'User-Agent': self.user_agent}, 
                                  timeout=self.timeout, verify=False, allow_redirects=True)
            
            Utilitarios.mostrar_status(f"Analisando cabeçalhos para {url}", status="sucesso")
            
            # Cabeçalhos de segurança importantes
            cab_seguranca = {
                'strict-transport-security': {'nome': 'HSTS', 'recomendado': 'max-age=31536000; includeSubDomains; preload'},
                'x-frame-options': {'nome': 'Clickjacking Protection', 'recomendado': 'DENY ou SAMEORIGIN'},
                'x-content-type-options': {'nome': 'MIME Sniffing', 'recomendado': 'nosniff'},
                'content-security-policy': {'nome': 'CSP', 'recomendado': 'Política restritiva'},
                'x-xss-protection': {'nome': 'XSS Protection', 'recomendado': '1; mode=block'},
                'referrer-policy': {'nome': 'Referrer Policy', 'recomendado': 'no-referrer-when-downgrade'},
                'permissions-policy': {'nome': 'Permissions Policy', 'recomendado': 'Política restritiva'},
                'cross-origin-opener-policy': {'nome': 'COOP', 'recomendado': 'same-origin'},
                'cross-origin-embedder-policy': {'nome': 'COEP', 'recomendado': 'require-corp'}
            }
            
            # Exibir todos os cabeçalhos com destaque para segurança
            Utilitarios.cabecalho_secao(" CABEÇALHOS ENCONTRADOS ", "-", Cores.AZUL)
            for cab, valor in resposta.headers.items():
                cab_lower = cab.lower()
                if cab_lower in cab_seguranca:
                    print(f"{Cores.VERDE}{Cores.NEGRITO}{cab}: {Cores.VERDE}{valor}{Cores.RESET}")
                else:
                    print(f"{Cores.CIANO}{cab}: {Cores.BRANCO}{valor}{Cores.RESET}")
            
            # Verificar cabeçalhos de segurança ausentes ou inadequados
            self._verificar_cab_seguranca(resposta.headers, cab_seguranca)
            
            # Verificar servidor web e tecnologia
            self._analisar_servidor_web(resposta.headers)
            
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na análise de cabeçalhos: {str(e)}", status="erro")
    
    def _verificar_cab_seguranca(self, headers, cab_seguranca):
        """Verifica cabeçalhos de segurança ausentes ou inadequados."""
        Utilitarios.cabecalho_secao(" ANÁLISE DE SEGURANÇA ", "-", Cores.ROXO)
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        problemas = []
        
        for cab, info in cab_seguranca.items():
            if cab not in headers_lower:
                problemas.append(f"{info['nome']}: {Cores.VERMELHO}AUSENTE{Cores.RESET} (Recomendado: {info['recomendado']})")
            else:
                valor = headers_lower[cab]
                if cab == 'strict-transport-security' and 'max-age=0' in valor:
                    problemas.append(f"HSTS: {Cores.VERMELHO}DESATIVADO{Cores.RESET} (max-age=0)")
                elif cab == 'x-frame-options' and valor.lower() == 'allow-from':
                    problemas.append(f"X-Frame-Options: {Cores.AMARELO}CONFIGURAÇÃO FRÁGIL{Cores.RESET} (allow-from)")
                elif cab == 'content-security-policy' and "'unsafe-inline'" in valor:
                    problemas.append(f"CSP: {Cores.AMARELO}CONFIGURAÇÃO FRÁGIL{Cores.RESET} (unsafe-inline detectado)")
        
        if problemas:
            for problema in problemas:
                print(f"{Cores.BRANCO}- {problema}{Cores.RESET}")
        else:
            Utilitarios.mostrar_status("Todos os cabeçalhos de segurança importantes estão presentes", status="sucesso")
    
    def _analisar_servidor_web(self, headers):
        """Analisa informações do servidor web e tecnologia."""
        Utilitarios.cabecalho_secao(" SERVIDOR WEB ", "-", Cores.AZUL)
        
        # Servidor web
        if 'server' in headers:
            Utilitarios.mostrar_status("Servidor web", headers['server'])
        else:
            Utilitarios.mostrar_status("Servidor web", "Não identificado", status="alerta")
        
        # Tecnologias (X-Powered-By etc.)
        tecnologias = []
        for cab in ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']:
            if cab in headers:
                tecnologias.append(f"{cab}: {headers[cab]}")
        
        if tecnologias:
            Utilitarios.mostrar_status("Tecnologias detectadas", "")
            for tech in tecnologias:
                print(f"{Cores.BRANCO}- {tech}{Cores.RESET}")
    
    def analise_ssl(self, dominio):
        """Análise avançada de certificado SSL/TLS."""
        Utilitarios.cabecalho_secao(" ANÁLISE SSL/TLS ", "=")
        
        try:
            contexto = ssl.create_default_context()
            with socket.create_connection((dominio, 443), timeout=self.timeout) as sock:
                with contexto.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    
                    Utilitarios.mostrar_status(f"Certificado SSL para {dominio}", status="sucesso")
                    
                    # Informações básicas do certificado
                    self._exibir_info_certificado(cert)
                    
                    # Verificação de vulnerabilidades
                    self._verificar_vulnerabilidades_ssl(ssock)
                    
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na análise SSL: {str(e)}", status="erro")
    
    def _exibir_info_certificado(self, cert):
        """Exibe informações detalhadas do certificado SSL."""
        Utilitarios.cabecalho_secao(" INFORMAÇÕES DO CERTIFICADO ", "-", Cores.AZUL)
        
        # Emissor
        if 'issuer' in cert:
            emissor = ""
            for item in cert['issuer']:
                emissor += f"{item[0][0]}: {item[0][1]}, "
            Utilitarios.mostrar_status("Emissor", emissor[:-2])
        
        # Assunto
        if 'subject' in cert:
            assunto = ""
            for item in cert['subject']:
                assunto += f"{item[0][0]}: {item[0][1]}, "
            Utilitarios.mostrar_status("Assunto", assunto[:-2])
        
        # Validade
        if 'notBefore' in cert and 'notAfter' in cert:
            data_inicio = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            data_fim = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            dias_restantes = (data_fim - datetime.now()).days
            
            Utilitarios.mostrar_status("Válido de", data_inicio.strftime('%d/%m/%Y'))
            Utilitarios.mostrar_status("Válido até", f"{data_fim.strftime('%d/%m/%Y')} ({dias_restantes} dias restantes)")
            
            if dias_restantes < 0:
                Utilitarios.mostrar_status("Status", "EXPIRADO", status="erro")
            elif dias_restantes < 30:
                Utilitarios.mostrar_status("Status", f"Expira em {dias_restantes} dias", status="alerta")
            else:
                Utilitarios.mostrar_status("Status", "Válido", status="sucesso")
        
        # Algoritmo de assinatura
        if 'signatureAlgorithm' in cert:
            Utilitarios.mostrar_status("Algoritmo", cert['signatureAlgorithm'])
        
        # SANs (Subject Alternative Names)
        if 'subjectAltName' in cert:
            Utilitarios.cabecalho_secao(" NOMES ALTERNATIVOS (SANs) ", "-", Cores.AZUL)
            for tipo, nome in cert['subjectAltName']:
                print(f"{Cores.BRANCO}- {tipo}: {nome}{Cores.RESET}")
    
    def _verificar_vulnerabilidades_ssl(self, ssock):
        """Verifica vulnerabilidades comuns em SSL/TLS."""
        Utilitarios.cabecalho_secao(" VERIFICAÇÃO DE VULNERABILIDADES ", "-", Cores.ROXO)
        
        # Obter informações da conexão SSL
        cipher = ssock.cipher()
        if cipher:
            Utilitarios.mostrar_status("Cifra atual", f"{cipher[0]} ({cipher[1]} bits)")
            
            # Verificar cifras fracas
            cifras_fracas = ['DES', 'RC4', '3DES', 'NULL', 'EXPORT']
            if any(cifra_fraca in cipher[0] for cifra_fraca in cifras_fracas):
                Utilitarios.mostrar_status("Cifra", "FRACA detectada", status="erro")
            else:
                Utilitarios.mostrar_status("Cifra", "Segura", status="sucesso")
        
        # Verificar versão do protocolo
        protocolo = ssock.version()
        if protocolo == 'TLSv1':
            Utilitarios.mostrar_status("Protocolo", "TLSv1 (OBSOLETO)", status="erro")
        elif protocolo == 'TLSv1.1':
            Utilitarios.mostrar_status("Protocolo", "TLSv1.1 (DESATUALIZADO)", status="alerta")
        elif protocolo in ['TLSv1.2', 'TLSv1.3']:
            Utilitarios.mostrar_status("Protocolo", f"{protocolo} (RECOMENDADO)", status="sucesso")
        else:
            Utilitarios.mostrar_status("Protocolo", f"{protocolo} (DESCONHECIDO)", status="alerta")
    
    def scan_portas(self, dominio):
        """Varredura de portas avançada com multi-threading."""
        Utilitarios.cabecalho_secao(" VARREURA DE PORTAS ", "=")
        
        try:
            ip = socket.gethostbyname(dominio)
            Utilitarios.mostrar_status(f"Varrendo {dominio} ({ip})", status="info")
            
            portas_abertas = []
            
            # Usando ThreadPoolExecutor para varredura mais rápida
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS) as executor:
                futures = []
                
                for porta, servico in Config.PORTAS_COMUNS.items():
                    futures.append(executor.submit(self._verificar_porta, ip, porta, servico))
                
                # Barra de progresso
                with tqdm(total=len(Config.PORTAS_COMUNS), desc=f"{Cores.AZUL}Varrendo portas{Cores.RESET}", unit="porta") as pbar:
                    for future in futures:
                        resultado = future.result()
                        if resultado:
                            portas_abertas.append(resultado)
                        pbar.update(1)
            
            # Resultados
            if portas_abertas:
                Utilitarios.cabecalho_secao(" PORTAS ABERTAS ", "-", Cores.VERDE)
                for porta, servico in portas_abertas:
                    print(f"{Cores.BRANCO}- Porta {porta}: {Cores.VERDE}{servico}{Cores.RESET}")
            else:
                Utilitarios.mostrar_status("Nenhuma porta comum aberta encontrada", status="alerta")
            
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na varredura de portas: {str(e)}", status="erro")
    
    def _verificar_porta(self, ip, porta, servico):
        """Verifica se uma porta específica está aberta."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        resultado = sock.connect_ex((ip, porta))
        sock.close()
        
        if resultado == 0:
            return (porta, servico)
        return None
    
    def deteccao_tecnologias(self, dominio):
        """Detecção avançada de tecnologias utilizadas no website."""
        Utilitarios.cabecalho_secao(" DETECÇÃO DE TECNOLOGIAS ", "=")
        
        try:
            url = f"https://{dominio}" if not dominio.startswith(('http://', 'https://')) else dominio
            resposta = requests.get(url, headers={'User-Agent': self.user_agent}, 
                                  timeout=self.timeout, verify=False, allow_redirects=True)
            
            # Detecção baseada em cabeçalhos e conteúdo
            tecnologias = self._detectar_tecnologias(resposta)
            
            # Verificar arquivos comuns
            arquivos_encontrados = self._verificar_arquivos_comuns(url)
            
            # Exibir resultados
            if tecnologias:
                Utilitarios.cabecalho_secao(" TECNOLOGIAS DETECTADAS ", "-", Cores.AZUL)
                for categoria, itens in tecnologias.items():
                    if itens:
                        print(f"{Cores.CIANO}{categoria}:{Cores.RESET}")
                        for item in itens:
                            print(f"{Cores.BRANCO}- {item}{Cores.RESET}")
            else:
                Utilitarios.mostrar_status("Nenhuma tecnologia comum detectada", status="alerta")
            
            if arquivos_encontrados:
                Utilitarios.cabecalho_secao(" ARQUIVOS ENCONTRADOS ", "-", Cores.ROXO)
                for arquivo in arquivos_encontrados:
                    print(f"{Cores.BRANCO}- {arquivo}{Cores.RESET}")
            
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro na detecção de tecnologias: {str(e)}", status="erro")
    
    def _detectar_tecnologias(self, resposta):
        """Detecta tecnologias baseadas em cabeçalhos e conteúdo."""
        tecnologias = {
            "CMS": [],
            "Frameworks Front-end": [],
            "Linguagens Back-end": [],
            "Servidores Web": [],
            "Bibliotecas JavaScript": [],
            "Outras Tecnologias": []
        }
        
        # Verificar CMS
        if 'wp-content' in resposta.text or 'wp-includes' in resposta.text:
            tecnologias["CMS"].append("WordPress")
        elif 'Joomla' in resposta.text:
            tecnologias["CMS"].append("Joomla")
        elif 'Drupal' in resposta.text:
            tecnologias["CMS"].append("Drupal")
        elif '/_next/' in resposta.text:
            tecnologias["CMS"].append("Next.js")
        
        # Verificar frameworks JavaScript
        if 'react' in resposta.text.lower() or 'react-dom' in resposta.text.lower():
            tecnologias["Frameworks Front-end"].append("React")
        elif 'angular' in resposta.text.lower():
            tecnologias["Frameworks Front-end"].append("Angular")
        elif 'vue' in resposta.text.lower():
            tecnologias["Frameworks Front-end"].append("Vue.js")
        
        # Verificar linguagens de programação
        if '.php' in resposta.text.lower():
            tecnologias["Linguagens Back-end"].append("PHP")
        elif 'asp.net' in resposta.text.lower():
            tecnologias["Linguagens Back-end"].append("ASP.NET")
        elif 'laravel' in resposta.text.lower():
            tecnologias["Linguagens Back-end"].append("Laravel")
        
        # Verificar servidor web
        servidor = resposta.headers.get('Server', '').lower()
        if 'apache' in servidor:
            tecnologias["Servidores Web"].append("Apache")
        elif 'nginx' in servidor:
            tecnologias["Servidores Web"].append("Nginx")
        elif 'iis' in servidor:
            tecnologias["Servidores Web"].append("Microsoft IIS")
        
        # Verificar bibliotecas JavaScript
        if 'jquery' in resposta.text.lower():
            tecnologias["Bibliotecas JavaScript"].append("jQuery")
        if 'bootstrap' in resposta.text.lower():
            tecnologias["Bibliotecas JavaScript"].append("Bootstrap")
        
        # Verificar outras tecnologias
        if 'cdn.cloudflare.com' in resposta.text:
            tecnologias["Outras Tecnologias"].append("Cloudflare")
        if 'google-analytics.com' in resposta.text:
            tecnologias["Outras Tecnologias"].append("Google Analytics")
        
        return tecnologias
    
    def _verificar_arquivos_comuns(self, url_base):
        """Verifica a existência de arquivos comuns no servidor."""
        arquivos_comuns = [
            'robots.txt', 'sitemap.xml', '.env', 'wp-config.php',
            'package.json', 'composer.json', 'yarn.lock',
            'phpinfo.php', 'test.php', 'admin.php', 'config.php',
            '.git/config', '.htaccess', 'web.config'
        ]
        
        encontrados = []
        
        for arquivo in arquivos_comuns:
            try:
                url = f"{url_base}/{arquivo}"
                resposta = requests.head(url, timeout=2, allow_redirects=False)
                if resposta.status_code == 200:
                    encontrados.append(arquivo)
            except:
                continue
        
        return encontrados
    
    def scan_completo(self, dominio):
        """Executa todas as análises disponíveis em sequência."""
        inicio = time.time()
        Utilitarios.cabecalho_secao(f" SCAN COMPLETO: {dominio.upper()} ", "#", Cores.MAGENTA)
        
        funcoes = [
            ("Análise de IP", self.scan_ip),
            ("WHOIS Avançado", self.whois_avancado),
            ("Análise DNS", self.analise_dns),
            ("Varredura de Subdomínios", self.scan_subdominios),
            ("Análise de Cabeçalhos", self.analise_headers),
            ("Análise SSL/TLS", self.analise_ssl),
            ("Varredura de Portas", self.scan_portas),
            ("Detecção de Tecnologias", self.deteccao_tecnologias)
        ]
        
        for nome, funcao in funcoes:
            Utilitarios.cabecalho_secao(f" {nome} ", "~", Cores.AZUL)
            funcao(dominio)
            time.sleep(1)  # Evitar rate limiting
        
        tempo_execucao = Utilitarios.calcular_tempo_execucao(inicio)
        Utilitarios.cabecalho_secao(" SCAN CONCLUÍDO ", "#", Cores.MAGENTA)
        Utilitarios.mostrar_status(f"Tempo total de execução: {tempo_execucao}", status="destaque")
    
    def gerar_relatorio(self, dominio):
        """Gera um relatório completo em arquivo HTML e TXT."""
        Utilitarios.cabecalho_secao(" GERAR RELATÓRIO ", "=")
        
        data_hora = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"lucid_relatorio_{dominio}_{data_hora}"
        
        try:
            # Gerar relatório em TXT
            with open(f"{nome_arquivo}.txt", 'w', encoding='utf-8') as f:
                original_stdout = sys.stdout
                sys.stdout = f
                
                print(f"Relatório LUCID para {dominio}")
                print(f"Gerado em: {Utilitarios.formatar_data_hora()}\n")
                self.scan_completo(dominio)
                
                sys.stdout = original_stdout
            
            # Gerar relatório em HTML (simplificado)
            self._gerar_html_relatorio(dominio, f"{nome_arquivo}.html")
            
            Utilitarios.mostrar_status(f"Relatórios salvos como:", f"{nome_arquivo}.txt e {nome_arquivo}.html", status="sucesso")
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro ao gerar relatório: {str(e)}", status="erro")
    
    def _gerar_html_relatorio(self, dominio, nome_arquivo):
        """Gera um relatório HTML estilizado."""
        # Implementação básica - pode ser expandida
        html = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório LUCID - {dominio}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
        h2 {{ color: #2980b9; }}
        .sucesso {{ color: #27ae60; }}
        .erro {{ color: #e74c3c; }}
        .alerta {{ color: #f39c12; }}
        .info {{ color: #3498db; }}
        .destaque {{ font-weight: bold; }}
        .secao {{ margin-bottom: 30px; border-left: 4px solid #3498db; padding-left: 15px; }}
        .item {{ margin-bottom: 10px; }}
    </style>
</head>
<body>
    <h1>Relatório LUCID - {dominio}</h1>
    <p>Gerado em: {Utilitarios.formatar_data_hora()}</p>
    
    <div class="secao">
        <h2>Informações Gerais</h2>
        <div class="item"><span class="destaque">Domínio:</span> {dominio}</div>
        <!-- Mais informações podem ser adicionadas aqui -->
    </div>
    
    <div class="secao">
        <h2>Observações</h2>
        <p>Este é um relatório gerado automaticamente pelo LUCID Security Scanner v{Config.VERSAO}.</p>
        <p>Para informações detalhadas, consulte o arquivo TXT anexo.</p>
    </div>
</body>
</html>
        """
        
        with open(nome_arquivo, 'w', encoding='utf-8') as f:
            f.write(html)

# =============================================
# INTERFACE DO USUÁRIO E MENUS
# =============================================

class InterfaceUsuario:
    def __init__(self):
        self.analisador = AnalisadorSeguranca()
        self.rodando = True
    
    def sequencia_inicial(self):
        """Exibe a sequência inicial do programa com animações."""
        Utilitarios.limpar_tela()
        
        # Exibir banner com efeito
        Utilitarios.efeito_digitacao(BANNER_LUCID, 0.005)
        time.sleep(0.5)
        
        # Exibir informações da versão
        print(f"\n{Cores.ROXO}{Cores.DESTAQUE}Versão: {Config.VERSAO} | Autor: {Config.AUTOR} | Contato: {Config.CONTATO}{Cores.RESET}")
        
        # Animação de inicialização
        Utilitarios.animacao_carregamento(3, "Inicializando sistema")
        
        # Verificar conexão com a internet
        if not Utilitarios.verificar_conexao():
            Utilitarios.mostrar_status("Sem conexão com a internet. Algumas funcionalidades podem não funcionar.", status="alerta")
            time.sleep(1)
        
        # Verificar API Shodan
        if not self.analisador.shodan_api:
            Utilitarios.mostrar_status("API Shodan não configurada. Algumas funcionalidades estarão limitadas.", status="alerta")
            time.sleep(1)
        
        Utilitarios.mostrar_status("Sistema pronto. Bem-vindo ao LUCID Security Scanner!", status="sucesso")
        time.sleep(1)
    
    def mostrar_menu_ajuda(self):
        """Exibe o menu de ajuda detalhado."""
        Utilitarios.limpar_tela()
        print(BANNER_LUCID)
        Utilitarios.cabecalho_secao(" MENU DE AJUDA ", "=")
        
        opcoes = [
            ("1. Análise de IP", "Resolução DNS, geolocalização e dados Shodan"),
            ("2. WHOIS Avançado", "Informações de registro e contatos do domínio"),
            ("3. Análise DNS", "Consulta múltiplos registros DNS e configurações"),
            ("4. Varredura de Subdomínios", "Busca por subdomínios comuns"),
            ("5. Análise de Cabeçalhos", "Inspeção de cabeçalhos HTTP e segurança"),
            ("6. Análise SSL/TLS", "Verificação de certificados e configurações"),
            ("7. Varredura de Portas", "Verificação de portas abertas e serviços"),
            ("8. Detecção de Tecnologias", "Identificação de CMS, frameworks e linguagens"),
            ("9. Scan Completo", "Executa todas as análises disponíveis"),
            ("R. Gerar Relatório", "Salva os resultados em arquivo (TXT e HTML)"),
            ("H. Ajuda", "Exibe este menu de ajuda"),
            ("0. Sair", "Encerra o programa")
        ]
        
        for opcao, descricao in opcoes:
            print(f"\n{Cores.AMARELO}{Cores.DESTAQUE}{opcao}{Cores.RESET}")
            print(f"  {Cores.BRANCO}{descricao}{Cores.RESET}")
        
        Utilitarios.aguardar_enter()
    
    def menu_principal(self):
        """Gerencia o menu principal e as interações do usuário."""
        while self.rodando:
            Utilitarios.limpar_tela()
            print(BANNER_SECUNDARIO)
            Utilitarios.cabecalho_secao(" MENU PRINCIPAL ", "=")
            
            opcoes = [
                ("1", "Análise de IP"),
                ("2", "WHOIS Avançado"),
                ("3", "Análise DNS"),
                ("4", "Varredura de Subdomínios"),
                ("5", "Análise de Cabeçalhos"),
                ("6", "Análise SSL/TLS"),
                ("7", "Varredura de Portas"),
                ("8", "Detecção de Tecnologias"),
                ("9", "Scan Completo"),
                ("R", "Gerar Relatório"),
                ("H", "Ajuda"),
                ("0", "Sair")
            ]
            
            # Exibir opções em duas colunas
            metade = (len(opcoes) + 1) // 2
            for i in range(metade):
                op1 = opcoes[i]
                op2 = opcoes[i + metade] if i + metade < len(opcoes) else None
                
                linha = f"{Cores.AMARELO}{op1[0]}.{Cores.RESET} {op1[1].ljust(25)}"
                if op2:
                    linha += f"  {Cores.AMARELO}{op2[0]}.{Cores.RESET} {op2[1]}"
                
                print(linha)
            
            # Obter escolha do usuário
            try:
                opcao = input(f"\n{Cores.AMARELO}{Cores.DESTAQUE}>>> {Cores.RESET}").strip().lower()
                
                if opcao == '0':
                    self._sair()
                elif opcao == 'h':
                    self.mostrar_menu_ajuda()
                elif opcao in ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'r']:
                    self._processar_opcao(opcao)
                else:
                    Utilitarios.mostrar_status("Opção inválida. Tente novamente.", status="erro")
                    time.sleep(1)
            
            except KeyboardInterrupt:
                Utilitarios.mostrar_status("\nOperação cancelada pelo usuário.", status="alerta")
                Utilitarios.aguardar_enter()
            except Exception as e:
                Utilitarios.mostrar_status(f"Erro: {str(e)}", status="erro")
                Utilitarios.aguardar_enter()
    
    def _processar_opcao(self, opcao):
        """Processa a opção selecionada pelo usuário."""
        dominio = input(f"{Cores.AZUL}Informe o domínio (ex: exemplo.com): {Cores.RESET}").strip()
        
        if not Utilitarios.validar_dominio(dominio):
            Utilitarios.mostrar_status("Formato de domínio inválido. Use: exemplo.com", status="erro")
            Utilitarios.aguardar_enter()
            return
        
        try:
            if opcao == '1':
                self.analisador.scan_ip(dominio)
            elif opcao == '2':
                self.analisador.whois_avancado(dominio)
            elif opcao == '3':
                self.analisador.analise_dns(dominio)
            elif opcao == '4':
                self.analisador.scan_subdominios(dominio)
            elif opcao == '5':
                self.analisador.analise_headers(dominio)
            elif opcao == '6':
                self.analisador.analise_ssl(dominio)
            elif opcao == '7':
                self.analisador.scan_portas(dominio)
            elif opcao == '8':
                self.analisador.deteccao_tecnologias(dominio)
            elif opcao == '9':
                self.analisador.scan_completo(dominio)
            elif opcao == 'r':
                self.analisador.gerar_relatorio(dominio)
            
            Utilitarios.aguardar_enter()
        
        except KeyboardInterrupt:
            Utilitarios.mostrar_status("\nOperação cancelada pelo usuário.", status="alerta")
        except Exception as e:
            Utilitarios.mostrar_status(f"Erro durante a operação: {str(e)}", status="erro")
    
    def _sair(self):
        """Encerra o programa com mensagem de despedida."""
        Utilitarios.efeito_digitacao(f"{Cores.VERDE}Obrigado por usar o LUCID Security Scanner. Até logo!", 0.03)
        self.rodando = False

# =============================================
# PONTO DE ENTRADA PRINCIPAL
# =============================================

if __name__ == "__main__":
    try:
        interface = InterfaceUsuario()
        interface.sequencia_inicial()
        interface.menu_principal()
    except KeyboardInterrupt:
        print(f"\n{Cores.VERMELHO}Programa encerrado pelo usuário.{Cores.RESET}")
        sys.exit(0)
    except Exception as e:
        Utilitarios.mostrar_status(f"Erro crítico: {str(e)}", status="erro")
        sys.exit(1)
