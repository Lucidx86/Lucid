import socket
import requests
import whois
import dns.resolver
import ssl
import os
import time
from colorama import Fore, Style, init

init(autoreset=True)

# Cores
R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
W = Fore.WHITE
B = Fore.BLUE
M = Fore.MAGENTA

ascii_bear = """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣶⣾⣿⣿⣷⣶⣤⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡿⠛⠉⠉⠁⠀⠀⠀⠀⠈⠉⠙⠛⠻⠿⢿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣷⣦⣄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⠏⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣷⣄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⣿⠏⠀⢀⣤⣶⣿⣿⣿⣿⣯⣭⣝⣻⣿⣿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣷⣄⠀⠀
⠀⠀⠀⠀⣼⣿⣿⡟⠁⠀⣾⣿⣿⡿⠋⠉⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⣿⣿⣿⣷⡄⠀⠀⠀⠀⠀⢿⣿⣿⣿⣄
⠀⠀⠀⣼⣿⣿⡟⠀⠀⠈⣿⡿⠋⠀⠀⠀⢀⣴⣶⣦⡀⠀⢀⣴⣶⣦⡀⠀⠀⠀⠀⢿⣿⣿⣧⠀⠀⠀⠀⢻⣿⣿⣿
⠀⠀⣸⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⠁⠀⠘⣿⣿⠟⠁⠀⠀⠀⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⢿⣿⣿
⠀⠀⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⣿⠀⠀⠀⢸⣿⣿
⠀⠀⢿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠛⠛⠛⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⠀⠀⠀⣼⣿⠇
⠀⠀⠘⢿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣿⠀⠀⣴⣿⠏⠀
⠀⠀⠀⠀⠙⢿⣿⣿⣿⣶⣦⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣠⣾⠟⠁⠀⠀
⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣿⣿⣿⣿⣷⣶⣤⣤⣤⣤⣤⣤⣤⣤⣴⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠁⠀⠀⠀"""

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def beep():
    print('\a', end='')

def typing(text, delay=0.02):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def intro():
    clear()
    typing(f"{C}[ LUCID SYSTEM ] Inicializando...", 0.04)
    time.sleep(0.5)
    typing(f"{C}[ STATUS ] Estabelecendo conexão segura...", 0.04)
    time.sleep(0.5)
    typing(f"{G}[ OK ] Ambiente pronto para execução.\n", 0.04)
    time.sleep(1)

def banner():
    clear()
    print(ascii_bear)
    print(f"{Y}LUCID v3 – SITE SCANNER HACKER BY DARIUS")
    print(f"{C}═══════════════════════════════════════════════════════════")

def wait():
    input(f"\n{Y}[!] Pressione ENTER para voltar ao menu...")

def check_connection():
    try:
        requests.get("https://1.1.1.1", timeout=3)
        return True
    except:
        return False

def scan_ip(url):
    print(f"\n{C}[Rastreamento de IP]")
    try:
        ip = socket.gethostbyname(url)
        print(f"\n{G}[✓] IP de {url}: {W}{ip}")
    except socket.gaierror:
        print(f"\n{R}[✗] Não foi possível resolver o IP.")
    beep()
    wait()

def whois_lookup(url):
    print(f"\n{C}[Consulta WHOIS]")
    try:
        domain = whois.whois(url)
        print(f"\n{G}[✓] Informações WHOIS:\n{W}{domain}")
    except Exception as e:
        print(f"\n{R}[✗] Erro no WHOIS: {e}")
    beep()
    wait()

def dns_lookup(url):
    print(f"\n{C}[Consulta DNS]")
    try:
        result = dns.resolver.resolve(url, 'A')
        print(f"\n{G}[✓] Registros DNS:")
        for ip in result:
            print(f"  {W}- {ip}")
    except Exception as e:
        print(f"\n{R}[✗] Falha na consulta DNS: {e}")
    beep()
    wait()

def subdomain_finder(url):
    print(f"\n{C}[Scan de Subdomínios]")
    subdomains = ["www", "mail", "ftp", "webmail", "cpanel", "blog", "shop", "smtp", "api"]
    found = False
    for sub in subdomains:
        sub_url = f"{sub}.{url}"
        try:
            ip = socket.gethostbyname(sub_url)
            print(f"{G}[+] Encontrado: {W}{sub_url} -> {ip}")
            found = True
        except:
            continue
    if not found:
        print(f"{R}[✗] Nenhum subdomínio encontrado.")
    beep()
    wait()

def header_scan(url):
    print(f"\n{C}[Headers HTTP]")
    try:
        response = requests.get(f"http://{url}", timeout=5)
        for k, v in response.headers.items():
            print(f"{C}{k}: {W}{v}")
    except Exception as e:
        print(f"{R}[✗] Erro ao buscar headers: {e}")
    beep()
    wait()

def ssl_info(url):
    print(f"\n{C}[Informações SSL/TLS]")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=url) as s:
            s.settimeout(3)
            s.connect((url, 443))
            cert = s.getpeercert()
            for k, v in cert.items():
                print(f"{C}{k}: {W}{v}")
    except Exception as e:
        print(f"{R}[✗] Não foi possível obter informações SSL: {e}")
    beep()
    wait()

def main_menu():
    if not check_connection():
        print(f"{R}[!] Sem conexão com a internet.")
        return
    while True:
        banner()
        print(f"""
{Y}Escolha uma função:

{G}[1]{W} Obter IP do domínio
{G}[2]{W} Consulta WHOIS detalhada
{G}[3]{W} Consulta DNS
{G}[4]{W} Procurar Subdomínios comuns
{G}[5]{W} Ver Headers HTTP do site
{G}[6]{W} Analisar certificado SSL/TLS
{G}[0]{W} Sair do Lucid
""")
        op = input(f"{Y}>>> {W}").strip()
        if op == "1":
            url = input(f"{B}Informe o domínio para rastrear IP: {W}")
            scan_ip(url)
        elif op == "2":
            url = input(f"{B}Alvo para análise WHOIS: {W}")
            whois_lookup(url)
        elif op == "3":
            url = input(f"{B}Digite o domínio para consultar DNS: {W}")
            dns_lookup(url)
        elif op == "4":
            url = input(f"{B}Domínio para escanear subdomínios: {W}")
            subdomain_finder(url)
        elif op == "5":
            url = input(f"{B}Site para verificar headers HTTP: {W}")
            header_scan(url)
        elif op == "6":
            url = input(f"{B}Alvo para análise SSL/TLS: {W}")
            ssl_info(url)
        elif op == "0":
            print(f"{G}Saindo da Lucid...\n")
            beep()
            break
        else:
            print(f"{R}[!] Opção inválida.")
            time.sleep(1)

if __name__ == "__main__":
    intro()
    main_menu()
