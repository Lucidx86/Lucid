import socket
import requests
import whois
import dns.resolver
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

def clear():
    os.system("clear" if os.name == "posix" else "cls")

def banner():
    clear()
    print(f"""{C}
    ╔══════════════════════════════════════════════╗
    ║                                              ║
    ║   {G}  _                _     _              {C}║
    ║   {G} | |    ___   __ _| |__ | | ___         {C}║
    ║   {G} | |   / _ \ / _` | '_ \| |/ _ \        {C}║
    ║   {G} | |__| (_) | (_| | |_) | |  __/        {C}║
    ║   {G} |_____\___/ \__,_|_.__/|_|\___|        {C}║
    ║                                              ║
    ║        {Y}Site Scanner by Darius (Lucid){C}         ║
    ╚══════════════════════════════════════════════╝
    """)

def wait():
    input(f"\n{Y}[!] Pressione ENTER para voltar ao menu...")

def scan_ip(url):
    try:
        ip = socket.gethostbyname(url)
        print(f"\n{G}[✓] IP de {url}: {W}{ip}")
    except socket.gaierror:
        print(f"\n{R}[✗] Não foi possível resolver o IP de {url}")
    wait()

def whois_lookup(url):
    try:
        domain = whois.whois(url)
        print(f"\n{G}[✓] Informações WHOIS:\n{W}{domain}")
    except Exception as e:
        print(f"\n{R}[✗] Erro no WHOIS: {e}")
    wait()

def dns_lookup(url):
    try:
        result = dns.resolver.resolve(url, 'A')
        print(f"\n{G}[✓] Registros DNS:")
        for ip in result:
            print(f"  {W}- {ip}")
    except Exception as e:
        print(f"\n{R}[✗] Falha na consulta DNS: {e}")
    wait()

def subdomain_finder(url):
    subdomains = [
        "www", "mail", "ftp", "webmail", "cpanel", "blog", "shop", "smtp", "api"
    ]
    print(f"\n{G}[•] Procurando subdomínios...\n")
    found = False
    for sub in subdomains:
        sub_url = f"{sub}.{url}"
        try:
            ip = socket.gethostbyname(sub_url)
            print(f"{C}[+] Encontrado: {W}{sub_url} -> {ip}")
            found = True
        except:
            continue
    if not found:
        print(f"{R}[✗] Nenhum subdomínio encontrado.")
    wait()

def main_menu():
    while True:
        banner()
        print(f"""
{Y}Escolha uma função:

{G}[1]{W} Scan de IP
{G}[2]{W} Consulta WHOIS
{G}[3]{W} Consulta DNS
{G}[4]{W} Buscar Subdomínios
{G}[0]{W} Sair
""")
        op = input(f"{Y}>>> {W}").strip()
        if op == "1":
            url = input(f"\n{C}Digite o domínio (ex: exemplo.com): {W}")
            scan_ip(url)
        elif op == "2":
            url = input(f"\n{C}Digite o domínio (ex: exemplo.com): {W}")
            whois_lookup(url)
        elif op == "3":
            url = input(f"\n{C}Digite o domínio (ex: exemplo.com): {W}")
            dns_lookup(url)
        elif op == "4":
            url = input(f"\n{C}Digite o domínio (ex: exemplo.com): {W}")
            subdomain_finder(url)
        elif op == "0":
            print(f"{G}Saindo...\n")
            break
        else:
            print(f"{R}[!] Opção inválida.")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
