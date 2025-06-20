# 🐰 LUCID — Website Scanner Tool | by Darius

![Status](https://img.shields.io/badge/status-ativo-brightgreen?style=for-the-badge)
![Feito para](https://img.shields.io/badge/Feito%20para-Termux%20%26%20Kali-informational?style=for-the-badge&logo=linux)

---

## 🚀 O que é a Lucid?

**Lucid** é uma ferramenta de scanner de sites em Python com visual hacker e arte ASCII. Desenvolvida para rodar direto no **Termux** ou **Kali Linux**, ela mostra tudo que você precisa saber sobre um domínio!

---

## 🧠 Funcionalidades

| Nº | Módulo                  | Descrição                                         |
|----|--------------------------|--------------------------------------------------|
| 1  | WHOIS Lookup             | Ver infos do domínio (dono, criação, expiração)  |
| 2  | IP Lookup                | Mostra o IP real do site                         |
| 3  | DNS Lookup               | Registros A, MX, NS, TXT                         |
| 4  | GeoIP                    | Localização geográfica do IP (país, cidade)      |
| 5  | Detectar Cloudflare      | Descobre se o site está protegido por Cloudflare |
| 6  | Checar portas 80/443     | Verifica se portas HTTP/HTTPS estão abertas      |

---

## 🎨 Visual

- Coelho em **ASCII colorido**
- Layout estilo **terminal hacker**
- Interface 100% interativa com cores ⚠️✅🧠

---

## 💻 Instalação (Termux ou Kali Linux)

```bash
# Atualize o sistema
pkg update && pkg upgrade -y

# Instale os pacotes necessários
pkg install git python -y
pip install colorama python-whois dnspython requests

# Clone este repositório
git clone https://github.com/SEU-USUARIO/lucid
cd lucid

# Execute a ferramenta
python lucid_v2.py

★ LUCID SCANNER v2.0 ★
1. WHOIS Lookup
2. IP Lookup
3. DNS Lookup
4. GeoIP (Localização)
5. Detectar Cloudflare
6. Checar portas 80/443
7. Sair
