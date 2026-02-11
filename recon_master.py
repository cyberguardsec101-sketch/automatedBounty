import requests
import nmap
import json
import sys
import os
import time
import subprocess
from bs4 import BeautifulSoup

RED = "\033[1;31m"
RESET = "\033[0;0m"

BANNER = f"""{RED}
▓█████▄  ██▀███   ██ ▄█▀  ██████  ██░ ██ ▓█████▄  █     █░
▒██▀ ██▌▓██ ▒ ██▒ ██▄█▒ ▒██    ▒ ▓██░ ██▒▒██▀ ██▌▓█░ █ ░█░
░██   █▌▓██ ░▄█ ▒▓███▄░ ░ ▓██▄   ▒██▀▀██░░██   █▌▒█░ █ ░█ 
░▓█▄   ▌▒██▀▀█▄  ▓██ █▄   ▒   ██▒░▓█ ░██ ░▓█▄   ▌░█░ █ ░█ 
░▒████▓ ░██▓ ▒██▒▒██▒ █▄▒██████▒▒░▓█▒░██▓░▒████▓ ░░██▒██▓ 
 ▒▒▓  ▒ ░ ▒▓ ░▒▓░▒ ▒▒ ▓▒▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒▓  ▒ ░ ▓░▒ ▒  
 ░ ▒  ▒   ░▒ ░ ▒░░ ░▒ ▒░░ ░▒  ░ ░ ▒ ░▒░ ░ ░ ▒  ▒   ▒ ░ ░  
 ░ ░  ░   ░░   ░ ░ ░░ ░ ░  ░  ░   ░  ░░ ░ ░ ░  ░   ░   ░  
   ░       ░     ░  ░         ░   ░  ░  ░   ░        ░    
 ░                                        ░               
                 by:DrkShdw47 
                                                          
          [ ELITE BUG BOUNTY FRAMEWORK ]
{RESET}"""

class ReconMaster:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "subdomains": [],
            "wayback_urls": [],
            "dorks_found": [],
            "fuzzing_results": [],
            "technologies": {},
            "nmap_scan": {}
        }

    def get_subdomains(self):
        print(f"[*] Identificando subdominios para {self.target}...")
        try:
            url = f"https://crt.sh/?q=%25.{self.target}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                subdomains = set([item['name_value'] for item in data])
                self.results["subdomains"] = list(subdomains)
        except Exception as e:
            print(f"[!] Error en subdominios: {e}")

    def get_wayback_urls(self):
        print(f"[*] Extrayendo URLs de Wayback Machine para {self.target}...")
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target}/*&output=json&collapse=urlkey"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                self.results["wayback_urls"] = [item[2] for item in data[1:]][:200]
        except Exception as e:
            print(f"[!] Error en Wayback: {e}")

    def run_dorking(self):
        print(f"[*] Ejecutando Dorking personalizado para {self.target}...")
        dorks = [
            f"site:{self.target} ext:env",
            f"site:{self.target} ext:log",
            f"site:{self.target} intitle:index.of",
            f"site:{self.target} inurl:admin",
            f"site:{self.target} \"PHP Parse error\"",
            f"site:{self.target} \"SQL syntax error\""
        ]
        # En un script real, usaríamos una API de búsqueda o scraping cauteloso
        # Aquí guardamos los dorks para que el usuario los ejecute o para futura integración
        self.results["dorks_found"] = dorks

    def run_fuzzing(self):
        print(f"[*] Iniciando Fuzzing inteligente basado en Wayback para {self.target}...")
        # Usamos dirsearch de forma básica para el ejemplo
        try:
            # Escaneamos solo el dominio principal para no demorar demasiado en el ejemplo
            cmd = f"dirsearch -u http://{self.target} -e php,txt,html,js,env,git --format=json -o fuzz_{self.target}.json"
            subprocess.run(cmd.split(), capture_output=True, text=True)
            if os.path.exists(f"fuzz_{self.target}.json"):
                with open(f"fuzz_{self.target}.json", 'r') as f:
                    self.results["fuzzing_results"] = json.load(f)
        except Exception as e:
            print(f"[!] Error en Fuzzing: {e}")

    def detect_tech(self):
        print(f"[*] Detectando tecnologías para {self.target}...")
        try:
            response = requests.get(f"http://{self.target}", timeout=10)
            self.results["technologies"]["headers"] = dict(response.headers)
            self.results["technologies"]["server"] = response.headers.get("Server", "Unknown")
        except Exception as e:
            print(f"[!] Error en detección de tech: {e}")

    def run_nmap(self):
        print(f"[*] Ejecutando escaneo de vulnerabilidades Nmap para {self.target}...")
        nm = nmap.PortScanner()
        try:
            nm.scan(self.target, arguments='-T4 -F -sV --script vuln')
            for host in nm.all_hosts():
                self.results["nmap_scan"][host] = []
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        service = nm[host][proto][port]
                        self.results["nmap_scan"][host].append({
                            "port": port,
                            "name": service['name'],
                            "product": service.get('product', ''),
                            "version": service.get('version', ''),
                            "script": service.get('script', {})
                        })
        except Exception as e:
            print(f"[!] Error en Nmap: {e}")

    def run_all(self):
        self.get_subdomains()
        self.get_wayback_urls()
        self.run_dorking()
        self.detect_tech()
        self.run_fuzzing()
        self.run_nmap()
        
        output_file = f"recon_{self.target}.json"
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Reconocimiento finalizado para {self.target}. Guardado en {output_file}")
        return output_file

def process_list(file_path):
    if not os.path.exists(file_path):
        print(f"[!] El archivo {file_path} no existe.")
        return
    with open(file_path, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    for domain in domains:
        print(f"\n{'='*60}\nPROCESANDO: {domain}\n{'='*60}")
        recon = ReconMaster(domain)
        recon.run_all()

if __name__ == "__main__":
    print(BANNER)
    if len(sys.argv) < 2:
        print("Uso individual: python3 recon_master.py <dominio>")
        print("Uso con lista:  python3 recon_master.py -l <archivo_dominios.txt>")
        sys.exit(1)
    
    if sys.argv[1] == "-l" and len(sys.argv) == 3:
        process_list(sys.argv[2])
    else:
        target_domain = sys.argv[1]
        recon = ReconMaster(target_domain)
        recon.run_all()
