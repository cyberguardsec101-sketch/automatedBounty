import json
import sys
import os
import shodan

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
                                                          
          [ VULNERABILITY ANALYZER & POC ]
{RESET}"""

SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

class VulnAnalyzer:
    def __init__(self, recon_file):
        self.recon_file = recon_file
        with open(recon_file, 'r') as f:
            self.data = json.load(f)
        self.vulnerabilities = []
        self.shodan_api = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

    def check_shodan(self, target):
        if not self.shodan_api:
            return
        print(f"[*] Consultando Shodan para {target}...")
        try:
            results = self.shodan_api.search(f"hostname:{target}")
            for result in results['matches']:
                self.vulnerabilities.append({
                    "source": "Shodan",
                    "ip": result['ip_str'],
                    "port": result['port'],
                    "vulns": result.get('vulns', []),
                    "poc_suggestion": "Verificar si el servicio expuesto tiene exploits conocidos en Exploit-DB."
                })
        except Exception as e:
            print(f"[!] Error en Shodan: {e}")

    def analyze_fuzzing(self):
        print("[*] Analizando resultados de Fuzzing para archivos sensibles...")
        fuzz_results = self.data.get("fuzzing_results", {})
        # Estructura de dirsearch puede variar, buscamos códigos 200 en archivos clave
        if isinstance(fuzz_results, dict) and "results" in fuzz_results:
            for res in fuzz_results["results"]:
                if res["status"] == 200:
                    self.vulnerabilities.append({
                        "type": "Sensitive File Found",
                        "url": res["url"],
                        "poc_suggestion": f"Acceder a {res['url']} y verificar si contiene credenciales o info sensible."
                    })

    def analyze_nmap_vulns(self):
        print("[*] Analizando hallazgos de Nmap Vuln Scan...")
        for host, services in self.data.get("nmap_scan", {}).items():
            for service in services:
                scripts = service.get("script", {})
                if scripts:
                    for script_name, output in scripts.items():
                        self.vulnerabilities.append({
                            "host": host,
                            "port": service["port"],
                            "vuln_found": script_name,
                            "details": output,
                            "poc_suggestion": "Usar el script de Nmap como base para crear un exploit manual o validar con Burp Suite."
                        })

    def generate_report(self):
        self.check_shodan(self.data["target"])
        self.analyze_fuzzing()
        self.analyze_nmap_vulns()
        
        report_file = f"vuln_report_{self.data['target']}.json"
        with open(report_file, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=4)
        
        print(f"\n[+] Análisis completado. Reporte: {report_file}")
        print(f"[+] Hallazgos con sugerencias de PoC: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print(f"\n{RED}[!] ATENCIÓN: Se encontraron posibles vulnerabilidades. Revisa el reporte para las sugerencias de PoC.{RESET}")

if __name__ == "__main__":
    print(BANNER)
    if len(sys.argv) < 2:
        print("Uso: python3 vuln_analyzer.py <archivo_recon.json>")
        sys.exit(1)
    
    analyzer = VulnAnalyzer(sys.argv[1])
    analyzer.generate_report()
