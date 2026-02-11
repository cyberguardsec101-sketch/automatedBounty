# automatedBounty
Automated Bug Bounty Recon by:DrkShdw47
DRKSHDW - Automated Bug Bounty Framework 🚀





























DRKSHDW es un framework de automatización para Bug Bounty diseñado para hackers que buscan maximizar su eficiencia en el reconocimiento y la identificación de vulnerabilidades. Combina técnicas de OSINT, escaneo activo, fuzzing inteligente y análisis de vulnerabilidades en un solo flujo de trabajo.

🛠️ Características Elite

•
Reconocimiento Exhaustivo: Subdominios (crt.sh), URLs históricas (Wayback Machine).

•
Dorking Personalizado: Identificación automática de dorks para archivos .env, .git, logs y paneles de administración.

•
Fuzzing Inteligente: Integración con dirsearch para encontrar archivos sensibles basados en el historial del dominio.

•
Escaneo de Vulnerabilidades: Motor de Nmap con scripts --script vuln integrados.

•
Análisis de Shodan: Reconocimiento pasivo profundo (requiere API Key).

•
Sugerencias de PoC: El analizador no solo encuentra fallos, sino que te sugiere cómo validarlos.

🚀 Instalación Rápida

Copia y pega este comando para instalar todas las dependencias necesarias en Ubuntu/Debian:

Bash


sudo apt-get update && sudo apt-get install -y nmap ffuf dirsearch python3-pip && \
sudo pip3 install python-nmap requests beautifulsoup4 shodan



📖 Modo de Uso

1. Reconocimiento (Recon Master)

Puedes correrlo para un solo dominio o para una lista completa.

Individual:

Bash


python3 recon_master.py example.com



Lista de dominios:

Bash


python3 recon_master.py -l targets.txt



2. Análisis de Vulnerabilidades (Vuln Analyzer)

Una vez generado el archivo JSON de reconocimiento, pásalo al analizador:

Bash


python3 vuln_analyzer.py recon_example.com.json



3. Integración con Shodan (Opcional)

Para activar el reconocimiento pasivo de Shodan, exporta tu API Key:

Bash


export SHODAN_API_KEY='TU_API_KEY_AQUI'



🎯 Estrategia de Hacker Elite

1.
Fuzzing: Usa los resultados de recon_master.py para alimentar ffuf con wordlists personalizadas.

2.
Dorking: No ignores los dorks generados; ejecútalos manualmente en Google para encontrar "low hanging fruits".

3.
Validación: Usa las sugerencias de poc_suggestion en el reporte final para crear tus informes en HackerOne o Bugcrowd.




Disclaimer: Esta herramienta es solo para fines educativos y de seguridad autorizada. El uso de esta herramienta contra objetivos sin consentimiento previo es ilegal.

