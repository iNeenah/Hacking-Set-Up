#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  _   _  ______ ______  _   _   __  __ 
# | \ | ||  ____||  ____|| \ | | |  \/  |
# |  \| || |__   | |__   |  \| | | \  / |
# | . ` ||  __|  |  __|  | . ` | | |\/| |
# | |\  || |____ | |____ | |\  | | |  | |
# |_| \_||______||______||_| \_| |_|  |_|
#
# HTB Operations Starter v3.0 - Asistente Inteligente by Neenah
#

import os
import subprocess
import sys
import time
import argparse
from threading import Thread
from itertools import cycle

# --- CONFIGURACIÓN CENTRALIZADA ---
# Modifica estas variables para adaptar el script a tu gusto.
CONFIG = {
    "HTB_PATH": "~/htb",
    "VPN_PATH": "~/vpns", # Ruta donde guardas tus archivos .ovpn
    "SHELL": "/usr/bin/zsh",
    "WORDLISTS": {
        "vhost": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "dir_fuzz": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    },
    "TOOLS": {
        "nmap": "sudo nmap {TARGET_IP} -oA {OUTPUT_DIR}/nmap/{SCAN_TYPE}",
        "ffuf_vhost": "ffuf -w {WORDLIST} -H 'Host: FUZZ.{BOX_NAME}.htb' -u http://{TARGET_IP}",
        "ffuf_dir": "ffuf -w {WORDLIST} -u http://{TARGET_IP}/FUZZ -e .php,.html,.txt,.bak"
    },
    "USE_I3_FULLSCREEN": True, # Cambia a False si no usas i3
    "I3_FULLSCREEN_CMD": "i3-msg '[con_id=\"__focused__\"] fullscreen enable'"
}

# --- COLORES PARA LA TERMINAL ---
class C:
    OK = '\033[92m'
    INFO = '\033[94m'
    WARN = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    CYAN = '\033[96m'

# --- CLASE DE UTILIDADES ---
class HtbSetup:
    def __init__(self, box_name, box_ip, domain=None):
        if not box_name or not box_ip:
            print(f"{C.FAIL}[-] Nombre de la máquina e IP son requeridos.{C.END}")
            sys.exit(1)
        
        self.box_name = box_name
        self.box_ip = box_ip
        self.domain = domain
        self.box_path = os.path.join(CONFIG["HTB_PATH"], self.box_name)
        self.spinner_stop = False
        self.tun0_ip = None

    def _is_host_alive(self):
        """Just pings the host once without spinner. Returns True if alive."""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '1', self.box_ip], capture_output=True)
            return result.returncode == 0
        except Exception:
            return False

    def _spinner(self, message=""):
        """A generic spinner."""
        for char in cycle(['|', '/', '-', '\\']):
            if self.spinner_stop:
                break
            sys.stdout.write(f'\r{C.INFO}{message} {char}{C.END}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(message) + 5) + '\r')

    def _manage_vpn(self):
        """Handles VPN connection logic."""
        print(f"{C.WARN}[!] El host no responde. Asistente de VPN iniciado.{C.END}")
        vpn_dir = os.path.expanduser(CONFIG["VPN_PATH"])
        try:
            ovpn_files = [f for f in os.listdir(vpn_dir) if f.endswith(".ovpn")]
            if not ovpn_files:
                print(f"{C.FAIL}[-] No se encontraron archivos .ovpn en {vpn_dir}{C.END}")
                sys.exit(1)

            print(f"{C.INFO}[i] Se encontraron las siguientes VPNs:{C.END}")
            for i, f in enumerate(ovpn_files):
                print(f"  {C.CYAN}[{i+1}]{C.END} {f}")
            
            choice = int(input(f"{C.INFO}[?] Elige el número de la VPN a conectar: {C.END}")) - 1
            vpn_file = os.path.join(vpn_dir, ovpn_files[choice])

            print(f"{C.INFO}[i] Conectando a {ovpn_files[choice]}... (requiere sudo){C.END}")
            subprocess.run(['sudo', 'openvpn', '--config', vpn_file, '--daemon'], check=True)
            print(f"{C.OK}[+] Comando de OpenVPN ejecutado. Esperando conexión...{C.END}")
            time.sleep(5)

        except (ValueError, IndexError):
            print(f"{C.FAIL}[-] Selección inválida.{C.END}")
            sys.exit(1)
        except Exception as e:
            print(f"{C.FAIL}[-] Error al gestionar la VPN: {e}{C.END}")
            sys.exit(1)

    def _ensure_connectivity(self):
        """Checks for connectivity and launches VPN wizard if needed."""
        print(f"{C.INFO}[i] Verificando conectividad con {self.box_ip}...{C.END}")
        
        spinner_thread = Thread(target=self._spinner, args=(f"[i] Esperando ping de {self.box_ip}",))
        spinner_thread.start()

        while not self._is_host_alive():
            self.spinner_stop = True
            spinner_thread.join()
            
            self._manage_vpn()

            self.spinner_stop = False
            spinner_thread = Thread(target=self._spinner, args=(f"[i] Reintentando ping tras conectar VPN",))
            spinner_thread.start()
            time.sleep(1)

        self.spinner_stop = True
        spinner_thread.join()
        print(f"{C.OK}[+] ¡Ping recibido! El objetivo está activo.{C.END}")

        try:
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if "inet " in line:
                    self.tun0_ip = line.strip().split()[1].split('/')[0]
                    print(f"{C.OK}[+] tun0 conectada con IP: {C.CYAN}{self.tun0_ip}{C.END}")
                    return
        except (FileNotFoundError, subprocess.CalledProcessError):
            print(f"{C.WARN}[!] No se pudo encontrar la IP de tun0, pero el host responde.{C.END}")

    def _update_hosts(self):
        """Adds entries to /etc/hosts robustly."""
        print(f"{C.INFO}[i] Actualizando /etc/hosts (requiere sudo)...{C.END}")
        
        entries = [f"{self.box_ip} {self.box_name}.htb"]
        if self.domain:
            entries.append(f"{self.box_ip} {self.box_name}.{self.domain}")
            entries.append(f"{self.box_ip} {self.domain}")

        hosts_data = "\n".join(entries) + "\n"
        
        print(f"{C.INFO}[i] Intentando añadir las siguientes entradas a /etc/hosts:{C.END}")
        for entry in entries:
            print(f"{C.CYAN}    {entry}{C.END}")

        try:
            proc = subprocess.run(
                ['sudo', 'tee', '-a', '/etc/hosts'],
                input=hosts_data, text=True, capture_output=True
            )
            if proc.returncode != 0:
                print(f"{C.FAIL}[-] Error al actualizar /etc/hosts.{C.END}")
                print(f"{C.FAIL}    Stderr: {proc.stderr.strip()}{C.END}")
                if input(f"{C.WARN}[?] ¿Continuar sin actualizar /etc/hosts? (s/n): {C.END}").lower() != 's':
                    sys.exit(1)
            else:
                print(f"{C.OK}[+] /etc/hosts actualizado correctamente.{C.END}")
        except FileNotFoundError:
            print(f"{C.FAIL}[-] Comando 'sudo' o 'tee' no encontrado.{C.END}")
            sys.exit(1)

    def _create_dirs(self):
        print(f"{C.INFO}[i] Creando estructura de directorios en {self.box_path}...{C.END}")
        try:
            os.makedirs(os.path.join(self.box_path, "nmap"), exist_ok=True)
            os.makedirs(os.path.join(self.box_path, "web"), exist_ok=True)
            os.makedirs(os.path.join(self.box_path, "exploits"), exist_ok=True)
            os.makedirs(os.path.join(self.box_path, "loot"), exist_ok=True)
            print(f"{C.OK}[+] Directorios creados.{C.END}")
        except Exception as e:
            print(f"{C.FAIL}[-] Error creando directorios: {e}{C.END}")
            sys.exit(1)

    def _preliminary_scan(self):
        print(f"{C.INFO}[i] Lanzando escaneo preliminar de puertos...{C.END}")
        cmd = CONFIG["TOOLS"]["nmap"].format(TARGET_IP=self.box_ip, OUTPUT_DIR=self.box_path, SCAN_TYPE="prelim")
        cmd += " --top-ports 20 -T4"
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            open_ports = []
            for line in result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    open_ports.append(int(line.split('/')[0]))
            print(f"{C.OK}[+] Puertos abiertos detectados: {open_ports}{C.END}")
            return open_ports
        except Exception as e:
            print(f"{C.FAIL}[-] Escaneo preliminar falló: {e}{C.END}")
            return []
            
    def _run_in_tmux(self, session, pane_map):
        print(f"{C.INFO}[i] Configurando sesión de tmux '{session}'...{C.END}")
        os.chdir(self.box_path)
        
        subprocess.run(['tmux', 'new-session', '-d', '-s', session, '-n', next(iter(pane_map))], check=True)

        is_first_window = True
        for window, panes in pane_map.items():
            if not is_first_window:
                subprocess.run(['tmux', 'new-window', '-t', session, '-n', window], check=True)
            
            layout = "tiled"
            if len(panes) == 2: layout = "main-horizontal"

            for i, command in enumerate(panes):
                if i > 0:
                    subprocess.run(['tmux', 'split-window', '-h' if layout == "main-horizontal" else "-v", '-t', f'{session}:{window}'], check=True)
                
                formatted_cmd = command.format(
                    TARGET_IP=self.box_ip, BOX_NAME=self.box_name, OUTPUT_DIR=self.box_path,
                    WORDLIST=CONFIG["WORDLISTS"].get(command.split()[0], "")
                )
                
                target_pane = f"{session}:{window}.{i}"
                subprocess.run(['tmux', 'send-keys', '-t', target_pane, formatted_cmd, 'C-m'], check=True)
            
            subprocess.run(['tmux', 'select-layout', '-t', f'{session}:{window}', layout], check=True)
            is_first_window = False

        if CONFIG["USE_I3_FULLSCREEN"]:
            os.system(CONFIG["I3_FULLSCREEN_CMD"])

        print(f"{C.OK}[+] Sesión de tmux creada. ¡A hackear!{C.END}")
        subprocess.run([CONFIG["SHELL"], "-c", f"tmux attach-session -t {session}"])

    def start(self):
        self._ensure_connectivity()
        self._update_hosts()
        self._create_dirs()
        
        open_ports = self._preliminary_scan()

        tmux_panes = {
            "Recon": [
                CONFIG["TOOLS"]["nmap"].format(TARGET_IP=self.box_ip, OUTPUT_DIR=self.box_path, SCAN_TYPE="tcp_full") + " -p- --open",
                CONFIG["TOOLS"]["nmap"].format(TARGET_IP=self.box_ip, OUTPUT_DIR=self.box_path, SCAN_TYPE="udp_top") + " -sU --top-ports 20"
            ]
        }
        
        if 80 in open_ports or 443 in open_ports:
            print(f"{C.INFO}[i] Puertos web detectados. Añadiendo ventanas de fuzzing.{C.END}")
            tmux_panes["WebFuzz"] = [
                CONFIG["TOOLS"]["ffuf_vhost"].format(WORDLIST=CONFIG["WORDLISTS"]["vhost"], BOX_NAME=self.box_name, TARGET_IP=self.box_ip),
                CONFIG["TOOLS"]["ffuf_dir"].format(WORDLIST=CONFIG["WORDLISTS"]["dir_fuzz"], TARGET_IP=self.box_ip)
            ]
        
        if self.domain:
            print(f"{C.INFO}[i] Máquina de Directorio Activo detectada. Añadiendo ventanas de AD.{C.END}")
            tmux_panes["AD-Enum"] = [
                f"echo 'enum4linux-ng -A -d {self.domain} {self.box_ip}'",
                f"echo 'kerbrute userenum --dc {self.domain} -d {self.domain} /usr/share/seclists/Usernames/names.txt'"
            ]

        self._run_in_tmux(self.box_name, tmux_panes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Asistente de inicio para máquinas de Hack The Box by Neenah.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("name", nargs='?', default=None, help="Nombre de la máquina (ej. Lame).")
    parser.add_argument("ip", nargs='?', default=None, help="Dirección IP de la máquina.")
    parser.add_argument("--domain", help="Dominio si es un DC (ej. 'lame.htb').", default=None)
    args = parser.parse_args()

    if args.name and args.ip:
        setup = HtbSetup(args.name, args.ip, args.domain)
    else:
        print(f"{C.INFO}[i] Modo interactivo iniciado.{C.END}")
        try:
            name = input(f"{C.CYAN}[?] Introduce el nombre de la máquina: {C.END}")
            ip = input(f"{C.CYAN}[?] Introduce la IP de la máquina: {C.END}")
            domain = input(f"{C.CYAN}[?] Introduce el dominio (opcional, pulsa Enter para omitir): {C.END}")
            
            if not name or not ip:
                print(f"{C.FAIL}[-] El nombre y la IP son obligatorios.{C.END}")
                sys.exit(1)

            setup = HtbSetup(name, ip, domain if domain else None)
        except KeyboardInterrupt:
            print(f"\n{C.WARN}[!] Operación cancelada por el usuario.{C.END}")
            sys.exit(0)

    setup.start()
