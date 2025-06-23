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
# HTB Operations Starter v2.0 - Optimizado por Neenah
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
    "HTB_PATH": "/htb",
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
    def __init__(self, box_name, box_ip):
        if not box_name or not box_ip:
            print(f"{C.FAIL}[-] Nombre de la máquina e IP son requeridos.{C.END}")
            sys.exit(1)
        
        self.box_name = box_name
        self.box_ip = box_ip
        self.box_path = os.path.join(CONFIG["HTB_PATH"], box_name)
        self.tun0_ip = self._check_tun0()
        self.spinner_stop = False

    def _check_tun0(self):
        print(f"{C.INFO}[i] Verificando interfaz tun0...{C.END}")
        try:
            result = subprocess.run(['ip', 'addr', 'show', 'tun0'], capture_output=True, text=True)
            if result.returncode != 0:
                print(f"{C.FAIL}[-] tun0 no encontrada. ¿Estás conectado a la VPN de HTB?{C.END}")
                sys.exit(1)
            for line in result.stdout.splitlines():
                if "inet " in line:
                    ip = line.strip().split()[1].split('/')[0]
                    print(f"{C.OK}[+] tun0 conectada con IP: {C.CYAN}{ip}{C.END}")
                    return ip
        except FileNotFoundError:
            print(f"{C.FAIL}[-] Comando 'ip' no encontrado. Asegúrate de estar en Linux.{C.END}")
            sys.exit(1)
        print(f"{C.FAIL}[-] tun0 encontrada pero sin IP asignada.{C.END}")
        sys.exit(1)

    def _create_dirs(self):
        print(f"{C.INFO}[i] Creando estructura de directorios en {self.box_path}...{C.END}")
        try:
            os.makedirs(os.path.join(self.box_path, "nmap"), exist_ok=True)
            os.makedirs(os.path.join(self.box_path, "web"), exist_ok=True)
            os.makedirs(os.path.join(self.box_path, "exploits"), exist_ok=True)
            print(f"{C.OK}[+] Directorios creados.{C.END}")
        except Exception as e:
            print(f"{C.FAIL}[-] Error creando directorios: {e}{C.END}")
            sys.exit(1)

    def _spinner(self):
        for char in cycle(['|', '/', '-', '\\']):
            if self.spinner_stop:
                break
            sys.stdout.write(f'\r{C.INFO}[i] Esperando ping de {self.box_ip} {char}{C.END}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * 50 + '\r') # Clean up line

    def _ping_host(self):
        spinner_thread = Thread(target=self._spinner)
        spinner_thread.start()
        
        while True:
            try:
                result = subprocess.run(['ping', '-c', '1', '-W', '1', self.box_ip], capture_output=True)
                if result.returncode == 0:
                    self.spinner_stop = True
                    spinner_thread.join()
                    print(f"{C.OK}[+] ¡Ping recibido! El objetivo está activo.{C.END}")
                    return True
            except Exception as e:
                self.spinner_stop = True
                spinner_thread.join()
                print(f"{C.FAIL}[-] Error durante el ping: {e}{C.END}")
                return False
            time.sleep(1)

    def _preliminary_scan(self):
        print(f"{C.INFO}[i] Lanzando escaneo preliminar de puertos para decidir estrategia...{C.END}")
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
        
        # Create session and first window
        first_window = next(iter(pane_map))
        subprocess.run(['tmux', 'new-session', '-d', '-s', session, '-n', first_window], check=True)

        is_first_window = True
        for window, panes in pane_map.items():
            if not is_first_window:
                subprocess.run(['tmux', 'new-window', '-t', session, '-n', window], check=True)
            
            layout = "tiled" # Default layout
            if len(panes) == 2: layout = "main-horizontal"
            if len(panes) > 2: layout = "tiled"

            for i, command in enumerate(panes):
                if i > 0:
                    subprocess.run(['tmux', 'split-window', '-h' if layout == "main-horizontal" else "-v", '-t', f'{session}:{window}'], check=True)
                
                # Format command with context
                formatted_cmd = command.format(
                    TARGET_IP=self.box_ip,
                    BOX_NAME=self.box_name,
                    OUTPUT_DIR=self.box_path,
                    WORDLIST=CONFIG["WORDLISTS"].get(command.split()[0], "") # Basic dynamic wordlist
                )
                
                # Send keys to the newly created pane
                target_pane = f"{session}:{window}.{i}"
                subprocess.run(['tmux', 'send-keys', '-t', target_pane, formatted_cmd, 'C-m'], check=True)
            
            subprocess.run(['tmux', 'select-layout', '-t', f'{session}:{window}', layout], check=True)
            is_first_window = False

        if CONFIG["USE_I3_FULLSCREEN"]:
            os.system(CONFIG["I3_FULLSCREEN_CMD"])

        print(f"{C.OK}[+] Sesión de tmux creada. ¡A hackear!{C.END}")
        subprocess.run(['tmux', 'attach-session', '-t', session])

    def start(self):
        self._create_dirs()
        self._ping_host()
        
        # Update /etc/hosts
        host_entry = f"{self.box_ip} {self.box_name}.htb"
        print(f"{C.INFO}[i] Añadiendo '{host_entry}' a /etc/hosts (requiere sudo)...{C.END}")
        os.system(f"echo '{host_entry}' | sudo tee -a /etc/hosts")

        open_ports = self._preliminary_scan()

        # Build dynamic tmux panes
        tmux_panes = {
            "Recon": [
                CONFIG["TOOLS"]["nmap"].format(TARGET_IP=self.box_ip, OUTPUT_DIR=self.box_path, SCAN_TYPE="tcp_full") + " -p-",
                CONFIG["TOOLS"]["nmap"].format(TARGET_IP=self.box_ip, OUTPUT_DIR=self.box_path, SCAN_TYPE="udp_top") + " -sU --top-ports 20"
            ]
        }
        
        if 80 in open_ports or 443 in open_ports:
            print(f"{C.INFO}[i] Puertos web detectados. Añadiendo ventanas de fuzzing.{C.END}")
            tmux_panes["WebFuzz"] = [
                CONFIG["TOOLS"]["ffuf_vhost"].format(WORDLIST=CONFIG["WORDLISTS"]["vhost"], BOX_NAME=self.box_name, TARGET_IP=self.box_ip),
                CONFIG["TOOLS"]["ffuf_dir"].format(WORDLIST=CONFIG["WORDLISTS"]["dir_fuzz"], TARGET_IP=self.box_ip)
            ]

        self._run_in_tmux(self.box_name, tmux_panes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script de inicio rápido para máquinas de Hack The Box by Neenah.")
    parser.add_argument("name", help="Nombre de la máquina (ej. Lame).")
    parser.add_argument("ip", help="Dirección IP de la máquina.")
    args = parser.parse_args()
    
    setup = HtbSetup(args.name, args.ip)
    setup.start()