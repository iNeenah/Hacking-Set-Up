# 🧰 Arsenal de Neenah v7.0 (Speedrun Edition)

```
  _   _  ______ ______  _   _   __  __ 
 | \ | ||  ____||  ____|| \ | | |  \/  |
 |  \| || |__   | |__   |  \| | | \  / |
 | . ` ||  __|  |  __|  | . ` | | |\/| |
 | |\  || |____ | |____ | |\  | | |  | |
 |_| \_||______||______||_| \_| |_|  |_|
```
*// Un toolkit de shell optimizado para la ejecución rápida en operaciones de pentesting, con un fuerte enfoque en Linux y Active Directory.*

---

## 📜 Descripción

Este repositorio es mi arsenal personal y centralizado de alias y funciones de shell (`bash`/`zsh`). Está diseñado para acelerar drásticamente las tareas repetitivas en entornos de CTF y laboratorios (Hack The Box, TryHackMe, etc.). El objetivo es simple: menos tipeo, más hacking.

---

## ⚡ Instalación y Configuración (Kali Linux)

Este kit está diseñado y probado para **Kali Linux**. Para usarlo en otras distribuciones, puede que necesites instalar dependencias adicionales.

### Paso 1: Clonar el Repositorio
Clona este repositorio en una ubicación fácil de recordar, como tu directorio de inicio.
```bash
git clone [https://github.com/iNeenah/Hacking-Set-Up.git](https://github.com/iNeenah/Hacking-Set-Up.git) ~/hacking-toolkit
```

### Paso 2: Instalar Dependencias
El arsenal depende de varias herramientas clave. La mayoría ya vienen en Kali, pero nos aseguramos de tener todo.
```bash
# Actualiza e instala herramientas del sistema
sudo apt update && sudo apt install -y zsh git xclip python3-pip neo4j

# Instala herramientas de Python
# (Se recomienda hacerlo dentro de un entorno virtual de Python)
python3 -m pip install --user -r requirements.txt 
# Nota: Deberás crear un archivo 'requirements.txt' con el contenido:
# impacket, bloodhound, certipy-ad, netexec, coercer
```

### Paso 3: Cargar en la Shell
Añade el script principal a la configuración de tu shell para que se cargue automáticamente cada vez que abres una nueva terminal.

```bash
# Este comando añade la línea 'source...' a tu archivo .zshrc
echo -e "\n# Cargar Arsenal de Neenah\nsource ~/hacking-toolkit/neenah_ad_toolkit.sh" >> ~/.zshrc

# Aplica los cambios inmediatamente
source ~/.zshrc
```
¡Listo! Tu terminal ahora está sobrecargada.

---

## 🛠️ Guía de Uso del Arsenal

### ➤ Utilidades Generales

#### `serve <puerto>`
Inicia un servidor web Python3 en el directorio actual. Útil para servir exploits o exfiltrar archivos.
```bash
┌──(neenah㉿kali)-[~/www]
└─$ serve 8000
[+] Sirviendo en [http://0.0.0.0:8000](http://0.0.0.0:8000) ...
Serving HTTP on 0.0.0.0 port 8000 ([http://0.0.0.0:8000/](http://0.0.0.0:8000/)) ...
```

#### `listen <puerto>`
Inicia un listener de `nc` para recibir reverse shells.
```bash
┌──(neenah㉿kali)-[~]
└─$ listen 4444
[+] Escuchando en puerto 4444...
listening on [any] 4444 ...
```

#### `tunip`
Copia la IP de tu interfaz `tun0` (VPN de HTB) directamente a tu portapapeles.
```bash
┌──(neenah㉿kali)-[~]
└─$ tunip
[+] IP de tun0 [10.10.14.49] copiada.
```

### ➤ Reconocimiento

#### `scan-ad <IP>`
Lanza un escaneo `nmap` optimizado para los puertos más comunes de Active Directory.
```bash
┌──(neenah㉿kali)-[~]
└─$ scan-ad 10.10.11.100
[+] Escaneando AD en 10.10.11.100...
Starting Nmap...
...
[+] Escaneo de AD guardado en 10.10.11.100/nmap/ad_scan.nmap
```

### ➤ Active Directory: Enumeración y Ataques

#### `kb-users <IP_DC> <dominio> <lista>`
Enumera usuarios de forma segura usando Kerbrute.
```bash
┌──(neenah㉿kali)-[~]
└─$ kb-users 10.10.11.100 sorcery.htb users.txt
...
2025/06/23 03:13:37 [+] VALID USERNAME:	 tom_summers@sorcery.htb
...
```

#### `asrep-roast <IP_DC> <dominio>`
Busca usuarios vulnerables a AS-REP Roasting.
```bash
┌──(neenah㉿kali)-[~]
└─$ asrep 10.10.11.100 sorcery.htb
Impacket v0.12.0 ...
$krb5asrep$23$svc_user@sorcery.htb:d1a2...
[+] Hashes para crackear guardados en asrep_hashes.txt
```

#### `ewinrm <IP> <user> '<pass>'`
Inicia una shell interactiva de PowerShell con Evil-WinRM.
```bash
┌──(neenah㉿kali)-[~]
└─$ ewinrm 10.10.11.150 tom_summers 'P@ssw0rd123!'
...
*Evil-WinRM* PS C:\Users\tom_summers\Documents>
```

### ➤ BloodHound

#### `bh <start|stop>`
Inicia o detiene los servicios de BloodHound (base de datos Neo4j y la GUI).
```bash
┌──(neenah㉿kali)-[~]
└─$ bh start
...
[+] Iniciando Neo4j y BloodHound GUI...
```

#### `bh-collect <user> '<pass>' <IP_DC> <dominio>`
Lanza el colector para mapear el dominio.
```bash
┌──(neenah㉿kali)-[~]
└─$ bh-collect tom_summers 'P@ssw0rd123!' 10.10.11.100 sorcery.htb
[+] Colección de BloodHound completada. Importa los archivos .json a la GUI.
```

---

## ⚠️ Advertencia Ética

Este toolkit está diseñado con fines **educativos y para su uso en entornos de hacking ético autorizados** (CTFs, laboratorios personales, auditorías con consentimiento explícito). El uso de estas herramientas en sistemas sin permiso es ilegal. Opera con profesionalismo y responsabilidad.