# 🚀 Hacking Operations Toolkit by iNeenah

<div align="center">

![Version](https://img.shields.io/badge/Version-v3.1-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-lightgrey.svg?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg?style=for-the-badge)

</div>

> Un arsenal de herramientas y scripts optimizados para agilizar tus operaciones de pentesting en entornos Linux y Active Directory. Diseñado para minimizar el tecleo y maximizar la eficiencia, permitiéndote concentrarte en la lógica de explotación.

---

### ✨ Características Estelares

*   **Automatización Inteligente:** Inicia máquinas de Hack The Box con un solo comando, gestionando VPNs, `/etc/hosts` y creando tu entorno de trabajo en `tmux` de forma automática.
*   **Flujo de Trabajo Optimizado:** Alias y funciones preconfiguradas para las tareas más comunes de reconocimiento, enumeración, acceso y post-explotación.
*   **Especialización en Active Directory:** Un conjunto robusto de herramientas para la enumeración, explotación y movimiento lateral en entornos de AD, incluyendo integración con Impacket, NetExec, Certipy, BloodHound y ahora también Kerberos con gestión de TGTs y cracking de hashes.
*   **Soporte Integral para Linux:** Funcionalidades específicas para la enumeración y escalada de privilegios en sistemas Linux, con descripciones claras y ejemplos prácticos.
*   **Interactividad y Facilidad de Uso:** El script principal te guía paso a paso si no proporcionas argumentos, haciendo el proceso intuitivo para principiantes y rápido para expertos.
*   **Modular y Extensible:** Añade o modifica fácilmente tus propias herramientas y alias para adaptar el toolkit a tu estilo de trabajo.

---

### ⚡ Instalación y Configuración

Diseñado y probado para **Kali Linux**.

#### Requisitos Previos

Asegúrate de tener instaladas las herramientas básicas y las dependencias de Python. Algunas herramientas pueden requerir instalación manual o vía `apt`.

```bash
# Actualiza el sistema e instala herramientas esenciales
sudo apt update && sudo apt install -y git zsh python3-pip xclip neo4j openvpn tmux nmap ffuf responder kerbrute john hashcat
```

#### Paso 1: Clonar el Repositorio

Clona el repositorio en una ubicación permanente en tu sistema.

```bash
git clone https://github.com/iNeenah/Hacking-Set-Up.git ~/hacking-toolkit
cd ~/hacking-toolkit
```

#### Paso 2: Instalar Dependencias de Python

Instala las librerías de Python recomendadas para el entorno general.

```bash
pip install -r requirements.txt
```

#### Paso 3: Configurar el Entorno Zsh

Añade el alias principal y carga los scripts de funciones en tu `.zshrc`.

```bash
# Añade el alias 'htb-start' para el script principal
echo "alias htb-start='python3 ~/hacking-toolkit/Tools/Productividad/empezarMaquinaHTB.py'" >> ~/.zshrc

# Carga los scripts de alias y funciones
echo "source ~/hacking-toolkit/Tools/Productividad/aliases.zsh" >> ~/.zshrc
echo "source ~/hacking-toolkit/Tools/Productividad/aliasParaAd.zsh" >> ~/.zshrc
echo "source ~/hacking-toolkit/Tools/Productividad/aliasParaLinux.zsh" >> ~/.zshrc

# Recarga la configuración de Zsh para aplicar los cambios
source ~/.zshrc
```

¡Listo! Tu terminal ahora está equipada con el arsenal completo.

---

### 🛠️ Guía de Uso Táctico

Este toolkit te proporciona comandos cortos y potentes para acelerar tus operaciones.

#### 1. Inicio Rápido de Máquinas HTB (`htb-start`)

El comando estrella para empezar una máquina de Hack The Box.

*   **Modo Interactivo (Recomendado):**
    Simplemente ejecuta el comando y te guiará.
    ```bash
    htb-start
    ```
    Te pedirá: Nombre de la máquina, IP y Dominio (opcional). Si el ping falla, te ayudará a conectar la VPN.

*   **Modo con Argumentos:**
    ```bash
    htb-start <nombre_maquina> <ip_maquina> [--domain <dominio.htb>]
    ```
    **Ejemplos:**
    ```bash
    htb-start Lame 10.10.10.3
    htb-start Forest 10.10.10.161 --domain forest.htb
    ```

#### 2. Utilidades Generales (Navaja Suiza)

Comandos versátiles para tareas comunes.

*   **`serve [puerto]`**: Inicia un servidor web Python en el directorio actual (por defecto puerto 8000).
    ```bash
    serve 8080
    ```
*   **`listen [puerto]`**: Inicia un listener de Netcat (por defecto puerto 443).
    ```bash
    listen 9001
    ```
*   **`tunip [interfaz]`**: Copia la IP de `tun0` (o la interfaz especificada) al portapapeles.
    ```bash
    tunip
    tunip eth0
    ```
*   **`revshell <tipo> <ip> <puerto>`**: Genera y copia al portapapeles una reverse shell.
    Tipos: `bash`, `python`, `nc`, `powershell`.
    ```bash
    revshell bash 10.10.14.13 4444
    revshell powershell 10.10.14.13 80
    ```
*   **`stabilize`**: Copia el comando PTY para estabilizar una TTY y muestra los pasos.
    ```bash
    stabilize
    ```

#### 3. Reconocimiento y Fuzzing

*   **`scan <IP> [args_nmap]`**: Escaneo Nmap versátil que organiza los resultados.
    ```bash
    scan 10.10.10.10 -p- -sV
    ```
*   **`scan-ad <IP_DC> [args_nmap]`**: Escaneo Nmap enfocado en puertos de Active Directory.
    ```bash
    scan-ad 10.10.10.10
    ```
*   **`fuzz <URL_CON_FUZZ_O_HEADER> [args_ffuf]`**: Fuzzer web inteligente con `ffuf`. Detecta automáticamente si es vhost o directorio.
    ```bash
    fuzz http://10.10.10.10/FUZZ
    fuzz -H 'Host: FUZZ.domain.htb' http://10.10.10.10
    ```

#### 4. Active Directory: Enumeración y Ataques de Autenticación

*   **`timesync <IP_DC>`**: Sincroniza la hora de tu sistema con el controlador de dominio (DC). Crucial para Kerberos.
    ```bash
    timesync 10.10.11.76
    ```
*   **`kb-users <IP_DC> <dominio> <ruta_lista_usuarios>`**: Kerbrute para enumerar usuarios válidos en un dominio.
*   **`kb-spray <IP_DC> <dominio> <ruta_lista_usuarios> <contraseña_o_ruta_lista_contraseñas>`**: Kerbrute para realizar un ataque de password spraying.
*   **`asrep <IP_DC> <dominio.local>`**: Impacket para AS-REP Roasting (obtener hashes de usuarios sin preautenticación).
*   **`keroast <IP_DC> <dominio/usuario:contraseña>`**: Impacket para Kerberoasting (obtener hashes de SPNs).
*   **`get-tgt <IP_DC> <dominio>/<usuario>:<contraseña_o_hash> [opciones_adicionales_impacket]`**: Obtiene un Ticket Granting Ticket (TGT) para autenticación Kerberos. Soporta contraseña o hash (Pass-the-Hash).
    ```bash
    get-tgt 10.10.11.76 voleur.htb/svc_winrm:password
    get-tgt 10.10.11.76 voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2
    ```
*   **`set-krb5ccname <nombre_archivo_ccache>`**: Configura la variable de entorno `KRB5CCNAME` para usar el TGT generado. Permite que otras herramientas usen el ticket Kerberos.
    ```bash
    set-krb5ccname svc_winrm.ccache
    ```
*   **`crack-asrep <archivo_hashes> <ruta_wordlist>`**: John The Ripper para crackear hashes de AS-REP (modo 18200).
*   **`crack-keroast <archivo_hashes> <ruta_wordlist>`**: John The Ripper para crackear hashes de Kerberoast (modo 13100).
*   **`hcat-asrep <archivo_hashes> <ruta_wordlist>`**: Hashcat para crackear hashes de AS-REP (modo 18200).
*   **`hcat-keroast <archivo_hashes> <ruta_wordlist>`**: Hashcat para crackear hashes de Kerberoast (modo 13100).

#### 5. Active Directory: Movimiento Lateral y Acceso

*   **`nxc-ldap <IP_DC> -u <usuario> -p <contraseña> -d <dominio> [opciones_nxc]`**: Ejecuta comandos de enumeración LDAP usando NetExec (nxc).
*   **`nxc-smb <IP> -u <user> -p '<pass>' -d <dominio> [opciones_nxc]`**: NetExec SMB para enumeración general y ejecución de comandos.
*   **`b-dump <dominio> <usuario_admin> '<contraseña_admin>'`**: BloodyAD para dumpear toda la información del dominio.
*   **`b-adduser <dominio> <usuario_admin> '<contraseña_admin>' <nuevo_usuario> <nueva_contraseña>`**: BloodyAD para añadir un nuevo usuario al dominio.
*   **`ewinrm <IP> <usuario> '<contraseña>'`**: Evil-WinRM para iniciar una shell interactiva WinRM.
*   **`ewinrm-pth <IP> <usuario> <hash_NTLM>`**: Evil-WinRM para iniciar una shell interactiva WinRM usando Pass-the-Hash.
*   **`ewinrm-krb <IP> <usuario> <dominio>`**: Evil-WinRM para iniciar una shell interactiva WinRM usando autenticación Kerberos (con `KRB5CCNAME`).
    ```bash
    ewinrm-krb dc.voleur.htb svc_winrm VOLEUR.HTB
    ```
*   **`pth-wmi <hash_NTLM> <dominio/usuario@IP>`**: Impacket wmiexec.py para ejecutar comandos vía WMI usando Pass-the-Hash.

#### 6. Active Directory: Persistencia y Escalada de Privilegios

*   **`secdump <dominio/usuario:contraseña@IP>`**: SecretsDump (Impacket) para dumpear hashes SAM/LSA/NTDS.
*   **`dcsync <dominio/usuario:contraseña>`**: DCSync (Impacket) para dumpear hashes usando el privilegio DCSync.
*   **`b-give-dcsync <dominio> <usuario_admin> '<contraseña_admin>' <usuario_objetivo>`**: BloodyAD para otorgar el privilegio DCSync a un usuario.
*   **`b-give-genericall <dominio> <usuario_admin> '<contraseña_admin>' <usuario_objetivo>`**: BloodyAD para otorgar el permiso GenericAll sobre un objeto.

#### 7. BloodHound y AD CS (Certificate Services)

*   **`bh <start|stop>`**: Inicia/Para los servicios de BloodHound (Neo4j y BloodHound GUI).
*   **`bh-collect <usuario> '<contraseña>' <IP_DC> <dominio.local>`**: Colector de BloodHound (bloodhound-python).
*   **`cp-find <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC>`**: Certipy para encontrar plantillas de certificados vulnerables.
*   **`cp-req <dominio>/<usuario>:<contraseña> -dc-ip <IP_DC> -ca <nombre_ca> -template <plantilla>`**: Certipy para solicitar un certificado (ataque ESC1).
*   **`cp-auth <ruta_certificado.pfx>`**: Certipy para autenticar usando un certificado (Pass-the-Certificate).
*   **`cp-shadow <ruta_archivo_pfx> <usuario_a_comprometer>`**: Certipy para realizar un ataque de Shadow Credentials.

#### 8. Post-Explotación y Escalada (Linux)

*   **`enumlinux`**: Descarga y ejecuta LinPEAS en memoria para enumeración de Linux. Útil para identificar posibles vectores de escalada de privilegios.
*   **`findsuid`**: Busca binarios con permisos SUID y SGID en el sistema. Útil para encontrar programas que se ejecutan con privilegios elevados.
*   **`findcaps`**: Busca binarios con capabilities de Linux. Útil para identificar programas con permisos especiales que pueden ser explotados.

#### 9. Pivoting y Movimiento Lateral

*   **`pivot <server|client> [ip_servidor] [puerto]`**: Gestor de túneles Chisel.
    ```bash
    # Iniciar servidor Chisel en tu máquina
    pivot server 8888
    # Generar comando de cliente para la víctima
    pivot client 10.10.14.13 8888
    ```

---

### 🎨 Personalización

Adapta el toolkit a tu gusto:

*   **Añadir nuevos alias/funciones:** Edita los archivos `.zsh` en `Tools/Productividad` para añadir tus propias funciones y alias.
*   **Cambiar alias existentes:** Modifica los alias directamente en los archivos de configuración.
*   **Añadir nuevas herramientas:** Coloca nuevas herramientas en la carpeta `Tools` y crea un alias o función para ellas.
*   **Configuración de `htb-start`:** Ajusta las rutas de `HTB_PATH` y `VPN_PATH` en el script `empezarMaquinaHTB.py` si tus directorios son diferentes.

---

### 🤔 Solución de Problemas

*   **"Comando no encontrado":** Asegúrate de haber recargado la terminal (`source ~/.zshrc`) o de haber abierto una nueva después de la instalación. Verifica que las rutas en tu `.zshrc` sean correctas.
*   **"Permiso denegado":** Otorga permisos de ejecución a los scripts (`chmod +x *.sh`) si es necesario. Para operaciones que requieren `sudo`, asegúrate de tener los permisos adecuados.
*   **Problemas con VPN:** Verifica que tus archivos `.ovpn` estén en la ruta configurada en `empezarMaquinaHTB.py` (`~/vpns` por defecto) y que OpenVPN esté instalado.
*   **Problemas con Kerberos:** Asegúrate de que el archivo `/etc/krb5.conf` esté configurado correctamente para el dominio objetivo. Consulta la sección de notas importantes en `aliasParaAd.zsh` para un ejemplo.

---

### 🤝 Contribuciones

Este es un proyecto personal, pero las sugerencias, mejoras y pull requests son siempre bienvenidas. ¡Juntos podemos hacerlo aún mejor!

---

### 🙏 Agradecimientos

Este toolkit se apoya en el trabajo de gigantes de la comunidad de seguridad, incluyendo:

*   **Impacket**
*   **NetExec**
*   **Certipy**
*   **BloodHound**
*   **Chisel**
*   **OpenVPN**
*   **Tmux**
*   **Nmap**
*   **FFUF**
*   **LinPEAS**
*   **Kerbrute**
*   **Evil-WinRM**
*   **BloodyAD**
*   **John the Ripper**
*   **Hashcat**
*   **Responder**

---

### 📄 Licencia

Este proyecto está bajo la **Licencia MIT**. Ver el archivo `LICENSE` para más detalles.

---

### ⚠️ Advertencia Ética

Este toolkit está diseñado con fines **educativos y para su uso exclusivo en entornos de hacking ético autorizados** (CTFs, laboratorios personales, auditorías con consentimiento explícito). El uso de estas herramientas en sistemas sin permiso es ilegal y no está respaldado por este proyecto. **Opera siempre con profesionalismo, responsabilidad y dentro de los límites de la ley.**
