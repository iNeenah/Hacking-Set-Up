# 🧰 Neenah's Hacking Toolkit v1.0

*// Mi arsenal personal de alias y funciones para operadores. Optimizado para velocidad y eficacia en entornos CTF y laboratorios de pentesting.*

---

## 🎯 Propósito

Este repositorio centraliza una colección de alias y funciones de shell (`bash`/`zsh`) diseñadas para automatizar y acelerar las tareas más comunes y repetitivas durante una auditoría de seguridad o la resolución de máquinas en plataformas como Hack The Box. El objetivo es minimizar el tipeo y maximizar el tiempo dedicado al análisis y la explotación.

---

## 🚀 Contenido del Arsenal

El script `neenah_aliases.sh` incluye, entre otras, las siguientes categorías de herramientas:

* **Utilidades Generales:** Servidores web rápidos (`serve`), listeners (`nc`), estabilización de TTY (`stabilize`) y manejo de IPs.
* **Reconocimiento y Fuzzing:** Wrappers optimizados para `nmap` (`scan`) y `ffuf` (`fuzz`) que automatizan la creación de directorios y el guardado de resultados.
* **Generación de Shells:** Un generador de reverse shells (`revshell`) para múltiples lenguajes (Bash, Python, PowerShell, etc.).
* **Escalada en Linux:** Comandos rápidos para encontrar vectores de escalada como binarios SUID/GUID (`findsuid`) y ejecutar scripts de enumeración como LinPEAS (`enumlinux`).
* **Active Directory:** Atajos para herramientas de Impacket y CrackMapExec para enumerar usuarios, realizar ataques de Kerberos y más.
* **Pivoting:** Una función unificada (`pivot`) para gestionar túneles y proxies SOCKS con `chisel`.

---

## ⚡ Instalación y Uso (WSL en Windows)

Este set-up está diseñado para ser usado dentro de un entorno de shell de Linux en Windows (WSL).

**Requisitos:**
* Una distribución de Linux en WSL (Kali, Ubuntu, etc.).
* `git` instalado.
* `zsh` (recomendado) o `bash`.

**Pasos de Instalación:**

1.  Clona este repositorio en tu directorio de inicio o donde prefieras.
    ```bash
    git clone [https://github.com/iNeenah/Hacking-Set-Up.git](https://github.com/iNeenah/Hacking-Set-Up.git) ~/neenah-toolkit
    ```

2.  Añade el script de alias a la configuración de tu shell para que se cargue automáticamente cada vez que abres una nueva terminal.
    ```bash
    # Si usas Zsh (por defecto en Kali)
    echo -e "\n# Cargar el arsenal de Neenah\nsource ~/neenah-toolkit/neenah_aliases.sh" >> ~/.zshrc

    # Si usas Bash
    # echo -e "\n# Cargar el arsenal de Neenah\nsource ~/neenah-toolkit/neenah_aliases.sh" >> ~/.bashrc
    ```

3.  Recarga la configuración de tu shell para aplicar los cambios inmediatamente.
    ```bash
    # Si usas Zsh
    source ~/.zshrc

    # Si usas Bash
    # source ~/.bashrc
    ```

¡Listo! Ahora todos los alias y funciones están disponibles globalmente en tu terminal.

---

## 💡 Ejemplos de Comandos

```bash
# Iniciar un servidor web en el puerto 8000
serve

# Escanear una IP con nmap y guardar los resultados en una carpeta
scan 10.10.10.10

# Obtener una reverse shell de bash para copiar y pegar
revshell bash 10.10.14.49 4444

# Estabilizar una shell básica
stabilize

# Iniciar un servidor chisel para pivoting
pivot server

# Enumerar un objetivo Linux de forma automática
enumlinux
```

---

## ⚠️ Advertencia

Estas herramientas están diseñadas para ser usadas exclusivamente en **entornos de hacking ético, laboratorios controlados y plataformas CTF autorizadas**. El uso de estas herramientas en sistemas sin el consentimiento explícito y por escrito del propietario es ilegal y no está respaldado por este proyecto.