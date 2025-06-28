<div align="center">

```
  _  _   ___   _____
 | || | / _ \ |_   _|
 | || || | | |  | |
 |__   _| |_| |  | |
    |_|  \___/   |_|
```

### Hacking Operations Toolkit
**v1.1 (Speedrun Edition)**

</div>

<div align="center">

![Version](https://img.shields.io/badge/Version-v1.1-blue.svg?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-lightgrey.svg?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg?style=for-the-badge)

</div>

> Un kit de herramientas de shell optimizado para la ejecución rápida en operaciones de pentesting, con un fuerte enfoque en Linux y Active Directory.

---

### 📜 Descripción

El objetivo de este toolkit es minimizar el tiempo de tipeo y maximizar el tiempo dedicado al análisis y la explotación. El arsenal es modular, lo que permite añadir o quitar herramientas fácilmente, y está diseñado para ser cargado automáticamente al iniciar una nueva sesión de terminal en Kali Linux.

---

### ✨ Características Clave

-   **🚀 Optimizado para Velocidad:** Alias cortos y mnemotécnicos para las operaciones más frecuentes.
-   **🎯 Enfoque en Active Directory:** Atajos para las herramientas más importantes (`Impacket`, `NetExec`, `Certipy`, `BloodHound`).
-   **🧩 Modular y Organizado:** Herramientas agrupadas por función para un fácil mantenimiento.
-   **🔧 Flexible:** Funciones que aceptan argumentos para adaptarse a diferentes escenarios.
-   **⚙️ Fácil de Instalar:** Configuración rápida con un solo comando.

---

### 🧰 Contenido del Toolkit

El toolkit se divide en los siguientes módulos principales:

| Módulo             | Descripción                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| **Reconocimiento** | Escaneo de puertos, enumeración de servicios, fuzzing de directorios.    |
| **Active Directory** | Enumeración, explotación y movimiento lateral en entornos de AD.         |
| **Pivoting**       | Creación de túneles y proxies inversos con `chisel`.                     |
| **Utilidades**     | Servidores web, transferencia de archivos y otras tareas comunes.        |

---

### ⚡ Instalación y Configuración

Diseñado y probado para **Kali Linux**.

#### Requisitos Previos
```bash
# Actualizar e instalar herramientas base
sudo apt update && sudo apt install -y git zsh python3-pip xclip neo4j
```

#### Paso 1: Clonar el Repositorio
```bash
# Clona el repositorio en una ubicación permanente
git clone https://github.com/iNeenah/Hacking-Set-Up.git ~/hacking-toolkit
cd ~/hacking-toolkit
```

#### Paso 2: Instalar Dependencias de Python
```bash
# Instala las librerías de Python necesarias
python3 -m pip install --user -r requirements.txt
```

#### Paso 3: Configurar el Entorno
```bash
# Añade la ruta de tu binario de Chisel a tu .zshrc (o .bashrc)
# (Descarga Chisel desde su GitHub si no lo tienes)
echo 'export CHISEL_PATH="~/tools/chisel"' >> ~/.zshrc

# Añade el cargador del toolkit a tu .zshrc
echo -e "
# Cargar Hacking Operations Toolkit
source ~/hacking-toolkit/neenah_ad_toolkit.sh" >> ~/.zshrc

# Aplica los cambios inmediatamente
source ~/.zshrc
```
¡Listo! Tu terminal ahora está equipada con el arsenal completo.

---

### 🛠️ Guía de Uso Táctico

#### Módulo de Reconocimiento
```bash
# Escaneo rápido de puertos comunes de AD en un objetivo
scan-ad 10.10.11.150

# Fuzzing de directorios en un servidor web
fuzz http://10.10.11.150/FUZZ
```

#### Módulo de Active Directory
```bash
# Buscar usuarios vulnerables a AS-REP Roasting
asrep 10.10.11.150 mydomain.local

# Obtener una shell interactiva con credenciales
ewinrm 10.10.11.150 'svc_user' 'P@ssw0rd123!'

# Encontrar plantillas de certificados vulnerables
cp-find 'mydomain.local/svc_user:P@ssw0rd123!' -dc-ip 10.10.11.150
```

---

### 🎨 Personalización

Adapta el toolkit a tu gusto:
-   **Añadir nuevos alias:** Edita `neenah_ad_toolkit.sh` y añade tus propias funciones.
-   **Cambiar alias existentes:** Modifica los alias en el archivo de configuración.
-   **Añadir nuevas herramientas:** Coloca nuevas herramientas en la carpeta `Tools` y crea un alias.

---

### 🤔 Solución de Problemas

-   **"Comando no encontrado":** Asegúrate de haber reiniciado la terminal después de la instalación o de haber ejecutado `source ~/.zshrc`.
-   **"Permiso denegado":** Otorga permisos de ejecución a los scripts (`chmod +x *.sh`).

---

### 🤝 Contribuciones

Este es un proyecto personal, pero las sugerencias y pull requests para mejorar las herramientas son siempre bienvenidas.

---

### 🙏 Agradecimientos

Este toolkit se apoya en el trabajo de gigantes de la comunidad de seguridad:
-   **Impacket**
-   **NetExec**
-   **Certipy**
-   **BloodHound**
-   **Chisel**

---

### 📄 Licencia

Este proyecto está bajo la **Licencia MIT**. Ver el archivo `LICENSE` para más detalles.

---

### ⚠️ Advertencia Ética

Este toolkit está diseñado con fines **educativos y para su uso en entornos de hacking ético autorizados** (CTFs, laboratorios personales, auditorías con consentimiento explícito). El uso de estas herramientas en sistemas sin permiso es ilegal y no está respaldado por este proyecto. **Opera con profesionalismo y responsabilidad.**
