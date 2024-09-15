# netpwn3
NetPwn3 - Herramienta de Pentesting para Redes


A continuación te proporciono la documentación de la herramienta **NetPwn3**

### README.md

```markdown
# NetPwn3 - Herramienta de Pentesting para Redes

NetPwn3 es una herramienta de pentesting para redes, diseñada para automatizar diversas tareas relacionadas con la seguridad de red. Ofrece escaneos de red, captura de paquetes, pruebas de conectividad, ataques DoS, escaneo de puertos y ataques de fuerza bruta. Además, incluye automatización de ataques MITM y la capacidad de ejecutar un flujo completo de ataques en un solo comando.

## Características

- Escaneo de red utilizando `arping2` y `Scapy`.
- Captura de paquetes con `tcpdump`.
- Pruebas de conectividad con `hping3`.
- Envío de solicitudes HTTP y comunicación con sockets.
- Cifrado y descifrado de mensajes utilizando `Fernet` (Cryptography).
- Automatización de ataques DoS.
- Automatización de escaneo de puertos con `nmap`.
- Ataques de fuerza bruta con `hydra` a servicios de autenticación.
- Ataques MITM (Man-in-the-Middle) con `arpspoof`.
- Flujo completo de ataques (escaneo de red, escaneo de puertos, MITM, DoS, fuerza bruta).

## Instalación

Para ejecutar **NetPwn3**, necesitarás instalar las dependencias necesarias. Asegúrate de tener Python 3 instalado en tu sistema.

1. Clona el repositorio:

    ```bash
    git clone https://github.com/espinozan/netpwn3.git
    cd netpwn3
    ```

2. Instala las dependencias requeridas:

    ```bash
    pip install -r requirements.txt
    ```

3. Asegúrate de tener instaladas las siguientes herramientas en tu sistema:

    - `arping2`
    - `tcpdump`
    - `hping3`
    - `nmap`
    - `hydra`
    - `arpspoof` (parte de `dsniff`)

## Uso

**NetPwn3** puede ejecutarse desde la línea de comandos. Aquí algunos ejemplos de cómo usar las funcionalidades más comunes.

### Escaneo de red

Escanea la red local utilizando `arping2`:

```bash
python netpwn3.py --scan-arping --ip-range 192.168.1.0/24
```

Escanea la red local utilizando `Scapy`:

```bash
python netpwn3.py --scan-scapy --ip-range 192.168.1.0/24
```

### Captura de paquetes

Captura paquetes en una interfaz de red:

```bash
python netpwn3.py --capture-tcpdump --interface eth0
```

### Prueba de conectividad

Prueba la conectividad con un host utilizando `hping3`:

```bash
python netpwn3.py --test-hping3 --ip-range 192.168.1.100
```

### Automatización de ataques

#### Ataque DoS

Ejecuta un ataque de denegación de servicio (DoS) contra un host:

```bash
python netpwn3.py --automate-dos 192.168.1.100
```

#### Escaneo de puertos

Automatiza un escaneo de puertos utilizando `nmap`:

```bash
python netpwn3.py --automate-portscan 192.168.1.100
```

#### Fuerza Bruta

Realiza un ataque de fuerza bruta a un servicio de autenticación (ej. SSH):

```bash
python netpwn3.py --automate-bruteforce 192.168.1.100,ssh,root,/path/to/wordlist.txt
```

#### Ataque MITM

Realiza un ataque MITM entre un dispositivo de la red y el gateway:

```bash
python netpwn3.py --automate-mitm 192.168.1.100,192.168.1.1 --interface eth0
```

#### Flujo completo de ataques

Ejecuta un flujo completo de ataques automatizados:

```bash
python netpwn3.py --full-attack --ip-range 192.168.1.0/24 --interface eth0
```

## Comandos Disponibles

```bash
$ python netpwn3.py --help

NetPwn3 - Herramienta de Pentesting para Redes
---------------------------------------------
Usage: netpwn3.py [OPTIONS]

Herramienta de pentesting para escaneo de red, captura de paquetes, pruebas de conectividad, ataques DoS, escaneo de puertos, y ataques de fuerza bruta.

Options:
  --ip-range TEXT         Rango de IP para escanear (ej. 192.168.1.0/24).
  --device INTEGER        Dispositivo a desencriptar (1, 2, ...).
  --interface TEXT        Interfaz de red para capturar paquetes (ej. eth0).
  --scan-arping           Escanear la red local utilizando `arping2`.
  --scan-scapy            Escanear la red local utilizando `Scapy`.
  --capture-tcpdump       Capturar paquetes de red usando `tcpdump`.
  --test-hping3           Probar la conectividad de un host con `hping3`.
  --http-request TEXT     Realizar una petición HTTP a un servidor.
  --socket-comm TEXT      Comunicación con sockets, enviar datos a un host.
  --encrypt TEXT          Cifrar un mensaje usando `Fernet`.
  --decrypt TEXT          Descifrar un mensaje cifrado con `Fernet`.

  --automate-dos TEXT     Automatizar un ataque DoS (Denegación de Servicio) usando `hping3`.
  --automate-portscan TEXT
                         Automatizar un escaneo de puertos de un objetivo (e.g., `nmap`).
  --automate-bruteforce TEXT
                         Realizar un ataque de fuerza bruta a un servicio objetivo (SSH, FTP, etc.).
  --automate-mitm TEXT    Ejecutar un ataque MITM (Man-in-the-Middle) sobre un dispositivo en la red.
  --full-attack           Ejecutar un flujo completo de ataques automatizados (escaneo + prueba de puertos + MITM + DoS).
  --help                  Mostrar este mensaje y salir.
```

## Dependencias

Las siguientes librerías y herramientas son requeridas:

- `scapy`
- `cryptography`
- `pandas`
- `click`
- `tcpdump`
- `arping2`
- `hping3`
- `nmap`
- `hydra`
- `arpspoof` (parte de `dsniff`)

Instala las dependencias de Python con:

```bash
pip install -r requirements.txt
```

## Contribuir

Si deseas contribuir a **NetPwn3**, sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una rama con una nueva funcionalidad (`git checkout -b feature/nueva-funcionalidad`).
3. Realiza tus cambios y haz commit (`git commit -m "Añadida nueva funcionalidad"`).
4. Sube tus cambios (`git push origin feature/nueva-funcionalidad`).
5. Crea un pull request.

## Licencia

Este proyecto está licenciado bajo la [MIT License](LICENSE).
