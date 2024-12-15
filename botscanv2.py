import nmap
import random
import time
from datetime import datetime, timedelta

# Generar IP públicas aleatorias
def generate_random_public_ip():
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        if not (ip.startswith("10.") or ip.startswith("192.168.") or
                ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31):
            return ip

# Realizar escaneo con tipo dinámico
def scan_ip(ip, nm, scan_type):
    try:
        if scan_type == "basic":
            print(f"[INFO] Escaneo básico en {ip}")
            nm.scan(ip, '1-1024', '-sV --host-timeout 30s')
        elif scan_type == "syn":
            print(f"[INFO] Escaneo SYN en {ip}")
            nm.scan(ip, '1-1024', '-sS -T4 --host-timeout 30s')
        elif scan_type == "full":
            print(f"[INFO] Escaneo completo en {ip}")
            nm.scan(ip, '1-65535', '-sV --host-timeout 30s')
        elif scan_type == "udp":
            print(f"[INFO] Escaneo UDP en {ip}")
            nm.scan(ip, '1-1024', '-sU --host-timeout 30s')
        elif scan_type == "evasive":
            print(f"[INFO] Escaneo evasivo en {ip}")
            nm.scan(ip, '1-1024', '-sS -T4 -f --mtu 24 --host-timeout 30s')
        else:
            print("[ERROR] Tipo de escaneo no válido.")
            return None
        return nm[ip] if ip in nm.all_hosts() else None
    except Exception as e:
        print(f"[ERROR] Error al escanear {ip}: {e}")
        return None

# Registrar resultados en archivo y consola
def log_results(host, data, file):
    file.write(f"IP: {host}\n")
    file.write("PUERTOS ABIERTOS:\n")
    print(f"IP: {host}")
    print("PUERTOS ABIERTOS:")
    for proto in data.all_protocols():
        lport = data[proto].keys()
        for port in lport:
            if data[proto][port]['state'] == 'open':
                service = data[proto][port].get('name', 'Unknown')
                version = data[proto][port].get('version', 'N/A')
                file.write(f"  - {port}: {service} ({version})\n")
                print(f"  - {port}: {service} ({version})")
    file.write("\n")
    print("")

# Escaneo autónomo
def main():
    nm = nmap.PortScanner()
    scan_types = ["basic", "syn", "full", "udp", "evasive"]  # Tipos de escaneo
    current_scan = 0  # Índice del tipo de escaneo actual
    end_time = datetime.now() + timedelta(hours=1)  # Limitar duración total a 1 hora

    with open("scan_results.txt", "a") as file:
        while datetime.now() < end_time:
            ip = generate_random_public_ip()
            print(f"[INFO] Escaneando IP: {ip} (Tipo: {scan_types[current_scan]})")
            data = scan_ip(ip, nm, scan_types[current_scan])

            # Si hay resultados, registrarlos
            if data:
                log_results(ip, data, file)
            else:
                print(f"[INFO] No se obtuvieron resultados para {ip}")

            # Cambiar al siguiente tipo de escaneo si no hay resultados
            current_scan = (current_scan + 1) % len(scan_types)

            time.sleep(1)  # Esperar 1 segundo antes del siguiente escaneo

if __name__ == "__main__":
    main()

