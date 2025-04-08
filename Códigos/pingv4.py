import sys, time, os
from scapy.all import IP, ICMP, send

def cesar(texto, d):
    resultado = ""
    for c in texto:
        if c.isalpha():
            base = 65 if c.isupper() else 97
            resultado += chr((ord(c) - base + d) % 26 + base)
        else:
            resultado += c
    return resultado

def ping(dest="8.8.8.8"):
    print(f"\n[+] Ping a {dest}...\n")
    os.system(f"ping -c 3 {dest}")

def enviar_icmp(texto, dest="8.8.8.8"):
    print("\n[+] Enviando paquetes ICMP...\n")
    for c in texto:
        payload = bytes([0]*16) + c.encode() + bytes([0]*(39 - 16))  # payload desde 0x10 a 0x37 (40 bytes)
        send(IP(dst=dest)/ICMP()/payload, verbose=False)
        print(f"Sent 1 packet. ({c})")
        time.sleep(0.5)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: sudo python3 script.py \"texto\" desplazamiento")
        sys.exit(1)

    try:
        d = int(sys.argv[2])
    except ValueError:
        print("Desplazamiento debe ser un número.")
        sys.exit(1)

    texto_cifrado = cesar(sys.argv[1], d)
    print(f"\nTexto cifrado: {texto_cifrado}")

    ping()
    enviar_icmp(texto_cifrado)
    ping()
