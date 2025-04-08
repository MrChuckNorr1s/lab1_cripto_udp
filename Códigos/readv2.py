#!/usr/bin/env python3
import sys
from scapy.all import rdpcap

def extraer_mensaje_pcapng(archivo_pcap):
    """Extrae el mensaje cifrado del archivo pcapng"""
    try:
        paquetes = rdpcap(archivo_pcap)
        mensaje = []
        for pkt in paquetes:
            if pkt.haslayer('ICMP') and pkt['ICMP'].type == 8 and pkt['ICMP'].load:
                char = pkt['ICMP'].load[16:17].decode('ascii', errors='ignore')
                if char.isalpha() or char == ' ':
                    mensaje.append(char)
        return ''.join(mensaje)
    except Exception as e:
        print(f"Error al leer PCAPNG: {e}")
        return None

def descifrar_cesar(mensaje_cifrado):
    """Descifrado César con resaltado correcto"""
    alfabeto = 'abcdefghijklmnopqrstuvwxyz'  # Alfabeto sin espacio
    
    print("\nProbando desplazamientos (0-25):")
    print("-------------------------------")
    
    for desplazamiento in range(26):
        descifrado = []
        for c in mensaje_cifrado.lower():
            if c == ' ':
                descifrado.append(' ')  # Mantenemos espacios
            elif c in alfabeto:
                idx = (alfabeto.index(c) - desplazamiento) % len(alfabeto)
                descifrado.append(alfabeto[idx])
            else:
                descifrado.append(c)
        
        texto = ''.join(descifrado)
        
        # Detección del mensaje correcto y resaltado
        if any(palabra in texto for palabra in ['seguridad', 'criptografia', 'redes']):
            print(f"\033[92m{desplazamiento:2d}: {texto}\033[0m")  # Texto en verde
        else:
            print(f"{desplazamiento:2d}: {texto}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 descifrar.py archivo.pcapng")
        sys.exit(1)
    
    mensaje = extraer_mensaje_pcapng(sys.argv[1])
    if not mensaje:
        print("No se pudo extraer mensaje del archivo PCAPNG")
        sys.exit(1)
    
    print(f"\nMensaje cifrado extraído: {mensaje}")
    descifrar_cesar(mensaje)