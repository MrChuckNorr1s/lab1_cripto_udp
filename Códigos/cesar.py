import sys

def cifrado_cesar(texto, desplazamiento):
    resultado = ""
    for caracter in texto:
        if caracter.isalpha():
            base = ord('A') if caracter.isupper() else ord('a')
            nuevo_caracter = chr(base + (ord(caracter) - base + desplazamiento) % 26)
        else:
            nuevo_caracter = caracter
        resultado += nuevo_caracter
    return resultado

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py \"texto a cifrar\" desplazamiento")
        sys.exit(1)
    
    texto = sys.argv[1]
    try:
        desplazamiento = int(sys.argv[2])
    except ValueError:
        print("El desplazamiento debe ser un número entero.")
        sys.exit(1)

    print(cifrado_cesar(texto, desplazamiento))
