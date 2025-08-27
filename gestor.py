#!/usr/bin/env python3
import os
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style

init(autoreset=True)

# -------------------- Configuración --------------------
STORAGE_DIR = "storage"
PASSWORD_FILE = os.path.join(STORAGE_DIR, "passwords.enc")
KEY_FILE = os.path.join(STORAGE_DIR, "key.key")
REGISTRY_FILE = os.path.join(STORAGE_DIR, "file_registry.txt")
NUM_PASSWORDS = 20
PASSWORD_LENGTH = 12

passwords_memoria = []

# -------------------- Funciones de cifrado --------------------
def generar_fernet_key(contraseña: str, salt: bytes = b'salt1234') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(contraseña.encode()))
    return key

def cargar_o_generar_clave():
    if not os.path.exists(STORAGE_DIR):
        os.makedirs(STORAGE_DIR)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return Fernet(key)

fernet = cargar_o_generar_clave()

# -------------------- Funciones de contraseñas --------------------
def generar_password(longitud=PASSWORD_LENGTH):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-={}[]"
    return ''.join(secrets.choice(chars) for _ in range(longitud))

def guardar_passwords():
    global passwords_memoria
    data = "\n".join(passwords_memoria).encode()
    encrypted = fernet.encrypt(data)
    with open(PASSWORD_FILE, "wb") as f:
        f.write(encrypted)

def cargar_passwords():
    global passwords_memoria
    if not os.path.exists(PASSWORD_FILE):
        return False
    with open(PASSWORD_FILE, "rb") as f:
        encrypted = f.read()
    data = fernet.decrypt(encrypted).decode()
    passwords_memoria = data.split("\n")
    return True

def generar_passwords():
    global passwords_memoria
    passwords_memoria = [generar_password() for _ in range(NUM_PASSWORDS)]
    print(Fore.GREEN + "\nContraseñas generadas:\n")
    for i, pw in enumerate(passwords_memoria, 1):
        print(Fore.CYAN + f"{i}: {pw}")
    guardar_passwords()
    print(Fore.GREEN + "\nContraseñas guardadas y cifradas\n")

def mostrar_passwords():
    if not passwords_memoria:
        print(Fore.YELLOW + "No hay contraseñas cargadas. Primero genera o carga el archivo.\n")
        return
    print(Fore.GREEN + "\nContraseñas en memoria:\n")
    for i, pw in enumerate(passwords_memoria, 1):
        print(Fore.CYAN + f"{i}: {pw}")
    print()

# -------------------- Funciones de archivos --------------------
def listar_archivos(directorio):
    archivos = [f for f in os.listdir(directorio) if os.path.isfile(os.path.join(directorio, f))]
    for i, f in enumerate(archivos, 1):
        print(Fore.CYAN + f"{i}: {f}")
    return archivos

def cifrar_archivo():
    if not passwords_memoria:
        print(Fore.YELLOW + "No hay contraseñas cargadas. Primero genera o carga el archivo.\n")
        return
    print(Fore.MAGENTA + "\nArchivos disponibles para cifrar (0 para cancelar):\n")
    archivos = listar_archivos(STORAGE_DIR)
    if not archivos:
        print(Fore.YELLOW + "No hay archivos para cifrar.\n")
        return

    opcion_input = input(Fore.GREEN + "Elige el número del archivo a cifrar (0 para cancelar): ")
    if opcion_input.strip() == "0":
        print(Fore.YELLOW + "Acción cancelada.\n")
        return

    opcion = int(opcion_input) - 1
    archivo = os.path.join(STORAGE_DIR, archivos[opcion])
    
    mostrar_passwords()
    pw_input = input(Fore.GREEN + "Elige el número de la contraseña para cifrar el archivo (0 para cancelar): ")
    if pw_input.strip() == "0":
        print(Fore.YELLOW + "Acción cancelada.\n")
        return

    pw_num = int(pw_input) - 1
    contraseña = passwords_memoria[pw_num]
    key = generar_fernet_key(contraseña)
    f = Fernet(key)
    with open(archivo, "rb") as file:
        data = file.read()
    encrypted = f.encrypt(data)
    enc_file = archivo + ".enc"
    with open(enc_file, "wb") as file:
        file.write(encrypted)
    os.remove(archivo)
    with open(REGISTRY_FILE, "a") as reg:
        reg.write(f"{os.path.basename(enc_file)}:{pw_num}\n")
    print(Fore.GREEN + f"\nArchivo cifrado correctamente como {os.path.basename(enc_file)}\n")


def descifrar_archivo():
    if not os.path.exists(REGISTRY_FILE):
        print(Fore.YELLOW + "No hay archivos cifrados registrados.\n")
        return

    with open(REGISTRY_FILE, "r") as reg:
        lines = reg.readlines()

    seen = set()
    valid_lines = []
    for line in lines:
        archivo_name = line.strip().split(":")[0]
        archivo_path = os.path.join(STORAGE_DIR, archivo_name)
        if os.path.exists(archivo_path) and archivo_name not in seen:
            valid_lines.append(line)
            seen.add(archivo_name)

    if not valid_lines:
        print(Fore.YELLOW + "No hay archivos disponibles para descifrar.\n")
        return

    print(Fore.MAGENTA + "\nArchivos disponibles para descifrar (0 para cancelar):\n")
    archivos = [line.strip().split(":")[0] for line in valid_lines]
    for i, f in enumerate(archivos, 1):
        print(Fore.CYAN + f"{i}: {f}")

    opcion_input = input(Fore.GREEN + "Elige el número del archivo a descifrar (0 para cancelar): ")
    if opcion_input.strip() == "0":
        print(Fore.YELLOW + "Acción cancelada.\n")
        return

    opcion = int(opcion_input) - 1
    archivo = os.path.join(STORAGE_DIR, archivos[opcion])
    pw_num = int(valid_lines[opcion].strip().split(":")[1])
    contraseña = passwords_memoria[pw_num]
    key = generar_fernet_key(contraseña)
    f = Fernet(key)

    with open(archivo, "rb") as file:
        encrypted = file.read()

    decrypted = f.decrypt(encrypted)
    output_file = archivo.replace(".enc", "")
    with open(output_file, "wb") as file:
        file.write(decrypted)
    os.remove(archivo)

    with open(REGISTRY_FILE, "w") as reg:
        for line in lines:
            archivo_name = line.strip().split(":")[0]
            if archivo_name != os.path.basename(archivo) and os.path.exists(os.path.join(STORAGE_DIR, archivo_name)):
                reg.write(line)

    print(Fore.GREEN + f"\nArchivo descifrado correctamente como {os.path.basename(output_file)}\n")




# -------------------- Banner y menú --------------------
def mostrar_banner():
    print(Fore.GREEN + r"""
                                                              
                                ████████████████            
                              ██▓▓            ████          
                          ▒▒██                  ████        
                          ██                      ██        
                  ████  ██▒▒                        ██      
              ██▓▓    ▓▓██                          ██      
            ██                                      ██      
            ██            ▒▒██████▓▓                ██      
          ██            ██          ██              ████    
          ██          ██    ██████▒▒  ██                ██  
      ██████        ██  ▓▓██      ████  ██                ██
    ██▓▓            ██  ██          ██  ██                ██
  ████              ██  ██          ██  ██                ██
  ██                ██  ██          ██  ██                ██
  ██                ██  ██          ██  ██                ██
  ██              ██████████████████████████            ██  
    ██          ██                          ██        ████  
      ████████████                          ██████████      
                ██          ██████          ██              
                ██          ██  ██          ██              
                ██          ██████          ██              
                ██            ██            ██              
                ██            ██            ██              
                ██                          ██              
                ██                          ██              
                ████████████████████████████▓▓              
   
Gestor de contraseñas y cifrado de archivos
""" + Style.RESET_ALL)

def limpiar_pantalla():
    os.system("clear")
    mostrar_banner()


def mostrar_menu():
    print(Fore.CYAN + "\n=== Opciones ===" + Style.RESET_ALL)
    print(Fore.YELLOW + "1) Generar 20 contraseñas seguras")
    print("2) Mostrar contraseñas")
    print("3) Cifrar un archivo")
    print("4) Descifrar un archivo")
    print("5) Salir\n")

# -------------------- Main --------------------
def main():
    if os.path.exists(PASSWORD_FILE):
        cargar_passwords()

    limpiar_pantalla()  # Limpia y muestra banner solo una vez al inicio

    while True:
        mostrar_menu()
        opcion = input(Fore.GREEN + "Elige opción: ")

        if opcion == "1":
            limpiar_pantalla()
            generar_passwords()

        elif opcion == "2":
            limpiar_pantalla()
            mostrar_passwords()

        elif opcion == "3":
            limpiar_pantalla()
            cifrar_archivo()

        elif opcion == "4":
            limpiar_pantalla()
            descifrar_archivo()

        elif opcion == "5":
            print(Fore.GREEN + "Saliendo...")
            break

        else:
            print(Fore.RED + "Opción no válida\n")


if __name__ == "__main__":
    main()
