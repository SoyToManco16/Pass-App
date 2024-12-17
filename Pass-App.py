from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import secrets
import string
import hashlib
import bcrypt
import os


def clean():
    os.system('cls' if os.name == 'nt' else 'clear')

print("Desarrollado por SoyToManco16 y ChatGPT xD") 
print("Generador y encriptador de contraseñas")
def mostrar_menu():
    print("Elija entre las dos opciones")
    print("1) Generar contraseña")
    print("2) Encriptar contraseña")
    print("3) Hashear contraseña")
    print("4) Desencriptar contraseña")
    print("5) Historial de contraseñas")
    print("6) Salir")

def generate(): # Opción 1
    print("Has escogido generar una contraseña")
    print("Especifique la longitud de su contraseña")
    print("A) 8")
    print("B) 12")
    print("C) 16")
    print("D) Longitud personalizada (max 30)")

    opcion = str(input("Elije una opción: ")).upper()
    longitudes = {"A": 8, "B": 12, "C": 16}
    if opcion in longitudes:
        longitud = longitudes[opcion]
    elif opcion == "D":
        try: 
            longitud = int(input("Introduzca la longitud deseada (max 30): "))
            if longitud < 8 or longitud > 30:
                print("La longitud no puede ser menor que 8 o mayor que 30")
                return

        except ValueError:
            print("Error: Debes de introducir un número válido")
            return
    else:
        print("Opción no válida, escoja entre (A B C D)")
        return

    # Generar contraseña
    caracteres = string.ascii_letters + string.digits + string.punctuation
    contraseña = ''.join(secrets.choice(caracteres) for _ in range (longitud))
    print(f"Contraseña generada de {longitud} carácteres: {contraseña}")


def crypt(): # Opción 2
    clean()
    print("Has seleccionado encriptar una contraseña")
    print("Escoja un metodo de encriptación")
    print("A) Cifrado simétrico")
    print("B) Cifrado asimétrico")
    print("C) Cifrado de contraseñas")

    option = str(input("Escoja una opción: ")).upper()
    if option == "A":
        mirrorcrypt()
    elif option == "B":
        nonmirrorcrypt()
    elif option == "C":
        passcrypt()
    else:
        print("Elija entre (A B C)")
        return

def mirrorcrypt():
    clean()
    print("Usted ha seleccionado cifrado simétrico")
    print("A) AES")
    print("B) ChaCha20")

    option = str(input("Seleccione un tipo de cifrado simétrico: ")).upper()
    if option == "A":
        key = Fernet.generate_key()
        cipher = Fernet(key)

        pwdtext = str(input("Introduce la contraseña o texto que deseas cifrar: "))
        ciphered = cipher.encrypt(pwdtext.encode())

        print(f"\nTexto cifrado: {ciphered.decode()}")
        print(f"\nLlave secreta (guardar para descifrar) {key.decode()}")
        
    if option == "B":
        key = ChaCha20Poly1305.generate_key()
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)

        pwdtext = str(input("Introduce la contraseña o texto que deseas cifrar: "))
        ciphered = cipher.encrypt(nonce, pwdtext.encode(), None)

        print(f"\nTexto cifrado (hexadecimal): {ciphered.hex()}")
        print(f"\nClave secreta: {key.hex()}")
        print(f"\nNonce (necesario para descifrar) {nonce.hex()}")

    else:
        return

def nonmirrorcrypt():
    clean()
    print("Usted ha seleccionado cifrado asimétrico")
    print("A) RSA")
    print("B) Ed25519 (SSH)")

    ans = str(input("Seleccione un tipo de cifrado asimétrico: ")).upper()
    if ans == "A":
        print("Longitudes para clave RSA")
        print("A) 2048 (Recomendada), B) 3072 (Común), C) 4096 (Alta seguridad), D) 1024 (No recomendable)")
        bytes = str(input("Escoja una longitud: ")).upper()
        if bytes == "A":
            ks = 2048
        elif bytes == "B":
            ks = 3072
        elif bytes == "C":
            ks = 4096
        elif bytes == "D":
            ks = 1024
        else:
            print("A dar porculo a tu casa")

        pvkey = rsa.generate_private_key(public_exponent=65537, key_size=ks)
        pubkey = pvkey.public_key()

        print("Par de claves generada")

        pem = pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )            

        print(f"{pem.decode()}")

        pwdtext = str(input("Introduce la contraseña o texto a cifrar: "))
        ciphered = pubkey.encrypt(
            pwdtext.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print(f"\nTexto cifrado (hexadecimal): {ciphered.hex()}")

    if ans == "B":
        pvkey = ed25519.Ed25519PrivateKey.generate()
        pubkey = pvkey.public_key()

        passphrase = str(input("Introduce un mensaje para firmar digitalmente: "))
        firma = pvkey.sign(passphrase.encode())

        print("\nSe ha generado la firma digital")
        print(f"Firma (hexadecimal): {firma.hex()}")

    else:
        return


def passcrypt():
    clean()
    print("Usted ha seleccionado cifrado para contraseñas")
    print("A) bcrypt")
    print("B) pbkdf2_hmac")

    ans = str(input("Selecciona un metodo de cifrado de contraseñas: ")).upper()
    if ans == "A":    

        pwd = str(input("Introduce la contraseña que deseas encriptar: "))
        salt = bcrypt.gensalt()
        hashpwd = bcrypt.hashpw(pwd.encode('utf-8'), salt)

        print(f"\nContraseña cifrada (bcrypt): {hashpwd.decode()}")

    if ans == "B":

        pwd = str(input("Introduce la contraseña que deseas encriptar: "))
        salt = os.urandom(16) # Generar un salt aleatorio
        hashpwd = hashlib.pbkdf2_hmac(
            'sha256', pwd.encode(), salt, 100000
        )

        print(f"\nSalt: {salt.hex()}")
        print(f"Contraseña cifrada (pbkdf2_hmac): {hashpwd.hex()}")

    else:
        return

def hashpass(): # Opción 3
    clean()
    print("Usted ha seleccionado hashear la contraseña")
    print("A) MD5")
    print("B) SHA256")

    ans = str(input("Seleccione un metodo de hasheo de contraseñas: ")).upper()

    if ans == "A":
        pwd = str(input("Introduzca la contraseña que desea hashear: "))
        hashed = hashlib.md5(pwd.encode()).hexdigest()
        print(f"Hash MD5 de la contraseña introducida: {hashed}")

    if ans == "B":
        pwd = str(input("Introduzca la contraseña que desea hashear: "))
        hashed = hashlib.sha256(pwd.encode()).hexdigest()
        print(f"Hash SHA256 de la contraseña introducida: {hashed}")

while True:
    mostrar_menu()
    try:
        answer = int(input("Escoja una opción: "))
    except KeyboardInterrupt:
        print(" "), print("Hasta la proxima compi :(")
        break

    if answer == 1:
        clean(); generate(); print(" ")
    elif answer == 2:
        clean(); crypt(); print(" ")
    elif answer == 3:
        clean(); hashpass(); print(" ")
    elif answer == 4:
        print("Saliendo del programa, hasta la próxima :)")
        break
        exit()
    else:
        clean(); print("Opción no valida introduzca de 1 a 4"); continue


