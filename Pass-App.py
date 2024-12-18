from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from colorama import init, Fore

import secrets
import string
import hashlib
import bcrypt
import os

# Inicializar colorama
init()

def clean():
    os.system('cls' if os.name == 'nt' else 'clear')

print("Desarrollado por SoyToManco16 y ChatGPT xD") 
print("Generador y encriptador de contraseñas")
print(" ")
def mostrar_menu():
    print(Fore.LIGHTBLUE_EX + "--- PASS APP ---" + Fore.RESET)
    print(Fore.LIGHTBLACK_EX + "1) Generar contraseña")
    print("2) Encriptar contraseña")
    print("3) Hashear contraseña")
    print("4) Desencriptar contraseña")
    print("5) Historial de contraseñas")
    print("q) Salir" + Fore.RESET)
    print(" ")

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
            print(Fore.RED + "Error: Debes de introducir un número válido" + Fore.RESET)
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

        pwdtext = str(input("Introduce la contraseña que deseas cifrar: "))
        ciphered = cipher.encrypt(pwdtext.encode())

        print(f"\nContraseña cifrada: {ciphered.decode()}")
        print(f"\nLlave secreta (guardar para descifrar) {key.decode()}")
        
    if option == "B":
        key = ChaCha20Poly1305.generate_key()
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(12)

        pwdtext = str(input("Introduce la contraseña que deseas cifrar: "))
        ciphered = cipher.encrypt(nonce, pwdtext.encode(), None)

        print(f"\nContraseña cifrada (hexadecimal): {ciphered.hex()}")
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

        try:
            pvkey = rsa.generate_private_key(public_exponent=65537, key_size=ks)
            pubkey = pvkey.public_key()

            print("Par de claves generado")

            pempub = pubkey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )            

            # Guardar la clave privada en un fichero .pem
            with open("pubkey.pem", "wb") as pubfile:
                pubfile.write(pempub)
            print("Clave pública guardada en pubkey.pem")

            # Preguntar por cifrado de clave privada
            ans = str(input("¿Deseas proteger la clave privada con contraseña? (s/n)")).upper()

            if ans == "S":
                pwduser = str(input("Introduzca la contraseña para el cifrado de la clave privada: ")).encode()
                
                pemprv = pvkey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(pwduser)
                ) 

            else:
                pemprv = pvkey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )

            with open("pvkey.pem", "wb") as pvfile:
                pvfile.write(pemprv)
            print("Clave pública guardada en pvkey.pem")

            pwdtext = str(input("Introduce la contraseña a cifrar: "))
            ciphered = pubkey.encrypt(
                pwdtext.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            print(f"\nContraseña cifrado (hexadecimal): {ciphered.hex()}")

        except Exception as err:
            print(Fore.RED + f"Ocurrió un error inesperado: {err}" + Fore.RESET)
            exit()

    elif ans == "B":
        pvkey = ed25519.Ed25519PrivateKey.generate()
        pubkey = pvkey.public_key()

        passphrase = str(input("Introduce un mensaje para firmar digitalmente: "))
        firma = pvkey.sign(passphrase.encode())

        print("\nSe ha generado la firma digital")
        print(f"Firma (hexadecimal): {firma.hex()}")

        print(f"Clave pública (hexadecimal): {pubkey.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()}")

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

def decrypt(): # Opción 4
    clean()
    print("Usted ha seleccionado descifrar contraseñas")
    print("A) Cifrado simétrico")
    print("B) Cifrado asimétrico")
    print("C) Cifrado de contraseñas")
    print("D) Hashes")

    ans = str(input("Seleccione que desea descifrar: ")).upper()

    if ans == "A":
        decryptsim()
    elif ans == "B":
        decryptasim()
    elif ans == "C":
        decryptpass()
    elif ans == "D":
        decrypthash()
    else:
        print("Esta opción no es válida")
        return

def decryptsim():
    print("Descifrado simétrico")
    print("A) AES")
    print("B) ChaCha20")

    read = str(input("Seleccione una opción: ")).upper()

    if read == "A":
        pvkey = str(input("Introduzca la llave secreta: "))
        pwdtext = str(input("Introduzca la contraseña cifrado: "))

        try:
            unciphered = Fernet(pvkey).decrypt(pwdtext)
            print(Fore.GREEN + f"Contraseña descifrada: {unciphered}" + Fore.RESET)

        except InvalidToken:
            print(Fore.RED + "Error: La clave secreta no es correcta o la contraseña cifrada está corrupto" + Fore.RESET)

        except Exception as err:
            print(Fore.RED + f"Ocurrió un error inesperado: {err}" + Fore.RESET)

    elif read == "B":
        pvkey = str(input("Introduzca la llave secreta (hex): "))
        nonce = str(input("Introduce el nonce que se generó junto a la llave secreta (hex): "))
        pwdtext = str(input("Introduzca la contraseña cifrado (hex): "))

        try:
            cleanpvkey = bytes.fromhex(pvkey)
            cleannonce = bytes.fromhex(nonce)
            cleanpwdtext = bytes.fromhex(pwdtext)

            inichacha = ChaCha20Poly1305(cleanpvkey)

            unciphered = inichacha.decrypt(cleannonce, cleanpwdtext, None)
            print(Fore.GREEN + f"Contraseña descifrada correctamente: {unciphered}" + Fore.RESET)

        except InvalidTag:
            print(Fore.RED + "Error: La clave secreta, el nonce o la contraseña cifrados están corruptos" + Fore.RESET)
        except ValueError:
            print(Fore.RED + "Error: Asegúrate de introducir valores en formato hexadecimal válidos" + Fore.RESET)
        except Exception as err:
            print(Fore.RED + f"Ocurrió un error inesperado: {err}" + Fore.RESET)


def decryptasim():
    print("Descifrado asimétrico")
    print("A) RSA")
    print("B) Verificación ED25519 (SSH)")

    read = str(input("Seleccione una opción: ")).upper()
    if read == "A":
        try: # Leer la clave privada de el archivo generado
            with open("pvkey.pem", "rb") as pvfile:
                pvkey = pvfile.read()

            ans = str(input("¿La clave privada está cifrada con una contraseña? (s/n): ")).upper()
            if ans == "S":
                pwd = str(input("Introduzca la contraseña para descifrar el mensaje: "))
                pvkey = serialization.load_pem_private_key(pvkey, password=pwd, backend=default_backend())
            else:
                pvkey = serialization.load_pem_private_key(pvkey, password=None, backend=default_backend())
            
            print("Clave privada cargada correctamente")

            # Solicitar texto o contraseña cifrada
            ciphered = str(input("Introduzca la contraseña (hex): "))
            cipheredbytes = bytes.fromhex(ciphered)

            # Descifrar pass o texto
            unciphered = pvkey.decrypt(
                cipheredbytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(Fore.GREEN + f"Contraseña descifrada: {unciphered}" + Fore.RESET)

        except FileNotFoundError:
            print(Fore.RED + "Error: No se ha detectado el archivo pvkey.pem")
        except ValueError:
            print("Error: La contraseña o el formato del archivo es incorrecto")
        except InvalidToken:
            print("Error: La clave privada no corresponde a la contraseña cifrada")
        except Exception as err:
            print(f"Ocurrió un error inesperado: {err}" + Fore.RESET)

    elif read == "B":

        # Solicitar firma y convertirla a bytes
        digitalsignature = str(input("Introduce la firma digital (hex): "))
        bytessignature = bytes.fromhex(digitalsignature)

        # Solicitar clave pública y convertirla a bytes
        pubkeyhex = str(input("Introduce la clave pública (hex): "))
        bytespubkey = bytes.fromhex(pubkeyhex)
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytespubkey)

        # Solicitar la passphrase
        passphrase = str(input("Introduce el mensaje original para comprobar su integridad: "))

        # Verificar la firma con la clave pública
        try:
            pubkey.verify(bytessignature, passphrase.encode())
            print(Fore.GREEN + "La firma es válida, el mensaje no ha sido alterado" + Fore.RESET)

        except ValueError as err:
            print(Fore.RED +  f"Error de verificación: La firma no es valida o los datos no coinciden. Detalles: {err}" + Fore.RESET)

        except TypeError as err:
            print(Fore.RED +  f"Error de tipo de dato: Hubo un problema con los tipos de datos. Detalles {err}" + Fore.RESET)
        
        except Exception as err:
            print(Fore.RED + f"Ocurrió un error inesperado: {err}" + Fore.RESET)


def decryptpass():
    print("Descifrado de contraseñas")
    print("A) bcrypt")
    print("B) pbkdf2_hmac")

def decrypthash():
    print("Descifrar hashes")
    print("A) MD5")
    print("B) SHA256")



while True:
    mostrar_menu()
    try:
        answer = str(input("Escoja una opción: "))
    except KeyboardInterrupt:
        print(" "), print("Hasta la proxima compi :(")
        break

    if answer == "1":
        clean(); generate(); print(" ")
    elif answer == "2":
        clean(); crypt(); print(" ")
    elif answer == "3":
        clean(); hashpass(); print(" ")
    elif answer == "4":
        clean(); decrypt(); print(" ")
    elif answer == "q":
        print("Saliendo del programa, hasta la próxima :)")
        break
        exit()
    elif answer == "":
        clean()
    else:
        clean(); print("Opción no valida introduzca de 1 a 5"); continue


