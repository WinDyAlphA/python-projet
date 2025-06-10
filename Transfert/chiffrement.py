from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey
import os

# recupere le pwd
pwd = os.getcwd()
# recuperer le fichier test.txt
file_path = os.path.join(pwd, "Transfert", "test.txt")


key = os.urandom(32)
iv = os.urandom(16)

def validate_key(key):
    try:
        if len(key) != 32:  # AES-256
            raise InvalidKey("La longueur de la clé doit être de 32 bytes")
        return True
    except Exception as e:
        raise InvalidKey(f"Clé invalide: {str(e)}")


def encrypt_message(message, encryption_key=key):
    try:
        if not validate_key(encryption_key):
            raise InvalidKey("La clé est invalide")
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    except InvalidKey:
        # On laisse remonter l'exception InvalidKey
        raise
    except Exception as e:
        print(f"Erreur lors du chiffrement: {str(e)}")
        return None

def decrypt_message(ciphertext, decryption_key=key):
    try:
        if not validate_key(decryption_key):
            raise InvalidKey("La clé est invalide")
        cipher = Cipher(algorithms.AES(decryption_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        return plaintext.decode()
    except InvalidKey:
        # On laisse remonter l'exception InvalidKey
        raise
    except Exception as e:
        print(f"Erreur lors du déchiffrement: {str(e)}")
        return None
  



def encrypt_to_file(message, filename):
  try:
    ciphertext = encrypt_message(message)
    with open(filename, 'wb') as f:
      f.write(ciphertext)
    return ciphertext
  except IOError as e:
    print(f"Erreur lors de l'écriture dans le fichier {filename}: {e}")
    return None
  except Exception as e:
    print(f"Erreur lors du chiffrement: {e}")
    return None

def decrypt_from_file(filename):
  try:
    with open(filename, 'rb') as f:
      ciphertext = f.read()
    return decrypt_message(ciphertext)
  except FileNotFoundError as e:
    print(f"Erreur lors de la lecture du fichier {filename}: {e}")
    return None
  except IOError as e:
    print(f"Erreur lors de la lecture du fichier {filename}: {e}")
    return None
  except Exception as e:
    print(f"Erreur lors du déchiffrement: {e}")
    return None

def decrypt_to_file(ciphertext, filename):
  try:
    plaintext = decrypt_message(ciphertext)
    with open(filename, 'w') as f:
      f.write(plaintext)
    return plaintext
  except IOError as e:
    print(f"Erreur lors de l'écriture dans le fichier {filename}: {e}")
    return None
  except Exception as e:
    print(f"Erreur lors du déchiffrement: {e}")
    return None

def encrypt_from_file(filename):
  try:
    with open(filename, 'r') as f:
      message = f.read()
    return encrypt_message(message)
  except FileNotFoundError as e:
    print(f"Erreur lors de la lecture du fichier {filename}: {e}")
    return None
  except Exception as e:
    print(f"Erreur lors du chiffrement: {e}")
    return None

# main 

if __name__ == "__main__":
    # Chiffrer le fichier test.txt
    cipher = encrypt_from_file(file_path)
    
    # Sauvegarder le chiffré dans un fichier
    with open(file_path+".enc", "wb") as f:
        if cipher is not None:
            f.write(cipher)
    print(f"Le fichier test.txt a été chiffré et sauvegardé dans encrypted_test.txt")
