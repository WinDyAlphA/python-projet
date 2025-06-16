#!/usr/bin/env python3

import os
import logging
import subprocess
import tempfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymm_padding
from cryptography.hazmat.primitives import serialization

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_public_key(public_key_path):
    """
    Charge une clé publique depuis un fichier PEM
    """
    try:
        with open(public_key_path, "rb") as key_file:
            public_pem = key_file.read()
        public_key = serialization.load_pem_public_key(public_pem)
        return public_key
    except Exception as e:
        logging.error(f"Erreur lors du chargement de la clé publique: {str(e)}")
        return None

def verify_file_signature(file_path, signature_path, public_key):
    """
    Vérifie la signature d'un fichier
    """
    try:
        # Lire le contenu du fichier
        with open(file_path, "rb") as file:
            message = file.read()
        
        # Lire la signature
        with open(signature_path, "rb") as sig_file:
            signature = sig_file.read()
        
        # Vérifier la signature
        try:
            public_key.verify(
                signature,
                message,
                asymm_padding.PSS(
                    mgf=asymm_padding.MGF1(hashes.SHA256()),
                    salt_length=asymm_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    except Exception as e:
        logging.error(f"Erreur lors de la vérification: {str(e)}")
        return False

def decrypt_message(ciphertext, key, iv):
    """
    Déchiffre un message avec AES-CBC
    """
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
        return plaintext.decode('utf-8')
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement: {str(e)}")
        return None

def run_docker_command(container_id, command):
    """
    Exécute une commande dans un conteneur Docker
    """
    try:
        result = subprocess.run(
            ["docker", "exec", container_id] + command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de l'exécution de la commande Docker: {str(e)}")
        logging.error(f"Stderr: {e.stderr}")
        return None

def copy_from_docker(container_id, src_path, dst_path):
    """
    Copie un fichier depuis un conteneur Docker vers l'hôte
    """
    try:
        result = subprocess.run(
            ["docker", "cp", f"{container_id}:{src_path}", dst_path],
            capture_output=True,
            text=True,
            check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de la copie depuis Docker: {str(e)}")
        logging.error(f"Stderr: {e.stderr}")
        return False

def main():
    """
    Récupère les fichiers depuis le conteneur SSH et déchiffre le fichier sécurisé
    """
    print("=" * 60)
    print("RÉCUPÉRATION ET DÉCHIFFREMENT DES FICHIERS AVEC DOCKER")
    print("=" * 60)
    
    # ID du conteneur Docker SSH
    container_id = input("Entrez l'ID du conteneur SSH (ex: acd157102376): ")
    
    # Dossier de destination pour les fichiers récupérés
    output_dir = "retrieved_files"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Chemins des fichiers sur le serveur SSH
    remote_config_dir = "/config"
    encrypted_file = os.path.join(remote_config_dir, "secure_file.enc")
    key_file = os.path.join(remote_config_dir, "encryption_key.bin")
    iv_file = os.path.join(remote_config_dir, "encryption_iv.bin")
    sig_file = os.path.join(remote_config_dir, "secure_file.sig")
    pub_key_file = os.path.join(remote_config_dir, "secure_file.pub")
    
    # Chemins locaux pour les fichiers récupérés
    local_encrypted_file = os.path.join(output_dir, "secure_file.enc")
    local_key_file = os.path.join(output_dir, "encryption_key.bin")
    local_iv_file = os.path.join(output_dir, "encryption_iv.bin")
    local_sig_file = os.path.join(output_dir, "secure_file.sig")
    local_pub_key_file = os.path.join(output_dir, "secure_file.pub")
    local_output_file = os.path.join(output_dir, "message_dechiffre.txt")
    
    # Liste des fichiers à récupérer
    files_to_retrieve = [
        (encrypted_file, local_encrypted_file),
        (key_file, local_key_file),
        (iv_file, local_iv_file),
        (sig_file, local_sig_file),
        (pub_key_file, local_pub_key_file)
    ]
    
    # Vérifier que les fichiers existent sur le serveur
    print("\nVérification des fichiers sur le serveur...")
    for remote_path, _ in files_to_retrieve:
        result = run_docker_command(container_id, ["ls", "-la", remote_path])
        if result is None:
            logging.error(f"Le fichier {remote_path} n'existe pas sur le serveur!")
            return False
        else:
            logging.info(f"Fichier trouvé: {remote_path}")
    
    # Récupération des fichiers
    print("\nRécupération des fichiers depuis le conteneur Docker...")
    all_files_retrieved = True
    for remote_path, local_path in files_to_retrieve:
        logging.info(f"Copie de {remote_path} vers {local_path}")
        success = copy_from_docker(container_id, remote_path, local_path)
        if not success:
            all_files_retrieved = False
            logging.error(f"Échec de la copie du fichier {remote_path}")
    
    if not all_files_retrieved:
        logging.error("Certains fichiers n'ont pas pu être récupérés")
        return False
    
    # Déchiffrement du fichier
    try:
        # Chargement de la clé et du vecteur d'initialisation
        logging.info("Chargement de la clé et du vecteur d'initialisation")
        with open(local_key_file, "rb") as f:
            key_data = f.read()
        
        with open(local_iv_file, "rb") as f:
            iv_data = f.read()
        
        # Chargement du fichier chiffré
        logging.info("Chargement du fichier chiffré")
        with open(local_encrypted_file, "rb") as f:
            ciphertext = f.read()
        
        # Déchiffrement
        logging.info("Déchiffrement du fichier")
        plaintext = decrypt_message(ciphertext, key_data, iv_data)
        
        if not plaintext:
            logging.error("Échec du déchiffrement")
            return False
        
        # Sauvegarde du message déchiffré
        logging.info(f"Sauvegarde du message déchiffré dans {local_output_file}")
        with open(local_output_file, "w") as f:
            f.write(plaintext)
        
        # Vérification de la signature
        logging.info("Vérification de l'intégrité du message")
        public_key = load_public_key(local_pub_key_file)
        
        if public_key:
            is_valid = verify_file_signature(local_output_file, local_sig_file, public_key)
            
            if is_valid:
                logging.info("✅ SUCCÈS: La signature du fichier déchiffré est valide. L'intégrité est confirmée.")
                
                # Affichage du contenu du fichier vérifié
                print("\n======== CONTENU DU FICHIER DÉCHIFFRÉ ========")
                print(plaintext)
                print("============================================\n")
                return True
            else:
                logging.error("❌ ÉCHEC: La signature du fichier déchiffré est invalide. Possible altération!")
                return False
        else:
            logging.error("Impossible de vérifier la signature: clé publique non disponible")
            return False
    
    except Exception as e:
        logging.error(f"Erreur lors du déchiffrement: {str(e)}")
        return False

if __name__ == "__main__":
    if main():
        print("\n✅ Opération réussie! Le message a été déchiffré et vérifié.")
    else:
        print("\n❌ Échec de l'opération.") 