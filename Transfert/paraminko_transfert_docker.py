import paramiko
import os
import logging
import getpass
import shutil
import tempfile
from signature import sign_for_send, verify_file_signature, load_public_key
from chiffrement import encrypt_from_file, decrypt_message, decrypt_message_binary, decrypt_from_file, key, iv


# Configuration du système de journalisation
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def transfer_file(file_path, remote_path, host="172.20.0.2", port=2222, username="noahheraud", 
                 use_key=False, key_path="/root/.ssh/id_rsa", password=None, key_password=None, encrypt=False):    
    """
    Transfère un fichier vers un serveur distant via SFTP.
    
    Paramètres:
    - file_path: Chemin du fichier local à transférer
    - remote_path: Chemin de destination sur le serveur distant
    - host: Adresse IP ou nom d'hôte du serveur distant
    - port: Port SSH (22 par défaut)
    - username: Nom d'utilisateur pour la connexion
    - use_key: Utiliser l'authentification par clé SSH (False par défaut)
    - key_path: Chemin vers la clé privée SSH
    - password: Mot de passe pour l'authentification par mot de passe
    - key_password: Mot de passe pour déverrouiller la clé SSH si elle est protégée
    - encrypt: Chiffrer le fichier avant le transfert (False par défaut)
    """
    try:
        logging.info(f"Connexion à {host}:{port} en tant que {username}")
        logging.info(f"Méthode d'authentification: {'Clé SSH' if use_key else 'Mot de passe'}")
        
        # Chiffrement du fichier si demandé
        temp_file_path = file_path
        if encrypt and not file_path.endswith(('.sig', '.pub', '.enc')):
            logging.info(f"Chiffrement du fichier {file_path}")
            ciphertext = encrypt_from_file(file_path)
            if ciphertext:
                temp_file_path = file_path + ".enc"
                with open(temp_file_path, "wb") as f:
                    f.write(ciphertext)
                logging.info(f"Fichier chiffré et sauvegardé dans {temp_file_path}")
            else:
                logging.error(f"Échec du chiffrement du fichier {file_path}")
                return False
        
        # Vérification de l'existence de la clé SSH si cette méthode est utilisée
        if use_key:
            logging.info(f"Utilisation de la clé: {key_path}")
            if not os.path.exists(key_path):
                logging.error(f"Fichier de clé SSH introuvable: {key_path}")
                return False
        
        # Création du client SSH
        # Le client SSH est l'objet principal pour établir une connexion SSH
        client = paramiko.SSHClient()
        
        # Cette politique accepte automatiquement les clés des serveurs inconnus
        # ATTENTION: En production, il est préférable d'utiliser une politique plus stricte
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Authentification par clé SSH
            if use_key:
                # Gestion des clés protégées par mot de passe
                if key_password is None:
                    try:
                        # Tentative de chargement de la clé sans mot de passe
                        key = paramiko.RSAKey.from_private_key_file(key_path)
                        
                        # Connexion avec la clé chargée
                        client.connect(hostname=host, port=port, username=username, pkey=key)
                    except paramiko.ssh_exception.PasswordRequiredException:
                        # La clé est protégée par mot de passe
                        logging.info("La clé SSH est protégée par mot de passe")
                        
                        # Pour Docker, utiliser le mot de passe prédéfini "password"
                        key_password = "password"
                        logging.info("Utilisation du mot de passe: password")
                        
                        # Connexion avec la clé et son mot de passe
                        client.connect(hostname=host, port=port, username=username, 
                                      key_filename=key_path, passphrase=key_password)
                else:
                    # Connexion avec la clé et le mot de passe fourni
                    client.connect(hostname=host, port=port, username=username, 
                                  key_filename=key_path, passphrase=key_password)
                logging.info("Connecté avec authentification par clé SSH")
            else:
                # Authentification par mot de passe
                if password is None:
                    # Mot de passe par défaut si non spécifié
                    password = "root"
                client.connect(hostname=host, port=port, username=username, password=password)
                logging.info("Connecté avec authentification par mot de passe")
            
            # Création du client SFTP (Secure File Transfer Protocol)
            # SFTP est un protocole de transfert de fichiers sécurisé basé sur SSH
            logging.info("Création du client SFTP")
            sftp = client.open_sftp()
    
            # Transfert du fichier
            logging.info(f"Transfert du fichier de {temp_file_path} vers {remote_path}")
            sftp.put(temp_file_path, remote_path)
            logging.info("Transfert de fichier terminé")
    
            # Nettoyage du fichier temporaire chiffré
            if encrypt and temp_file_path != file_path:
                os.remove(temp_file_path)
                logging.info(f"Fichier temporaire {temp_file_path} supprimé")
                
            # Fermeture des connexions
            sftp.close()
            client.close()
            logging.info("Connexion fermée")
            return True
            
        # Gestion des erreurs d'authentification
        except paramiko.ssh_exception.AuthenticationException as e:
            logging.error(f"Échec d'authentification: {str(e)}")
            client.close()
            return False
            
        # Gestion des autres erreurs pendant le transfert
        except Exception as e:
            logging.error(f"Erreur lors du transfert de fichier: {str(e)}")
            client.close()
            return False
            
    # Gestion des erreurs de connexion générales
    except Exception as e:
        logging.error(f"Erreur de connexion: {str(e)}")
        return False

def retrieve_and_decrypt_file(remote_file_path, local_file_path, decryption_key=None, decryption_iv=None, 
                             host="172.20.0.2", port=2222, username="noahheraud",
                             use_key=False, key_path="/root/.ssh/id_rsa", password=None, key_password=None):
    """
    Récupère un fichier chiffré depuis le serveur distant et le déchiffre.
    
    Paramètres:
    - remote_file_path: Chemin du fichier distant à récupérer
    - local_file_path: Chemin local où sauvegarder le fichier déchiffré
    - decryption_key: Clé de déchiffrement (facultatif, utilise la clé globale par défaut)
    - decryption_iv: Vecteur d'initialisation pour le déchiffrement (facultatif, utilise l'iv global par défaut)
    - host, port, username, use_key, key_path, password, key_password: Paramètres de connexion SSH
    
    Retourne:
    - True si la récupération et le déchiffrement sont réussis, False sinon
    """
    try:
        logging.info(f"Connexion à {host}:{port} en tant que {username} pour récupérer {remote_file_path}")
        
        # Configuration de la connexion SSH
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Authentification
        if use_key:
            if key_password is None:
                try:
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                    client.connect(hostname=host, port=port, username=username, pkey=key)
                except paramiko.ssh_exception.PasswordRequiredException:
                    key_password = "password"
                    client.connect(hostname=host, port=port, username=username, 
                                  key_filename=key_path, passphrase=key_password)
            else:
                client.connect(hostname=host, port=port, username=username, 
                              key_filename=key_path, passphrase=key_password)
        else:
            if password is None:
                password = "root"
            client.connect(hostname=host, port=port, username=username, password=password)
        
        # Création du client SFTP
        sftp = client.open_sftp()
        
        # Création d'un fichier temporaire pour stocker le fichier chiffré
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_path = temp.name
        
        # Récupération du fichier chiffré
        logging.info(f"Récupération du fichier distant {remote_file_path}")
        sftp.get(remote_file_path, temp_path)
        
        # Fermeture des connexions
        sftp.close()
        client.close()
        
        # Déchiffrement du fichier
        logging.info(f"Déchiffrement du fichier {temp_path}")
        decryption_key = key if decryption_key is None else decryption_key
        decryption_iv = iv if decryption_iv is None else decryption_iv
        
        with open(temp_path, 'rb') as f:
            ciphertext = f.read()
        
        # Utilisation de la fonction decrypt appropriée
        if local_file_path.endswith('.pdf'):
            plaintext_bin = decrypt_message_binary(ciphertext, decryption_key)
            if plaintext_bin is not None:
                with open(local_file_path, 'wb') as f:
                    f.write(plaintext_bin)
                logging.info(f"Fichier PDF déchiffré et sauvegardé dans {local_file_path}")
                os.remove(temp_path)
                return True
            else:
                logging.error("Échec du déchiffrement du PDF")
                os.remove(temp_path)
                return False
        else:
            plaintext = decrypt_message(ciphertext, decryption_key)
            if plaintext:
                with open(local_file_path, 'w') as f:
                    f.write(plaintext)
                logging.info(f"Fichier déchiffré et sauvegardé dans {local_file_path}")
                os.remove(temp_path)
                return True
            else:
                logging.error("Échec du déchiffrement")
                os.remove(temp_path)
                return False
    
    except Exception as e:
        logging.error(f"Erreur lors de la récupération et du déchiffrement: {str(e)}")
        return False

# Point d'entrée du programme lorsqu'il est exécuté directement
if __name__ == "__main__":
    # copie du fichier rapport_total.pdf dans le dossier Transfert
    # Vérification de l'existence du fichier rapport_total.pdf
    if not os.path.exists("rapport_total.pdf"):
        logging.error("Le fichier rapport_total.pdf n'existe pas. Veuillez le créer avant d'exécuter le script.")
        exit(1)

    # Étape 1: Signature du fichier en clair
    logging.info("ÉTAPE 1: Signature du fichier rapport_total.pdf")
    sign_for_send("rapport_total.pdf")
    logging.info("Fichier signé avec succès")

    # Préparation des clés SSH
    ssh_dir = "/root/.ssh"
    if not os.path.exists(ssh_dir):
        os.makedirs(ssh_dir)
    
    # Copie des clés du montage en lecture seule vers un emplacement où on peut modifier les permissions
    shutil.copy("/tmp/ssh_keys/id_rsa", "/root/.ssh/id_rsa")
    shutil.copy("/tmp/ssh_keys/id_rsa.pub", "/root/.ssh/id_rsa.pub")
    
    # Définition des permissions correctes
    os.chmod("/root/.ssh/id_rsa", 0o600)
    os.chmod("/root/.ssh/id_rsa.pub", 0o644)
    
    # Configuration de l'hôte
    with open("/etc/hosts", "a") as f:
        f.write("172.20.0.2 ssh_server\n")
    
    # Étape 2: Préparation du chiffrement et sauvegarde des clés
    logging.info("ÉTAPE 2: Préparation du chiffrement")
    enc_key_path = "encryption_key.bin"
    enc_iv_path = "encryption_iv.bin"
    with open(enc_key_path, "wb") as f:
        f.write(key)
    with open(enc_iv_path, "wb") as f:
        f.write(iv)
    logging.info(f"Clés de chiffrement sauvegardées dans {enc_key_path} et {enc_iv_path}")
    
    # Étape 3: Chiffrement et transfert des fichiers
    logging.info("ÉTAPE 3: Chiffrement et transfert des fichiers")
    
    # Transférer le fichier chiffré
    result_encrypted = transfer_file("rapport_total.pdf", "/config/rapport_total_secure.enc", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password", encrypt=True)
    
    # Transfert des fichiers nécessaires au déchiffrement et à la vérification
    result_key = transfer_file(enc_key_path, "/config/encryption_key.bin", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password")
                
    result_iv = transfer_file(enc_iv_path, "/config/encryption_iv.bin", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password")
    
    result_sig = transfer_file("file_signature.sig", "/config/file_signature.sig", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password")
    
    result_pub = transfer_file("signature_public_key.pub", "/config/signature_public_key.pub", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password")
    
    # Vérification du résultat des transferts
    if result_encrypted and result_key and result_iv and result_sig and result_pub:
        logging.info("Transfert de tous les fichiers réussi")
    else:
        logging.error("Échec du transfert d'un ou plusieurs fichiers")
        exit(1)
    
    # Étape 4: Simulation de réception - Récupération et déchiffrement
    logging.info("ÉTAPE 4: Simulation de réception - Récupération et déchiffrement")
    
    # Chargement des clés de déchiffrement (normalement, on les récupérerait du serveur)
    with open(enc_key_path, "rb") as f:
        decryption_key = f.read()
    with open(enc_iv_path, "rb") as f:
        decryption_iv = f.read()
    
    # Récupération et déchiffrement du fichier
    decryption_result = retrieve_and_decrypt_file(
        remote_file_path="/config/rapport_total_secure.enc",
        local_file_path="received_rapport_total.pdf",
        decryption_key=decryption_key,
        decryption_iv=decryption_iv,
        use_key=True,
        key_path="/root/.ssh/id_rsa",
        key_password="password"
    )
    
    if not decryption_result:
        logging.error("Échec de la récupération et du déchiffrement")
        exit(1)
    
    # Étape 5: Vérification de l'intégrité par signature
    logging.info("ÉTAPE 5: Vérification de l'intégrité par signature")
    
    # Récupération de la signature et de la clé publique
    # Normalement, on les récupérerait du serveur, mais ici on utilise celles existantes
    public_key = load_public_key("signature_public_key.pub")
    
    if public_key:
        # Vérification de la signature avec la clé publique
        is_valid = verify_file_signature("received_rapport_total.pdf", "file_signature.sig", public_key)
        if is_valid:
            logging.info("✅ SUCCÈS: La signature du fichier PDF déchiffré est valide. L'intégrité est confirmée.")
            print("✅ SUCCÈS: La signature du fichier PDF déchiffré est valide. L'intégrité est confirmée.")
            
            # Information sur le fichier vérifié
            print("\n======== FICHIER PDF VÉRIFIÉ ========")
            try:
                file_size = os.path.getsize("received_rapport_total.pdf")
                print(f"Fichier PDF déchiffré: received_rapport_total.pdf")
                print(f"Taille du fichier: {file_size} octets")
                print("Le fichier PDF a été déchiffré et vérifié avec succès.")
            except Exception as e:
                print(f"Erreur lors de la vérification du fichier: {str(e)}")
            print("=====================================\n")
        else:
            logging.error("❌ ÉCHEC: La signature du fichier déchiffré est invalide. Possible altération!")
            print("❌ ÉCHEC: La signature du fichier déchiffré est invalide. Possible altération!")
    else:
        logging.error("Impossible de vérifier la signature: clé publique non disponible")
        print("Impossible de vérifier la signature: clé publique non disponible")