import paramiko
import os
import logging
import getpass
import shutil

# Configuration du système de journalisation
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def transfer_file(file_path, remote_path, host="172.20.0.2", port=2222, username="noahheraud", 
                 use_key=False, key_path="/root/.ssh/id_rsa", password=None, key_password=None):    
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
    """
    try:
        logging.info(f"Connexion à {host}:{port} en tant que {username}")
        logging.info(f"Méthode d'authentification: {'Clé SSH' if use_key else 'Mot de passe'}")
        
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
            logging.info(f"Transfert du fichier de {file_path} vers {remote_path}")
            sftp.put(file_path, remote_path)
            logging.info("Transfert de fichier terminé")
    
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


# Point d'entrée du programme lorsqu'il est exécuté directement
if __name__ == "__main__":
    # Création d'un fichier de test si nécessaire
    if not os.path.exists("test.txt"):
        with open("test.txt", "w") as f:
            f.write("Ceci est un fichier de test")
        logging.info("Fichier test.txt créé pour les tests")

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
    
    # Exemple d'utilisation avec authentification par clé SSH protégée par mot de passe
    result = transfer_file("test.txt", "/config/ceciestunfichier.txt", 
                use_key=True, key_path="/root/.ssh/id_rsa", key_password="password")
    
    # Vérification du résultat
    if result:
        logging.info("Transfert de fichier réussi")
    else:
        logging.error("Échec du transfert de fichier")