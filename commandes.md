# Commandes pour configurer et tester l'environnement SFTP avec clé SSH

## 1. Préparation de l'environnement

```bash
# Créer les répertoires nécessaires
mkdir -p ssh_keys
mkdir -p ssh_server_data

# Générer une paire de clés SSH protégée par mot de passe
ssh-keygen -t rsa -b 4096 -f ssh_keys/id_rsa -N "password" -C "noahheraud@test.com"

# Copier la clé publique pour le serveur SSH
cp ssh_keys/id_rsa.pub ssh_server_data/ssh_pubkey

# Configurer les permissions des fichiers
chmod 600 ssh_keys/id_rsa
chmod 644 ssh_keys/id_rsa.pub
chmod 644 ssh_server_data/ssh_pubkey
```

## 2. Lancement des conteneurs Docker

```bash
# Démarrer les conteneurs avec docker-compose
docker-compose up -d

# Vérifier que les conteneurs sont en cours d'exécution
docker ps
```

## 3. Configuration du client SSH

```bash
# Se connecter au conteneur client
docker exec -it ssh_client bash

# Dans le conteneur client, installer les dépendances
apt-get update
apt-get install -y openssh-client
pip install paramiko

# Créer le répertoire SSH
mkdir -p /root/.ssh

# Copier les clés du montage en lecture seule vers un emplacement avec permissions d'écriture
cp /tmp/ssh_keys/id_rsa /root/.ssh/id_rsa
cp /tmp/ssh_keys/id_rsa.pub /root/.ssh/id_rsa.pub

# Définir les permissions correctes
chmod 600 /root/.ssh/id_rsa
chmod 644 /root/.ssh/id_rsa.pub

# Ajouter l'entrée du serveur dans le fichier hosts
echo "172.20.0.2 ssh_server" >> /etc/hosts

# Quitter le conteneur client
exit
```

## 4. Test de la connexion SSH

```bash
# Tester la connexion SSH depuis le client vers le serveur
docker exec -it ssh_client ssh -i /root/.ssh/id_rsa noahheraud@ssh_server -p 2222

# Quand il vous demande le mot de passe de la clé, entrez "password"
# Puis quittez la session SSH
exit
```

## 5. Exécution du script de transfert SFTP

```bash
# Exécuter le script Python pour le transfert de fichier
docker exec -it ssh_client bash -c "cd /app && python paraminko_transfert_docker.py"
```

## 6. Vérification du transfert

```bash
# Vérifier que le fichier a bien été transféré sur le serveur
docker exec -it ssh_server bash -c "ls -la /config/ceciestunfichier.txt"

# Afficher le contenu du fichier transféré
docker exec -it ssh_server bash -c "cat /config/ceciestunfichier.txt"
```

## 7. Nettoyage (optionnel)

```bash
# Arrêter et supprimer les conteneurs
docker-compose down

# Supprimer les données générées
rm -rf ssh_keys/ ssh_server_data/
``` 