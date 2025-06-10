#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Configuration de l'environnement de test SFTP ===${NC}"

# Création des répertoires nécessaires
mkdir -p ssh_keys
mkdir -p ssh_server_data

echo -e "${YELLOW}Génération d'une paire de clés SSH protégée par mot de passe...${NC}"

# Génération de la clé SSH avec mot de passe
ssh-keygen -t rsa -b 4096 -f ssh_keys/id_rsa -N "password" -C "noahheraud@test.com"

# Copie de la clé publique pour le serveur SSH
cp ssh_keys/id_rsa.pub ssh_server_data/ssh_pubkey

echo -e "${GREEN}Configuration des permissions...${NC}"
chmod 600 ssh_keys/id_rsa
chmod 644 ssh_keys/id_rsa.pub
chmod 644 ssh_server_data/ssh_pubkey

# Modification du script Python pour utiliser les paramètres Docker
echo -e "${YELLOW}Création d'une version adaptée pour Docker du script Python...${NC}"
cp Transfert/paraminko_transfert.py Transfert/paraminko_transfert_docker.py

# Remplacer les paramètres dans le fichier pour Docker
sed -i.bak "s/host=\"143.110.170.33\"/host=\"172.20.0.2\"/" Transfert/paraminko_transfert_docker.py
sed -i.bak "s/port=22/port=2222/" Transfert/paraminko_transfert_docker.py
sed -i.bak "s/key_path=\"\/Users\/noahheraud\/.ssh\/digitalocean\"/key_path=\"\/root\/.ssh\/id_rsa\"/" Transfert/paraminko_transfert_docker.py
rm Transfert/paraminko_transfert_docker.py.bak

echo -e "${GREEN}Configuration terminée !${NC}"
echo -e "${YELLOW}Pour lancer l'environnement Docker :${NC} docker-compose up -d"
echo -e "${YELLOW}Mot de passe de la clé SSH :${NC} password" 