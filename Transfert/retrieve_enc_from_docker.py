#!/usr/bin/env python3
"""
retrieve_enc_from_docker.py

Récupère le fichier PDF chiffré (rapport_total_secure.enc) depuis le conteneur
Docker SSH et le sauvegarde localement avec le même nom.
"""

import os
import subprocess
import logging

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_docker_available() -> bool:
    """Vérifie la disponibilité de Docker sur la machine hôte."""
    try:
        subprocess.run(["docker", "--version"], check=True, capture_output=True, text=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        logging.error("Docker n'est pas disponible. Veuillez installer et démarrer Docker.")
        return False

def auto_detect_container(image_keywords=None):
    """Tente de détecter automatiquement le conteneur SSH basé sur l'image."""
    if image_keywords is None:
        image_keywords = ["ssh_server", "openssh-server"]
    for keyword in image_keywords:
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", f"ancestor={keyword}", "--format", "{{.ID}}"],
                check=True, capture_output=True, text=True,
            )
            container_ids = [cid for cid in result.stdout.strip().split("\n") if cid]
            if container_ids:
                cid = container_ids[0]
                logging.info(f"Conteneur SSH détecté automatiquement: {cid} (image contient '{keyword}')")
                return cid
        except subprocess.CalledProcessError:
            continue
    return None

def ask_container_id() -> str:
    """Demande à l'utilisateur de saisir l'ID du conteneur Docker."""
    print("\nListe des conteneurs en cours:")
    subprocess.run(["docker", "ps", "--format", "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}"], text=True)
    cid = input("\nEntrez l'ID du conteneur SSH: ").strip()
    return cid

def verify_container(cid: str) -> bool:
    """Vérifie qu'un conteneur existe et est en cours d'exécution."""
    try:
        result = subprocess.run(["docker", "ps", "-q", "--filter", f"id={cid}"], check=True, capture_output=True, text=True)
        return bool(result.stdout.strip())
    except subprocess.CalledProcessError:
        return False

def docker_cp(cid: str, remote: str, local: str) -> bool:
    """Copie un fichier du conteneur vers l'hôte à l'aide de docker cp."""
    try:
        subprocess.run(["docker", "cp", f"{cid}:{remote}", local], check=True)
        logging.info(f"Fichier copié depuis {remote} vers {local}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Erreur lors de docker cp: {e}")
        return False

def main():
    print("================ RÉCUPÉRATION PDF CHIFFRÉ ================")
    if not check_docker_available():
        return 1

    cid = auto_detect_container()
    if not cid:
        cid = ask_container_id()
        if not verify_container(cid):
            logging.error("ID de conteneur invalide ou conteneur non démarré.")
            return 1

    files_to_copy = {
        "/config/rapport_total_secure.enc": "rapport_total_secure.enc",
        "/config/encryption_key.bin": "encryption_key.bin",
        "/config/encryption_iv.bin": "encryption_iv.bin",
    }

    output_dir = "retrieved_files"
    os.makedirs(output_dir, exist_ok=True)

    success_all = True
    for remote, filename in files_to_copy.items():
        local_path = os.path.join(output_dir, filename)
        if not docker_cp(cid, remote, local_path):
            success_all = False
    
    if success_all:
        print("✅ Tous les fichiers ont été récupérés avec succès !")
        print(f"📂 Dossier : {output_dir}/")
        return 0
    else:
        print("❌ Un ou plusieurs fichiers n'ont pas pu être récupérés.")
        return 1

if __name__ == "__main__":
    exit(main()) 