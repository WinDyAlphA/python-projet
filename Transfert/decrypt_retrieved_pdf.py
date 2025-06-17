#!/usr/bin/env python3
"""
decrypt_retrieved_pdf.py

Déchiffre le fichier PDF récupéré par `retrieve_enc_from_docker.py`.
Par défaut le script s'attend à trouver :
  • retrieved_encrypted/rapport_total_secure.enc
  • retrieved_encrypted/encryption_key.bin
  • retrieved_encrypted/encryption_iv.bin

Il produit :
  • decrypted_files/rapport_total_decrypted.pdf

Usage :
    python3 decrypt_retrieved_pdf.py [--enc ENC_FILE] [--key KEY_FILE] [--iv IV_FILE] [--out OUTPUT_PDF]
"""

import argparse
import os
import logging
from typing import Optional

import chiffrement  # notre module local
from chiffrement import decrypt_message_binary
from signature import load_public_key, verify_file_signature  # ajout pour la vérification de signature

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def read_bin(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Impossible de lire {path}: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description="Déchiffre le PDF récupéré depuis Docker et vérifie son intégrité.")
    parser.add_argument("--enc", dest="enc_file", default="retrieved_files/rapport_total_secure.enc", help="Fichier PDF chiffré")
    parser.add_argument("--key", dest="key_file", default="retrieved_files/encryption_key.bin", help="Fichier contenant la clé AES")
    parser.add_argument("--iv", dest="iv_file", default="retrieved_files/encryption_iv.bin", help="Fichier contenant le vecteur IV")
    parser.add_argument("--out", dest="out_pdf", default="decrypted_files/rapport_total_decrypted.pdf", help="Chemin du PDF déchiffré")
    parser.add_argument("--sig", dest="sig_file", default="retrieved_files/file_signature.sig", help="Fichier de signature pour vérifier l'intégrité")
    parser.add_argument("--pub", dest="pub_key_file", default="retrieved_files/signature_public_key.pub", help="Clé publique de vérification de signature")
    args = parser.parse_args()

    # Lecture des fichiers
    ciphertext = read_bin(args.enc_file)
    key_data = read_bin(args.key_file)
    iv_data = read_bin(args.iv_file)

    if None in (ciphertext, key_data, iv_data):
        logging.error("Lecture des fichiers impossible. Abandon.")
        return 1

    # Injecter le vecteur IV dans le module chiffrement
    chiffrement.iv = iv_data  # type: ignore

    logging.info("Déchiffrement en cours…")
    plaintext = decrypt_message_binary(ciphertext, key_data)
    if plaintext is None:
        logging.error("Échec du déchiffrement.")
        return 1

    # Création dossier sortie
    out_dir = os.path.dirname(args.out_pdf)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.out_pdf, "wb") as f:
        f.write(plaintext)
    logging.info(f"✅ PDF déchiffré et sauvegardé: {args.out_pdf}")

    # Vérification d'intégrité via la signature
    logging.info("Vérification de l'intégrité via la signature…")
    public_key = load_public_key(args.pub_key_file)
    if public_key is None:
        logging.error("Clé publique non disponible. Impossible de vérifier la signature.")
        print("❌ ÉCHEC: Clé publique non trouvée pour la vérification de signature.")
        return 1

    is_valid = verify_file_signature(args.out_pdf, args.sig_file, public_key)
    if is_valid:
        logging.info("✅ Signature valide. L'intégrité du fichier est confirmée.")
        print("✅ Signature valide. L'intégrité du fichier est confirmée.")
        return 0
    else:
        logging.error("❌ Signature invalide. Possible altération du fichier.")
        print("❌ ÉCHEC: Signature invalide. Possible altération du fichier.")
        return 1

if __name__ == "__main__":
    exit(main()) 