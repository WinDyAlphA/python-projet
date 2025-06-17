#!/usr/bin/env bash
#
# Automatisation de la mise en place, des tests et du nettoyage
# d'un environnement SFTP (serveur + client) dans Docker.
# ─────────────────────────────────────────────────────────────

set -euo pipefail

### Paramètres ################################################

# Répertoires locaux
KEY_DIR="./ssh_keys"
SERVER_DATA_DIR="./ssh_server_data"

# Clé / passphrase
KEY_FILE="${KEY_DIR}/id_rsa"
KEY_PUB_FILE="${KEY_DIR}/id_rsa.pub"
KEY_PASSPHRASE="password"
KEY_COMMENT="noahheraud@test.com"

# Conteneurs
CLIENT_CONTAINER="ssh_client"
SERVER_CONTAINER="ssh_server"

# Commande docker-compose (adapter si besoin)
COMPOSE_CMD="docker-compose"

# Hôte / port vus depuis le client
SERVER_HOSTNAME="ssh_server"
SERVER_IP="172.20.0.2"
SERVER_PORT=2222
SERVER_USER="noahheraud"

### Fonctions #################################################

prepare_environment() {
  echo "⏳  Préparation de l'environnement local…"

  mkdir -p "${KEY_DIR}" "${SERVER_DATA_DIR}"

  if [[ ! -f "${KEY_FILE}" ]]; then
    ssh-keygen -t rsa -b 4096 \
      -f "${KEY_FILE}" \
      -N "${KEY_PASSPHRASE}" \
      -C "${KEY_COMMENT}"
  else
    echo "✅  La clé SSH existe déjà (${KEY_FILE}) – étape ignorée."
  fi

  cp "${KEY_PUB_FILE}" "${SERVER_DATA_DIR}/ssh_pubkey"

  chmod 600 "${KEY_FILE}"
  chmod 644 "${KEY_PUB_FILE}" "${SERVER_DATA_DIR}/ssh_pubkey"

  echo "✅  Préparation terminée."
}

start_containers() {
  echo "⏳  Démarrage des conteneurs Docker…"
  ${COMPOSE_CMD} up -d
  docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
  echo "✅  Conteneurs lancés."
}

configure_client() {
  echo "⏳  Configuration du conteneur client…"

  docker exec "${CLIENT_CONTAINER}" bash -c "
    set -e
    apt-get update -qq && apt-get install -y -qq openssh-client sshpass python3-pip
    pip install --quiet paramiko

    mkdir -p /root/.ssh
    cp /tmp/ssh_keys/id_rsa /root/.ssh/id_rsa
    cp /tmp/ssh_keys/id_rsa.pub /root/.ssh/id_rsa.pub
    chmod 600 /root/.ssh/id_rsa
    chmod 644 /root/.ssh/id_rsa.pub

    grep -q '${SERVER_HOSTNAME}' /etc/hosts || \
      echo '${SERVER_IP} ${SERVER_HOSTNAME}' >> /etc/hosts
  "
  echo "✅  Client configuré."
}

test_connection() {
  echo "⏳  Test de la connexion SSH (passphrase envoyée automatiquement)…"

  docker exec "${CLIENT_CONTAINER}" bash -c "
    sshpass -P passphrase -p '${KEY_PASSPHRASE}' \
      ssh -o StrictHostKeyChecking=no \
          -i /root/.ssh/id_rsa \
          ${SERVER_USER}@${SERVER_HOSTNAME} -p ${SERVER_PORT} 'echo Connexion réussie && exit'
  "
  echo "✅  Connexion testée avec succès."
}

run_transfer_script() {
  echo "⏳  Exécution du script Python de transfert…"
  docker exec "${CLIENT_CONTAINER}" bash -c "
    cd /app && python paraminko_transfert_docker.py
  "
  echo "✅  Script de transfert terminé."
}

decrypt_step() {
  echo "⏳  Récupération puis déchiffrement du PDF…"
  python3 Transfert/retrieve_enc_from_docker.py
  python3 Transfert/decrypt_retrieved_pdf.py
  echo "✅  PDF déchiffré."
}

cleanup_all() {
  echo "🧹  Nettoyage complet (conteneurs + fichiers)…"
  ${COMPOSE_CMD} down
  rm -rf "${KEY_DIR}" "${SERVER_DATA_DIR}"
  echo "✅  Nettoyage terminé."
}

### Dispatcher ###############################################

usage() {
  cat <<EOF
Usage: $0 {prepare|start|configure|test|transfer|decrypt|cleanup|nocleanup|all}

  prepare    : génère les clés et prépare les répertoires locaux
  start      : lance docker-compose
  configure  : installe et configure le client SSH
  test       : vérifie la connexion SSH
  transfer   : exécute le script Python de transfert
  decrypt    : récupère et déchiffre le PDF
  cleanup    : arrête et supprime les conteneurs + données temporaires
  nocleanup  : exécute les étapes 1 à 5 (prepare → transfer) sans nettoyage
  all        : exécute toutes les étapes dans l'ordre (prepare → decrypt)
EOF
  exit 1
}

main() {
  [[ $# -eq 1 ]] || usage
  case "$1" in
    prepare)   prepare_environment ;;
    start)     start_containers ;;
    configure) configure_client ;;
    test)      test_connection ;;
    transfer)  run_transfer_script ;;
    decrypt)   decrypt_step ;;
    cleanup)   cleanup_all ;;
    nocleanup)
      prepare_environment
      start_containers
      configure_client
      test_connection
      ;;
    all)
      prepare_environment
      start_containers
      configure_client
      test_connection
      run_transfer_script
      decrypt_step
      ;;
    *) usage ;;
  esac
}

main "$@" 