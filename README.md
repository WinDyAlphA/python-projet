# Projet : Développement d'un Outil d'Audit de Sécurité avec Transfert Sécurisé des Rapports

## Objectif Global du Projet

Vous devrez développer un outil Python qui :
* Scanne les ports ouverts d'une machine cible.
* Analyse le trafic réseau pour détecter des anomalies.
* Identifie des vulnérabilités web courantes.
* Génère un rapport structuré.
* Sécurise le rapport avec chiffrement et signature numérique.
* Transfère le rapport vers un serveur distant via SSH.

## Répartition des Séances possible

### Séance 1 : Fondations en Cryptographie et Connexions SSH (Basé sur "Séance 1.pdf")

#### Objectifs :
* Comprendre les principes fondamentaux de la cryptographie symétrique (AES) et asymétrique (RSA).
* Savoir générer des clés cryptographiques symétriques avec cryptography.
* Savoir générer une paire de clés RSA (publique et privée) avec cryptography.
* Comprendre le concept de signature numérique.
* Se familiariser avec la bibliothèque Paramiko pour établir des connexions SSH.
* Apprendre à configurer une politique pour les clés d'hôte manquantes avec Paramiko.
* Introduire le transfert de fichiers sécurisé via SFTP avec Paramiko.
* Définir le planning initial et la répartition des tâches.

#### Activités :
* Révision des concepts de cryptographie symétrique (AES) et asymétrique (RSA).
* Exercices pratiques de génération de clés AES aléatoires avec `os.urandom(32)`.
* Exercices pratiques de génération de clés RSA publique et privée avec `rsa.generate_private_key()`.
* Exercices de signature numérique d'un message avec la clé privée et de vérification avec la clé publique.
* Introduction à la création d'un objet SSHClient et à la configuration de `set_missing_host_key_policy`.
* Premier aperçu de l'établissement d'une connexion SSH (vers un serveur fictif ou local pour test).
* Introduction à l'utilisation de `paramiko.Transport` et `paramiko.SFTPClient` pour le transfert de fichiers.
* Discussion sur la manière dont la cryptographie sera utilisée pour sécuriser le rapport.

### Séance 2 : Analyse de Trafic Réseau et Détection d'Intrusions de Base (Basé sur "Séance 2.pdf", "Séance 3.pdf" et "Séance 4.pdf")

#### Objectifs :
* Apprendre à installer et utiliser Scapy pour la capture et l'analyse de paquets réseau.
* Savoir capturer des paquets simples et filtrer des paquets spécifiques (ex: ICMP).
* Identifier des patterns de trafic anormaux comme des scans de ports rudimentaires.
* Comprendre le principe de la détection d'attaques SYN Flood.

#### Activités :
* Installation et test de Scapy.
* Exercices de capture et d'affichage de paquets réseau.
* Développement de fonctions en Python utilisant Scapy pour :
  * Compter les paquets par adresse IP source.
  * Détecter un nombre élevé de connexions vers différents ports depuis une même source (détection de scan de ports).
  * Identifier un nombre élevé de paquets SYN potentiellement indicatif d'une attaque SYN Flood.
* Mise à jour du planning et adaptation de la répartition des tâches.

### Séance 3 : Sécurité Web et Scan de Vulnérabilités Simples (Basé sur "Séance 6.pdf")

#### Objectifs :
* Comprendre les vulnérabilités web courantes comme l'injection SQL et le Cross-Site Scripting (XSS).
* Apprendre à effectuer des requêtes HTTP GET et POST avec la bibliothèque requests.
* Développer des techniques de base pour identifier des vulnérabilités potentielles en envoyant des payloads spécifiques dans les paramètres d'URL.
* Collecter les URLs d'un site web à l'aide de requests et BeautifulSoup (si nécessaire, bien que non explicitement dans "Séance 6.pdf", c'est une pratique courante pour le crawling).

#### Activités :
* Révision des concepts de sécurité web et des principales menaces.
* Installation et utilisation de la bibliothèque requests pour effectuer des requêtes HTTP.
* Implémentation de fonctions pour tester des URLs cibles avec des payloads d'injection SQL simples et des scripts XSS basiques.
* Discussion sur la manière de construire un rapport structuré des résultats de l'audit.

### Séance 4 : Intégration, Sécurisation du Rapport et Envoi via SSH (Basé sur les séances précédentes et "Séance 7.pdf" pour l'automatisation)

#### Objectifs :
* Intégrer les fonctionnalités de scan réseau et web dans un outil cohérent.
* Générer un rapport structuré des résultats de l'audit, incluant les ports ouverts, les anomalies réseau détectées et les potentielles vulnérabilités web identifiées.
* Implémenter le chiffrement du rapport en utilisant l'algorithme AES avec la bibliothèque cryptography. Une clé symétrique sera générée pour chaque rapport.
* Implémenter la signature numérique du rapport chiffré en utilisant la clé privée RSA générée lors de la première séance avec la bibliothèque cryptography.
* Établir une connexion SSH vers un serveur distant à l'aide de Paramiko.
* Transférer de manière sécurisée le rapport chiffré et signé vers le serveur distant via SFTP.
* Préparer la présentation pour la séance de soutenance (planning, répartition des tâches, outils, difficultés, démonstration).

#### Activités :
* Assemblage des modules de scan réseau et web.
* Création d'une fonction pour générer le rapport (format texte, JSON, etc.).
* Implémentation des fonctions `encrypt_message` et `decrypt_message` (ou similaires adaptées au fichier rapport) en utilisant AES.
* Implémentation de la fonction de signature du rapport chiffré en utilisant la clé privée RSA.
* Implémentation de la connexion SSH avec Paramiko en utilisant les informations d'identification nécessaires (adresse IP, nom d'utilisateur, mot de passe ou clé privée). Il est important de noter que la gestion sécurisée des informations d'identification SSH est cruciale mais pourrait être simplifiée pour ce projet pédagogique en utilisant des informations de test.
* Utilisation de `paramiko.SFTPClient` pour transférer le fichier du rapport chiffré et signé vers le serveur distant.
* Préparation des slides de présentation, en détaillant l'ensemble du processus, y compris les étapes de chiffrement, de signature et de transfert sécurisé.

### Séance 5 : Soutenance des Projets (15 minutes par groupe)

#### Format : 
Chaque binôme ou trinôme présentera son projet à l'aide de supports visuels (slides PowerPoint ou autre).

#### Contenu de la Présentation (15 minutes) :
* **Introduction et Planning (1-2 minutes)** : Présentation des membres, du titre, et rappel du planning.
* **Répartition des Tâches (2-3 minutes)** : Explication de la division du travail.
* **Gestion du Temps (1-2 minutes)** : Bilan de la gestion du temps.
* **Outils Utilisés (1-2 minutes)** : Présentation des bibliothèques Python (cryptography, socket, scapy, requests, Paramiko, et potentiellement BeautifulSoup). Justification de leur choix.
* **Difficultés Rencontrées (2-3 minutes)** : Discussion des obstacles et des solutions apportées.
* **Fonctionnement de l'Outil (2-3 minutes)** : Explication du fonctionnement global, en mettant l'accent sur le processus de scan, de génération du rapport, de chiffrement, de signature et d'envoi sécurisé via SSH.
* **Démonstration (2-3 minutes)** : Courte démonstration de l'outil, illustrant les différentes étapes, y compris la tentative d'envoi du rapport sécurisé (même si un serveur distant n'est pas réellement configuré pour la réception, la démonstration du processus de chiffrement, de signature et de tentative de connexion SSH/SFTP est essentielle).
* **Conclusion (0-1 minute)** : Bilan et perspectives.

## Livrables pour la Soutenance

* **Code Source du Projet** : L'ensemble des scripts Python développés.
* **Exemple de Rapport Généré** : Un exemple du rapport d'audit.
* **Exemple de Rapport Chiffré et Signé (si possible)** : Un exemple du fichier qui serait envoyé via SSH.
* **Présentation Slides** : Un fichier de présentation couvrant les points mentionnés.