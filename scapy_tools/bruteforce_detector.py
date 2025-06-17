#!/usr/bin/env python3
"""
Détecteur d'attaques par force brute utilisant Scapy
Ce script surveille le trafic réseau et détecte les tentatives d'attaque par force brute
"""

from scapy.all import *
import time
from collections import defaultdict
import threading

class BruteForceDetector:
    def __init__(self, alert_callback=None):
        # Fonction de callback pour les alertes
        self.alert_callback = alert_callback
        
        # Liste noire des IPs à ignorer (pas de détection d'attaque)
        self.blacklisted_ips = {
            # DNS publics
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS secondaire
            '1.1.1.1',      # Cloudflare DNS
            '1.0.0.1',      # Cloudflare DNS secondaire
            '9.9.9.9',      # Quad9 DNS
            '208.67.222.222',  # OpenDNS
            '208.67.220.220',  # OpenDNS
            # Services cloud populaires (AWS, Azure, GCP)
            '18.214.59.207',   # AWS (exemple de faux positif)
            # Ajoutez d'autres IPs légitimes selon vos besoins
        }
        
        # Dictionnaire pour suivre les tentatives de connexion par IP source
        self.connections = defaultdict(lambda: {
            'ssh_attempts': 0,
            'ftp_attempts': 0,
            'http_attempts': 0,
            'https_attempts': 0,
            'telnet_attempts': 0,
            'smtp_attempts': 0,
            'pop3_attempts': 0,
            'imap_attempts': 0,
            'rdp_attempts': 0,
            'total_attempts': 0,
            'first_seen': None,  # Sera défini au premier paquet
            'last_seen': None,   # Sera défini au premier paquet
            'connection_failures': 0,
            'successful_connections': 0
        })
        
        # Fenêtre de temps pour la détection (en secondes)
        self.time_window = 10  # 10 secondes
        
        # Seuil principal de détection: 100 requêtes en 10 secondes
        self.main_threshold = 100    # Tentatives totales en 10 secondes
        
        # Seuils de détection pour différents services
        self.ssh_threshold = 10      # Tentatives SSH
        self.ftp_threshold = 15      # Tentatives FTP
        self.http_threshold = 50     # Tentatives HTTP/HTTPS
        self.general_threshold = 20  # Tentatives générales sur d'autres ports
        
        # Ports de services courants
        self.service_ports = {
            22: 'SSH',
            21: 'FTP',
            80: 'HTTP',
            443: 'HTTPS',
            23: 'Telnet',
            25: 'SMTP',
            110: 'POP3',
            143: 'IMAP',
            3389: 'RDP',
            993: 'IMAPS',
            995: 'POP3S',
            587: 'SMTP-TLS',
            465: 'SMTPS',
            53: 'DNS',
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            5984: 'CouchDB',
            27017: 'MongoDB'
        }
        
        # Thread pour le nettoyage périodique
        self.cleanup_thread = None
        self.running = True
        
    def start_cleanup_thread(self):
        """Démarre le thread de nettoyage des anciennes connexions"""
        def cleanup():
            while self.running:
                current_time = time.time()
                expired_ips = []
                
                for ip, data in self.connections.items():
                    if current_time - data['last_seen'] > self.time_window:
                        expired_ips.append(ip)
                
                for ip in expired_ips:
                    del self.connections[ip]
                
                time.sleep(60)  # Nettoyage toutes les minutes
        
        self.cleanup_thread = threading.Thread(target=cleanup, daemon=True)
        self.cleanup_thread.start()
    
    def add_to_blacklist(self, ip):
        """Ajoute une IP à la liste noire"""
        self.blacklisted_ips.add(ip)
        print(f"✅ IP {ip} ajoutée à la liste noire")
    
    def remove_from_blacklist(self, ip):
        """Supprime une IP de la liste noire"""
        if ip in self.blacklisted_ips:
            self.blacklisted_ips.remove(ip)
            print(f"✅ IP {ip} supprimée de la liste noire")
        else:
            print(f"⚠️  IP {ip} n'est pas dans la liste noire")
    
    def is_blacklisted(self, ip):
        """Vérifie si une IP est dans la liste noire"""
        return ip in self.blacklisted_ips
    
    def analyze_packet(self, packet, packet_time=None):
        """Analyse un paquet pour détecter des patterns de force brute"""
        # Utiliser le timestamp du paquet si fourni, sinon le temps actuel
        if packet_time is None:
            if hasattr(packet, 'time'):
                current_time = packet.time
            else:
                current_time = time.time()
        else:
            current_time = packet_time
        
        # Analyser seulement les paquets TCP
        if packet.haslayer(TCP) and packet.haslayer(IP):
            self.analyze_tcp_connection(packet, current_time)
    
    def analyze_tcp_connection(self, packet, current_time):
        """Analyse les connexions TCP pour détecter les attaques par force brute"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        
        # Ignorer le trafic local
        if (src_ip.startswith('127.') or src_ip.startswith('192.168.') or 
            src_ip.startswith('10.') or src_ip.startswith('172.')):
            return
        
        # Ignorer les IPs de la liste noire
        if self.is_blacklisted(src_ip):
            return
        
        # Mettre à jour les statistiques
        conn_data = self.connections[src_ip]
        
        # Initialiser les timestamps si c'est la première fois
        if conn_data['first_seen'] is None:
            conn_data['first_seen'] = current_time
        if conn_data['last_seen'] is None:
            conn_data['last_seen'] = current_time
        
        conn_data['last_seen'] = current_time
        conn_data['total_attempts'] += 1
        
        # Identifier le service et compter les tentatives
        service = self.service_ports.get(dst_port, 'Unknown')
        
        # Détecter les tentatives de connexion (paquets SYN)
        if tcp_flags & 0x02:  # SYN flag
            if dst_port == 22:  # SSH
                conn_data['ssh_attempts'] += 1
            elif dst_port == 21:  # FTP
                conn_data['ftp_attempts'] += 1
            elif dst_port == 80:  # HTTP
                conn_data['http_attempts'] += 1
            elif dst_port == 443:  # HTTPS
                conn_data['https_attempts'] += 1
            elif dst_port == 23:  # Telnet
                conn_data['telnet_attempts'] += 1
            elif dst_port in [25, 587, 465]:  # SMTP
                conn_data['smtp_attempts'] += 1
            elif dst_port in [110, 995]:  # POP3
                conn_data['pop3_attempts'] += 1
            elif dst_port in [143, 993]:  # IMAP
                conn_data['imap_attempts'] += 1
            elif dst_port == 3389:  # RDP
                conn_data['rdp_attempts'] += 1
        
        # Détecter les échecs de connexion (RST flag)
        elif tcp_flags & 0x04:  # RST flag
            conn_data['connection_failures'] += 1
        
        # Détecter les connexions réussies (ACK flag sans SYN)
        elif tcp_flags & 0x10 and not (tcp_flags & 0x02):  # ACK without SYN
            conn_data['successful_connections'] += 1
        
        # Vérifier si c'est une attaque par force brute
        self.check_bruteforce_patterns(src_ip, conn_data, dst_port, service, current_time)
    
    def check_bruteforce_patterns(self, src_ip, conn_data, current_port, service, current_time):
        """Vérifie les patterns d'attaque par force brute"""
        duration = current_time - conn_data['first_seen']
        
        # Calculer le taux de succès pour éviter les faux positifs
        total_conn_attempts = conn_data['connection_failures'] + conn_data['successful_connections']
        success_rate = 0
        if total_conn_attempts > 0:
            success_rate = conn_data['successful_connections'] / total_conn_attempts
        
        # Pattern principal: Plus de 100 requêtes en 10 secondes
        # MAIS ignorer si le taux de succès est trop élevé (> 50%) car c'est probablement légitime
        if (conn_data['total_attempts'] >= self.main_threshold and 
            duration <= self.time_window and 
            success_rate < 0.5):  # Taux de succès < 50%
            self.alert_bruteforce(src_ip, conn_data, 'High-Volume-Attack', current_port, 'total_attempts', current_time)
            return
        
        # Patterns alternatifs (pour les attaques plus lentes mais ciblées)
        # Appliquer la logique de taux de succès aux patterns spécifiques aussi
        
        # Pattern 1: Trop de tentatives SSH (mais pas si trop de succès)
        if (conn_data['ssh_attempts'] >= self.ssh_threshold and 
            success_rate < 0.3):  # Plus strict pour SSH
            self.alert_bruteforce(src_ip, conn_data, 'SSH', current_port, 'ssh_attempts', current_time)
        
        # Pattern 2: Trop de tentatives FTP (mais pas si trop de succès)
        elif (conn_data['ftp_attempts'] >= self.ftp_threshold and 
              success_rate < 0.3):  # Plus strict pour FTP
            self.alert_bruteforce(src_ip, conn_data, 'FTP', current_port, 'ftp_attempts', current_time)
        
        # Pattern 3: Trop de tentatives HTTP/HTTPS (mais pas si trop de succès)
        elif ((conn_data['http_attempts'] + conn_data['https_attempts']) >= self.http_threshold and 
              success_rate < 0.6):  # Plus permissif pour HTTP car peut être légitime
            self.alert_bruteforce(src_ip, conn_data, 'HTTP/HTTPS', current_port, 'http_attempts', current_time)
        
        # Pattern 4: Taux d'échec élevé
        elif (conn_data['connection_failures'] > 10 and 
              conn_data['connection_failures'] > conn_data['successful_connections'] * 3):
            self.alert_bruteforce(src_ip, conn_data, 'High-Failure-Rate', current_port, 'connection_failures', current_time)
        
        # Pattern 5: Autres services
        elif (conn_data['telnet_attempts'] >= 10 or 
              conn_data['smtp_attempts'] >= 15 or
              conn_data['pop3_attempts'] >= 15 or
              conn_data['imap_attempts'] >= 15 or
              conn_data['rdp_attempts'] >= 10):
            service_type = 'Telnet' if conn_data['telnet_attempts'] >= 10 else \
                          'SMTP' if conn_data['smtp_attempts'] >= 15 else \
                          'POP3' if conn_data['pop3_attempts'] >= 15 else \
                          'IMAP' if conn_data['imap_attempts'] >= 15 else 'RDP'
            self.alert_bruteforce(src_ip, conn_data, service_type, current_port, 'service_attempts', current_time)
    
    def alert_bruteforce(self, src_ip, conn_data, attack_type, current_port, metric, current_time):
        """Alerte pour une attaque par force brute détectée"""
        
        # Si un callback est défini, l'utiliser
        if self.alert_callback:
            self.alert_callback(attack_type, src_ip, conn_data, current_port)
        else:
            # Sinon, afficher l'alerte directement
            print(f"\n🚨 ALERTE - ATTAQUE FORCE BRUTE DÉTECTÉE!")
            print(f"   Type: {attack_type}")
            print(f"   IP Source: {src_ip}")
            print(f"   Port actuel: {current_port}")
            print(f"   Tentatives SSH: {conn_data['ssh_attempts']}")
            print(f"   Tentatives FTP: {conn_data['ftp_attempts']}")
            print(f"   Tentatives HTTP/HTTPS: {conn_data['http_attempts'] + conn_data['https_attempts']}")
            print(f"   Tentatives totales: {conn_data['total_attempts']}")
            print(f"   Échecs de connexion: {conn_data['connection_failures']}")
            print(f"   Connexions réussies: {conn_data['successful_connections']}")
            print(f"   Durée: {current_time - conn_data['first_seen']:.2f} secondes")
            print(f"   Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time))}")
            print("-" * 60)
        
        # Marquer cette IP comme alertée pour éviter les doublons
        conn_data[f'{attack_type}_alerted'] = True
    
    def get_stats(self):
        """Retourne les statistiques actuelles"""
        return {
            'monitored_ips': len(self.connections),
            'total_ssh_attempts': sum(data['ssh_attempts'] for data in self.connections.values()),
            'total_ftp_attempts': sum(data['ftp_attempts'] for data in self.connections.values()),
            'total_http_attempts': sum(data['http_attempts'] + data['https_attempts'] for data in self.connections.values()),
            'total_connection_failures': sum(data['connection_failures'] for data in self.connections.values()),
            'blacklisted_ips': list(self.blacklisted_ips)
        }
    
    def stop(self):
        """Arrête le détecteur"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join()

def main():
    """Fonction principale pour test standalone"""
    print("🔍 Détecteur d'attaques par force brute - Démarrage...")
    print("=" * 60)
    print("Ce script utilise Scapy pour détecter les attaques par force brute.")
    print("Services surveillés:")
    print("  - SSH (port 22)")
    print("  - FTP (port 21)")
    print("  - HTTP/HTTPS (ports 80/443)")
    print("  - Telnet (port 23)")
    print("  - SMTP (ports 25/587/465)")
    print("  - POP3/IMAP (ports 110/143/993/995)")
    print("  - RDP (port 3389)")
    print("=" * 60)
    
    # Créer le détecteur
    detector = BruteForceDetector()
    detector.start_cleanup_thread()
    
    try:
        print(f"🎯 Surveillance active - Seuils de détection:")
        print(f"   PRINCIPAL: {detector.main_threshold} requêtes en {detector.time_window} secondes")
        print(f"   SSH: {detector.ssh_threshold} tentatives")
        print(f"   FTP: {detector.ftp_threshold} tentatives")
        print(f"   HTTP/HTTPS: {detector.http_threshold} tentatives")
        print("=" * 60)
        print("Appuyez sur Ctrl+C pour arrêter...\n")
        
        # Démarrer la capture
        sniff(filter="tcp", prn=detector.analyze_packet, store=0)
        
    except KeyboardInterrupt:
        print(f"\n\nArrêt demandé par l'utilisateur...")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
    finally:
        detector.stop()
        stats = detector.get_stats()
        print(f"\n📊 Statistiques finales:")
        print(f"   IPs surveillées: {stats['monitored_ips']}")
        print(f"   Tentatives SSH: {stats['total_ssh_attempts']}")
        print(f"   Tentatives FTP: {stats['total_ftp_attempts']}")
        print(f"   Tentatives HTTP: {stats['total_http_attempts']}")
        print(f"   Échecs totaux: {stats['total_connection_failures']}")
        print("Au revoir!")

if __name__ == "__main__":
    main() 