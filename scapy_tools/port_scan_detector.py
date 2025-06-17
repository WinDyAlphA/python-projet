#!/usr/bin/env python3
"""
Détecteur de scan de ports utilisant Scapy
Ce script surveille le trafic réseau et détecte les tentatives de scan de ports
"""

from scapy.all import *
import time
from collections import defaultdict, deque
import threading
import sys
import signal

class PortScanDetector:
    def __init__(self):
        # Dictionnaire pour suivre les connexions par IP source
        self.connections = defaultdict(lambda: {
            'ports': set(),
            'syn_count': 0,
            'udp_count': 0,
            'first_seen': time.time(),
            'last_seen': time.time()
        })
        
        # Fenêtre de temps pour la détection (en secondes)
        self.time_window = 60
        
        # Seuils de détection
        self.syn_threshold = 100  # Nombre de paquets SYN pour déclencher l'alerte
        self.port_threshold = 100   # Nombre de ports différents pour déclencher l'alerte
        self.udp_threshold = 1000   # Nombre de paquets UDP pour déclencher l'alerte
        
        # Liste noire des IPs à ignorer (pas de détection d'attaque)
        self.blacklisted_ips = {
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS secondaire
            '1.1.1.1',      # Cloudflare DNS
            '1.0.0.1'       # Cloudflare DNS secondaire
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
                
                time.sleep(30)  # Nettoyage toutes les 30 secondes
        
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
    
    def analyze_packet(self, packet):
        """Analyse un paquet pour détecter des patterns de scan"""
        current_time = time.time()
        
        # Analyse des paquets TCP
        if packet.haslayer(TCP):
            self.analyze_tcp_packet(packet, current_time)
        
        # Analyse des paquets UDP
        elif packet.haslayer(UDP):
            self.analyze_udp_packet(packet, current_time)
    
    def analyze_tcp_packet(self, packet, current_time):
        """Analyse les paquets TCP pour détecter les scans SYN"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        
        # Ignorer le trafic local
        if src_ip.startswith('127.') or src_ip.startswith('192.168.') or src_ip.startswith('10.'):
            return
        
        # Ignorer les IPs de la liste noire
        if self.is_blacklisted(src_ip):
            return
        
        # Mettre à jour les statistiques
        conn_data = self.connections[src_ip]
        conn_data['last_seen'] = current_time
        conn_data['ports'].add(dst_port)
        
        # Détecter les paquets SYN (flags = 2)
        if tcp_flags & 0x02:  # SYN flag
            conn_data['syn_count'] += 1
            
            # Vérifier si c'est un scan SYN
            if (conn_data['syn_count'] >= self.syn_threshold or 
                len(conn_data['ports']) >= self.port_threshold):
                self.alert_tcp_scan(src_ip, conn_data, dst_port)
    
    def analyze_udp_packet(self, packet, current_time):
        """Analyse les paquets UDP pour détecter les scans UDP"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[UDP].dport
        
        # Ignorer le trafic local
        if src_ip.startswith('127.') or src_ip.startswith('192.168.') or src_ip.startswith('10.'):
            return
        
        # Ignorer les IPs de la liste noire
        if self.is_blacklisted(src_ip):
            return
        
        # Mettre à jour les statistiques
        conn_data = self.connections[src_ip]
        conn_data['last_seen'] = current_time
        conn_data['ports'].add(dst_port)
        conn_data['udp_count'] += 1
        
        # Vérifier si c'est un scan UDP
        if (conn_data['udp_count'] >= self.udp_threshold or 
            len(conn_data['ports']) >= self.port_threshold):
            self.alert_udp_scan(src_ip, conn_data, dst_port)
    
    def alert_tcp_scan(self, src_ip, conn_data, current_port):
        """Alerte pour un scan TCP détecté"""
        print(f"\n🚨 ALERTE - SCAN TCP DÉTECTÉ!")
        print(f"   IP Source: {src_ip}")
        print(f"   Ports scannés: {sorted(list(conn_data['ports']))}")
        print(f"   Nombre de paquets SYN: {conn_data['syn_count']}")
        print(f"   Port actuel: {current_port}")
        print(f"   Durée: {time.time() - conn_data['first_seen']:.2f} secondes")
        print(f"   Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
    
    def get_stats(self):
        """Retourne les statistiques actuelles"""
        return {
            'monitored_ips': len(self.connections),
            'total_connections': sum(len(data['ports']) for data in self.connections.values()),
            'blacklisted_ips': list(self.blacklisted_ips)
        }
    
    def stop(self):
        """Arrête le détecteur"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join()

def signal_handler(signum, frame):
    """Gestionnaire de signal pour arrêt propre"""
    print(f"\n\nArrêt du détecteur de scan de ports...")
    detector.stop()
    sys.exit(0)

def main():
    global detector
    
    print("🔍 Détecteur de scan de ports - Démarrage...")
    print("=" * 60)
    print("Ce script utilise Scapy pour détecter les scans de ports.")
    print("Types de scans détectés:")
    print("  - Scans TCP SYN")
    print("  - Scans UDP")
    print("  - Scans multi-ports")
    print("=" * 60)
    
    # Vérifier les privilèges
    if os.geteuid() != 0:
        print("⚠️  ATTENTION: Ce script nécessite des privilèges root pour capturer les paquets.")
        print("   Utilisez: sudo python3 scapy.py")
        sys.exit(1)
    
    # Créer le détecteur
    detector = PortScanDetector()
    detector.start_cleanup_thread()
    
    # Configurer le gestionnaire de signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print(f"🎯 Surveillance active - Seuils de détection:")
        print(f"   TCP SYN: {detector.syn_threshold} paquets")
        print(f"   UDP: {detector.udp_threshold} paquets")
        print(f"   Multi-ports: {detector.port_threshold} ports")
        print(f"   Fenêtre de temps: {detector.time_window} secondes")
        print(f"🚫 IPs en liste noire (ignorées): {', '.join(sorted(detector.blacklisted_ips))}")
        print("=" * 60)
        print("Appuyez sur Ctrl+C pour arrêter...\n")
        
        # Fonction de callback pour chaque paquet
        def packet_callback(packet):
            detector.analyze_packet(packet)
        
        # Démarrer la capture (filtre pour TCP et UDP)
        sniff(filter="tcp or udp", prn=packet_callback, store=0)
        
    except KeyboardInterrupt:
        print(f"\n\nArrêt demandé par l'utilisateur...")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")
    finally:
        detector.stop()
        stats = detector.get_stats()
        print(f"\n📊 Statistiques finales:")
        print(f"   IPs surveillées: {stats['monitored_ips']}")
        print(f"   Connexions totales: {stats['total_connections']}")
        print("Au revoir!")

if __name__ == "__main__":
    main()
