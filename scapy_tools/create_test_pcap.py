#!/usr/bin/env python3
"""
Script pour créer un fichier pcap de test avec des scans de ports simulés
"""

from scapy.all import *
import random

def create_test_pcap():
    """Crée un fichier pcap avec des scans de ports simulés"""
    packets = []
    
    # Adresses IP simulées (publiques pour éviter le filtrage)
    attacker_ip = "203.0.113.100"  # IP publique de test
    target_ip = "10.0.0.1"
    
    print("🔧 Génération de paquets de scan TCP SYN...")
    # Générer un scan TCP SYN sur 150 ports (dépasse le seuil de 100)
    for port in range(20, 1024, 5):  # Environ 200 ports
        packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=port, flags="S")
        packets.append(packet)
    
    print("🔧 Génération de paquets de scan UDP...")
    # Générer un scan UDP sur 120 ports (dépasse le seuil de 100)
    for port in range(1000, 2000, 8):  # Environ 125 ports
        packet = IP(src=attacker_ip, dst=target_ip) / UDP(dport=port)
        packets.append(packet)
    
    print("🔧 Ajout de trafic normal...")
    # Ajouter du trafic normal pour rendre le test plus réaliste
    normal_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    for _ in range(50):
        src_ip = random.choice(normal_ips)
        port = random.choice([53, 80, 443, 25, 110])
        if random.choice([True, False]):
            packet = IP(src=src_ip, dst=target_ip) / TCP(dport=port, flags="S")
        else:
            packet = IP(src=src_ip, dst=target_ip) / UDP(dport=port)
        packets.append(packet)
    
    # Mélanger les paquets pour simuler un ordre réaliste
    random.shuffle(packets)
    
    filename = "test_scan.pcap"
    print(f"💾 Sauvegarde de {len(packets)} paquets dans {filename}...")
    wrpcap(filename, packets)
    
    print(f"✅ Fichier pcap créé: {filename}")
    print(f"📊 Contenu:")
    print(f"   - Paquets TCP SYN: ~200 (scan détectable)")
    print(f"   - Paquets UDP: ~125 (scan détectable)")
    print(f"   - Trafic normal: 50 paquets")
    print(f"   - Total: {len(packets)} paquets")

if __name__ == "__main__":
    create_test_pcap() 