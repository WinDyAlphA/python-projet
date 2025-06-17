#!/usr/bin/env python3
"""
Script pour créer un fichier pcap de test avec des attaques par force brute simulées
"""

from scapy.all import *
import random

def create_bruteforce_pcap():
    """Crée un fichier pcap avec des attaques par force brute simulées"""
    packets = []
    
    # Adresses IP simulées
    attacker_ip = "203.0.113.100"  # IP publique de test
    target_ip = "10.0.0.1"
    
    print("🔧 Génération d'attaques SSH par force brute...")
    # Générer une attaque SSH par force brute (15 tentatives - dépasse le seuil de 10)
    for i in range(15):
        # Paquet SYN pour SSH
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=22, flags="S")
        packets.append(syn_packet)
        
        # Réponse SYN-ACK simulée
        synack_packet = IP(src=target_ip, dst=attacker_ip) / TCP(sport=22, dport=syn_packet[TCP].sport, flags="SA")
        packets.append(synack_packet)
        
        # Paquet ACK
        ack_packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=22, flags="A")
        packets.append(ack_packet)
        
        # Simulation d'échec de connexion (RST)
        if i < 12:  # 12 échecs sur 15 tentatives
            rst_packet = IP(src=target_ip, dst=attacker_ip) / TCP(sport=22, dport=ack_packet[TCP].sport, flags="R")
            packets.append(rst_packet)
    
    print("🔧 Génération d'attaques FTP par force brute...")
    # Générer une attaque FTP par force brute (20 tentatives - dépasse le seuil de 15)
    for i in range(20):
        # Paquet SYN pour FTP
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=21, flags="S")
        packets.append(syn_packet)
        
        # Simulation d'échec de connexion (RST)
        if i < 18:  # 18 échecs sur 20 tentatives
            rst_packet = IP(src=target_ip, dst=attacker_ip) / TCP(sport=21, dport=syn_packet[TCP].sport, flags="R")
            packets.append(rst_packet)
    
    print("🔧 Génération d'attaques HTTP par force brute...")
    # Générer une attaque HTTP par force brute (60 tentatives - dépasse le seuil de 50)
    for i in range(60):
        # Alternance entre HTTP et HTTPS
        port = 80 if i % 2 == 0 else 443
        syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=port, flags="S")
        packets.append(syn_packet)
        
        # Quelques échecs simulés
        if i % 3 == 0:
            rst_packet = IP(src=target_ip, dst=attacker_ip) / TCP(sport=port, dport=syn_packet[TCP].sport, flags="R")
            packets.append(rst_packet)
    
    print("🔧 Génération d'attaques multi-ports...")
    # Attaque sur plusieurs services (RDP, SMTP, etc.)
    services = [3389, 25, 110, 143, 23]  # RDP, SMTP, POP3, IMAP, Telnet
    for service_port in services:
        for i in range(5):  # 5 tentatives par service = 25 total (> 20 seuil général)
            syn_packet = IP(src=attacker_ip, dst=target_ip) / TCP(dport=service_port, flags="S")
            packets.append(syn_packet)
            
            # Simulation d'échec
            rst_packet = IP(src=target_ip, dst=attacker_ip) / TCP(sport=service_port, dport=syn_packet[TCP].sport, flags="R")
            packets.append(rst_packet)
    
    print("🔧 Génération d'attaques multi-cibles...")
    # Attaque sur plusieurs IPs cibles
    target_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
    for target in target_ips:
        for i in range(8):  # 8 tentatives par IP = 32 total (> 20 seuil)
            syn_packet = IP(src=attacker_ip, dst=target) / TCP(dport=22, flags="S")
            packets.append(syn_packet)
    
    # Mélanger les paquets pour simuler un trafic réaliste
    random.shuffle(packets)
    
    # Sauvegarder le fichier pcap
    output_file = "test_bruteforce.pcap"
    wrpcap(output_file, packets)
    
    print(f"✅ Fichier pcap créé: {output_file}")
    print(f"📊 {len(packets)} paquets générés")
    print("🎯 Attaques simulées:")
    print("   - SSH: 15 tentatives (seuil: 10)")
    print("   - FTP: 20 tentatives (seuil: 15)")
    print("   - HTTP/HTTPS: 60 tentatives (seuil: 50)")
    print("   - Multi-ports: 25 tentatives sur 5 services (seuil: 20)")
    print("   - Multi-cibles: 32 tentatives sur 4 IPs (seuil: 20)")
    
    return output_file

if __name__ == "__main__":
    create_bruteforce_pcap() 