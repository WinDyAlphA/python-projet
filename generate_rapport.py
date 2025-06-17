#!/usr/bin/env python3
"""
CLI pour générer des rapports de détection de scan de ports
Usage:
    python3 generate_rapport.py --live                    # Mode surveillance en temps réel
    python3 generate_rapport.py --pcap fichier.pcap       # Analyse d'un fichier pcap
"""

import argparse
from fpdf import FPDF
import sys
import os
import time
from datetime import datetime
import json
from scapy.all import *
from scapy_tools.port_scan_detector import PortScanDetector
from scapy_tools.bruteforce_detector import BruteForceDetector
from scan import scan_ports, load_ports_from_file, _format_port_list
from vuln.fuzz import fuzz_web_application
from vuln.main import run_default_dvwa_tests

class SecurityReportGenerator:
    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------
    def __init__(self, output_file=None):
        self.port_detector = PortScanDetector()
        self.bruteforce_detector = BruteForceDetector(alert_callback=self.add_bruteforce_alert)
        self.output_file = output_file or f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.port_scan_alerts = []
        self.bruteforce_alerts = []
        self.start_time = time.time()
        # Résultats éventuels d'un scan de ports externe déclenché via --scan
        self.external_scan = None  # dict: {'target_ip': str, 'open_ports': List[int], 'scanned_count': int}
        self.dvwa_results = None  # dict summary of DVWA tests
        
    def add_port_scan_alert(self, alert_type, src_ip, conn_data, current_port):
        """Ajoute une alerte de scan de ports au rapport"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'source_ip': src_ip,
            'ports_scanned': sorted(list(conn_data['ports'])),
            'port_count': len(conn_data['ports']),
            'current_port': current_port,
            'duration': time.time() - conn_data['first_seen'],
            'packet_count': {
                'syn': conn_data.get('syn_count', 0),
                'udp': conn_data.get('udp_count', 0)
            }
        }
        self.port_scan_alerts.append(alert)
        
        # Afficher l'alerte en temps réel
        self.print_port_scan_alert(alert)
    
    def add_bruteforce_alert(self, attack_type, src_ip, conn_data, current_port):
        """Ajoute une alerte de force brute au rapport"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'source_ip': src_ip,
            'current_port': current_port,
            'duration': time.time() - conn_data['first_seen'],
            'attempts': {
                'ssh': conn_data.get('ssh_attempts', 0),
                'ftp': conn_data.get('ftp_attempts', 0),
                'http': conn_data.get('http_attempts', 0) + conn_data.get('https_attempts', 0),
                'total': conn_data.get('total_attempts', 0)
            },
            'connection_stats': {
                'failures': conn_data.get('connection_failures', 0),
                'successes': conn_data.get('successful_connections', 0)
            }
        }
        self.bruteforce_alerts.append(alert)
        
        # Afficher l'alerte en temps réel
        self.print_bruteforce_alert(alert)
    
    def print_port_scan_alert(self, alert):
        """Affiche une alerte de scan de ports formatée"""
        print(f"\n🚨 ALERTE - SCAN {alert['type'].upper()} DÉTECTÉ!")
        print(f"   IP Source: {alert['source_ip']}")
        print(f"   Ports scannés: {alert['ports_scanned']}")
        print(f"   Nombre de ports: {alert['port_count']}")
        print(f"   Port actuel: {alert['current_port']}")
        print(f"   Durée: {alert['duration']:.2f} secondes")
        print(f"   Paquets SYN: {alert['packet_count']['syn']}")
        print(f"   Paquets UDP: {alert['packet_count']['udp']}")
        print(f"   Timestamp: {alert['timestamp']}")
        print("-" * 60)
    
    def print_bruteforce_alert(self, alert):
        """Affiche une alerte de force brute formatée"""
        print(f"\n🚨 ALERTE - FORCE BRUTE {alert['type'].upper()} DÉTECTÉ!")
        print(f"   IP Source: {alert['source_ip']}")
        print(f"   Port actuel: {alert['current_port']}")
        print(f"   Durée: {alert['duration']:.2f} secondes")
        print(f"   Tentatives SSH: {alert['attempts']['ssh']}")
        print(f"   Tentatives FTP: {alert['attempts']['ftp']}")
        print(f"   Tentatives HTTP: {alert['attempts']['http']}")
        print(f"   Total tentatives: {alert['attempts']['total']}")
        print(f"   Échecs: {alert['connection_stats']['failures']}")
        print(f"   Succès: {alert['connection_stats']['successes']}")
        print(f"   Timestamp: {alert['timestamp']}")
        print("-" * 60)
    
    def analyze_packet(self, packet):
        """Analyse un paquet et génère des alertes si nécessaire"""
        # Utiliser le timestamp du paquet si disponible, sinon le temps actuel
        if hasattr(packet, 'time'):
            current_time = packet.time
        else:
            current_time = time.time()
        
        # Analyse des paquets TCP pour scan de ports
        if packet.haslayer(TCP):
            self._analyze_tcp_packet(packet, current_time)
        
        # Analyse des paquets UDP pour scan de ports
        elif packet.haslayer(UDP):
            self._analyze_udp_packet(packet, current_time)
        
        # Analyse pour détection de force brute
        self.bruteforce_detector.analyze_packet(packet, current_time)
    
    def _analyze_tcp_packet(self, packet, current_time):
        """Analyse les paquets TCP pour détecter les scans SYN"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        tcp_flags = packet[TCP].flags
        
        # Ignorer le trafic local
        if src_ip.startswith('127.') or src_ip.startswith('192.168.') or src_ip.startswith('10.'):
            return
        
        # Mettre à jour les statistiques
        conn_data = self.port_detector.connections[src_ip]
        
        # Initialiser first_seen si c'est la première fois
        if 'first_seen' not in conn_data or conn_data['first_seen'] == 0:
            conn_data['first_seen'] = current_time
        
        conn_data['last_seen'] = current_time
        conn_data['ports'].add(dst_port)
        
        # Détecter les paquets SYN (flags = 2)
        if tcp_flags & 0x02:  # SYN flag
            conn_data['syn_count'] += 1
            
            # Vérifier si c'est un scan SYN
            if (conn_data['syn_count'] >= self.port_detector.syn_threshold or 
                len(conn_data['ports']) >= self.port_detector.port_threshold):
                self.add_port_scan_alert('tcp', src_ip, conn_data, dst_port)
    
    def _analyze_udp_packet(self, packet, current_time):
        """Analyse les paquets UDP pour détecter les scans UDP"""
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[UDP].dport
        
        # Ignorer le trafic local
        if src_ip.startswith('127.') or src_ip.startswith('192.168.') or src_ip.startswith('10.'):
            return
        
        # Mettre à jour les statistiques
        conn_data = self.port_detector.connections[src_ip]
        
        # Initialiser first_seen si c'est la première fois
        if 'first_seen' not in conn_data or conn_data['first_seen'] == 0:
            conn_data['first_seen'] = current_time
        
        conn_data['last_seen'] = current_time
        conn_data['ports'].add(dst_port)
        conn_data['udp_count'] += 1
        
        # Vérifier si c'est un scan UDP
        if (conn_data['udp_count'] >= self.port_detector.udp_threshold or 
            len(conn_data['ports']) >= self.port_detector.port_threshold):
            self.add_port_scan_alert('udp', src_ip, conn_data, dst_port)
    
    def run_live_analysis(self):
        """Lance l'analyse de sécurité en temps réel"""
        print("🔍 Analyse de Sécurité Réseau - Mode LIVE")
        print("=" * 60)
        print("Surveillance du trafic réseau en temps réel...")
        print("🔴 Détection: Scans de ports")
        print("🟠 Détection: Attaques par force brute")
        print(f"Rapport sera sauvegardé dans: {self.output_file}")
        print("=" * 60)
        print("Appuyez sur Ctrl+C pour arrêter...\n")
        
        try:
            # Démarrer la capture en temps réel
            sniff(filter="tcp or udp", prn=self.analyze_packet, store=0)
            
        except KeyboardInterrupt:
            print(f"\n\nArrêt demandé par l'utilisateur...")
        except Exception as e:
            print(f"\n❌ Erreur: {e}")
        finally:
            self.save_report()
    
    def run_pcap_analysis(self, pcap_file):
        """Lance l'analyse de sécurité d'un fichier pcap"""
        if not os.path.exists(pcap_file):
            print(f"❌ Erreur: Le fichier {pcap_file} n'existe pas.")
            return False
        
        print("🔍 Analyse de Sécurité Réseau - Mode PCAP")
        print("=" * 60)
        print(f"Analyse du fichier: {pcap_file}")
        print("🔴 Détection: Scans de ports")
        print("🟠 Détection: Attaques par force brute")
        print(f"Rapport sera sauvegardé dans: {self.output_file}")
        print("=" * 60)
        
        try:
            print("📁 Chargement du fichier pcap...")
            packets = rdpcap(pcap_file)
            total_packets = len(packets)
            
            print(f"📊 {total_packets} paquets à analyser")
            print("🔄 Analyse en cours...\n")
            
            # Analyser chaque paquet
            for i, packet in enumerate(packets):
                self.analyze_packet(packet)
                
                # Afficher le progrès
                if i % 1000 == 0:
                    progress = (i / total_packets) * 100
                    print(f"Progrès: {progress:.1f}% ({i}/{total_packets})", end='\r')
            
            print(f"\n✅ Analyse terminée: {total_packets} paquets traités")
            
        except Exception as e:
            print(f"❌ Erreur lors de l'analyse du fichier pcap: {e}")
            return False
        finally:
            self.save_report()
        
        return True
    
    def save_report(self):
        """Sauvegarde le rapport au format TXT structuré"""
        end_time = time.time()
        
        # Calculer les statistiques pour les deux types d'alertes
        total_port_alerts = len(self.port_scan_alerts)
        total_bf_alerts = len(self.bruteforce_alerts)
        total_alerts = total_port_alerts + total_bf_alerts
        
        all_ips = set()
        if self.port_scan_alerts:
            all_ips.update(alert['source_ip'] for alert in self.port_scan_alerts)
        if self.bruteforce_alerts:
            all_ips.update(alert['source_ip'] for alert in self.bruteforce_alerts)
        unique_ips = len(all_ips)
        
        tcp_scans = len([a for a in self.port_scan_alerts if a['type'] == 'tcp'])
        udp_scans = len([a for a in self.port_scan_alerts if a['type'] == 'udp'])
        
        # Statistiques force brute par type
        ssh_bf = len([a for a in self.bruteforce_alerts if a['type'] == 'SSH'])
        ftp_bf = len([a for a in self.bruteforce_alerts if a['type'] == 'FTP'])
        http_bf = len([a for a in self.bruteforce_alerts if a['type'] == 'HTTP/HTTPS'])
        high_volume_bf = len([a for a in self.bruteforce_alerts if a['type'] == 'High-Volume-Attack'])
        duration = end_time - self.start_time
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                # En-tête du rapport
                f.write("=" * 80 + "\n")
                f.write("           RAPPORT DE DÉTECTION DE SCAN DE PORTS\n")
                f.write("=" * 80 + "\n\n")
                
                # Informations générales
                f.write("📅 Date de génération: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "\n")
                f.write(f"⏱️  Durée d'analyse: {duration:.2f} secondes\n")
                f.write(f"⚙️  Configuration Scan: {self.port_detector.syn_threshold} paquets SYN, {self.port_detector.udp_threshold} paquets UDP, {self.port_detector.port_threshold} ports en {self.port_detector.time_window}s\n")
                f.write(f"⚙️  Configuration Force Brute: {self.bruteforce_detector.main_threshold} requêtes en {self.bruteforce_detector.time_window}s (principal), {self.bruteforce_detector.ssh_threshold} SSH, {self.bruteforce_detector.ftp_threshold} FTP, {self.bruteforce_detector.http_threshold} HTTP\n\n")
                
                # ------------------------------------------------------------------
                # Résultats éventuels d'un scan de ports externe (--scan)
                # ------------------------------------------------------------------
                if self.external_scan is not None:
                    f.write("🔎 RÉSULTAT DU SCAN DE PORTS EXTERNE\n")
                    f.write("-" * 40 + "\n")
                    tgt = self.external_scan['target_ip']
                    open_ports = self.external_scan['open_ports']
                    scanned_cnt = self.external_scan['scanned_count']
                    f.write(f"   Cible: {tgt}\n")
                    f.write(f"   Ports scannés: {scanned_cnt}\n")
                    f.write(f"   Ports ouverts ({len(open_ports)}): ")
                    if open_ports:
                        # Afficher max 20 ports pour ne pas surcharger
                        display = ', '.join(map(str, open_ports[:20]))
                        if len(open_ports) > 20:
                            display += f" … (+{len(open_ports)-20} autres)"
                        f.write(display + "\n\n")
                    else:
                        f.write("Aucun port ouvert détecté.\n\n")
                
                # ------------------------------------------------------------------
                # Résultats éventuels des tests DVWA (--dvwa)
                # ------------------------------------------------------------------
                if self.dvwa_results is not None:
                    f.write("🧪 TESTS DVWA (SQLi + XSS)\n")
                    f.write("-" * 40 + "\n")
                    r = self.dvwa_results
                    f.write(f"   Cible: {r.get('target')}\n")

                    # SQLi
                    sqli = r.get('sqli')
                    if sqli:
                        f.write("   SQLi:\n")
                        f.write(f"     - URL: {sqli.get('url')}\n")
                        f.write(f"     - Colonnes détectées: {sqli.get('num_columns')}\n")
                        f.write(f"     - Payloads testés: {sqli.get('payloads_tested')}\n")
                        f.write(f"     - Succès: {sqli.get('successes')}\n")
                        # Détails des payloads ayant retourné du contenu
                        details = sqli.get('details', [])
                        if details:
                            f.write(f"     - Payloads réussis ({len(details)}):\n")
                            for d in details:
                                f.write("         ------------------------------\n")
                                f.write(f"         PAYLOAD:\n{d['payload']}\n")
                                f.write("         RÉPONSE:\n")
                                # Indenter chaque ligne de la réponse pour lisibilité
                                for line in d['content'].splitlines():
                                    f.write(f"           {line}\n")
                                f.write("         ------------------------------\n")
                    else:
                        f.write("   SQLi: Non testée ou échec de connexion\n")

                    # XSS
                    xss = r.get('xss')
                    if xss:
                        f.write(f"   XSS: {'Succès' if xss.get('success') else 'Échec'}\n")
                        if xss.get('payloads'):
                            f.write("     Payloads injectés avec succès:\n")
                            for p in xss['payloads']:
                                f.write(f"       * {p}\n")
                    else:
                        f.write("   XSS: Non testée\n")
                    f.write("\n")
                
                # Vérifier s'il y a des attaques
                if total_alerts == 0:
                    f.write("🔒 RÉSULTAT: Aucune attaque détectée\n")
                    f.write("\nAucun scan de ports ou attaque par force brute n'a été identifié durant l'analyse.\n")
                    f.write("Le trafic réseau analysé ne présente pas de patterns d'attaque.\n")
                else:
                    # Résumé des attaques détectées
                    f.write("🚨 ATTAQUES DÉTECTÉES!\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"📊 Nombre total d'alertes: {total_alerts}\n")
                    f.write(f"🌐 IPs sources uniques: {unique_ips}\n\n")
                    
                    # Résumé des scans de ports
                    if total_port_alerts > 0:
                        f.write("🔴 SCANS DE PORTS:\n")
                        f.write(f"   - Scans TCP: {tcp_scans}\n")
                        f.write(f"   - Scans UDP: {udp_scans}\n")
                        f.write(f"   - Total: {total_port_alerts}\n\n")
                    
                    # Résumé des attaques par force brute
                    if total_bf_alerts > 0:
                        f.write("🟠 ATTAQUES PAR FORCE BRUTE:\n")
                        f.write(f"   - SSH: {ssh_bf}\n")
                        f.write(f"   - FTP: {ftp_bf}\n")
                        f.write(f"   - HTTP/HTTPS: {http_bf}\n")
                        f.write(f"   - High-Volume: {high_volume_bf}\n")
                        f.write(f"   - Total: {total_bf_alerts}\n\n")
                    
                    # Détails des attaques par IP
                    ips_grouped = {}
                    
                    # Regrouper les alertes de scan de ports
                    for alert in self.port_scan_alerts:
                        ip = alert['source_ip']
                        if ip not in ips_grouped:
                            ips_grouped[ip] = {'port_scans': {'tcp': [], 'udp': []}, 'bruteforce': []}
                        ips_grouped[ip]['port_scans'][alert['type']].append(alert)
                    
                    # Regrouper les alertes de force brute
                    for alert in self.bruteforce_alerts:
                        ip = alert['source_ip']
                        if ip not in ips_grouped:
                            ips_grouped[ip] = {'port_scans': {'tcp': [], 'udp': []}, 'bruteforce': []}
                        ips_grouped[ip]['bruteforce'].append(alert)
                    
                    for ip, attacks in ips_grouped.items():
                        f.write("=" * 80 + "\n")
                        f.write(f"🎯 ATTAQUANT: {ip}\n")
                        f.write("=" * 80 + "\n")
                        
                        tcp_attacks = attacks['port_scans']['tcp']
                        udp_attacks = attacks['port_scans']['udp']
                        bf_attacks = attacks['bruteforce']
                        
                        # Afficher les scans de ports TCP
                        if tcp_attacks:
                            f.write(f"\n🔴 SCANS TCP ({len(tcp_attacks)} alertes):\n")
                            f.write("-" * 50 + "\n")
                            for i, alert in enumerate(tcp_attacks, 1):  # Limiter à 3 alertes par type
                                f.write(f"  {i}. {alert['timestamp'][:19]}\n")
                                f.write(f"     Ports scannés: {alert['port_count']} ports\n")
                                f.write(f"     Échantillon: {', '.join(map(str, alert['ports_scanned'][:10]))}")
                                if len(alert['ports_scanned']) > 10:
                                    f.write(f" ... (+{len(alert['ports_scanned'])-10} autres)")
                                f.write(f"\n     Durée: {alert['duration']:.2f}s\n")
                                f.write(f"     Paquets SYN: {alert['packet_count']['syn']}\n\n")
            
                        
                        # Afficher les scans de ports UDP
                        if udp_attacks:
                            f.write(f"\n🔵 SCANS UDP ({len(udp_attacks)} alertes):\n")
                            f.write("-" * 50 + "\n")
                            for i, alert in enumerate(udp_attacks[:3], 1):  # Limiter à 3 alertes par type
                                f.write(f"  {i}. {alert['timestamp'][:19]}\n")
                                f.write(f"     Ports scannés: {alert['port_count']} ports\n")
                                f.write(f"     Échantillon: {', '.join(map(str, alert['ports_scanned'][:10]))}")
                                if len(alert['ports_scanned']) > 10:
                                    f.write(f" ... (+{len(alert['ports_scanned'])-10} autres)")
                                f.write(f"\n     Durée: {alert['duration']:.2f}s\n")
                                f.write(f"     Paquets UDP: {alert['packet_count']['udp']}\n\n")
                            
                            if len(udp_attacks) > 3:
                                f.write(f"     ... et {len(udp_attacks)-3} autres alertes UDP\n\n")
                        
                        # Afficher les attaques par force brute
                        if bf_attacks:
                            f.write(f"\n🟠 ATTAQUES FORCE BRUTE ({len(bf_attacks)} alertes):\n")
                            f.write("-" * 50 + "\n")
                            for i, alert in enumerate(bf_attacks[:3], 1):  # Limiter à 3 alertes par type
                                f.write(f"  {i}. {alert['timestamp'][:19]} - {alert['type']}\n")
                                f.write(f"     Port ciblé: {alert['current_port']}\n")
                                f.write(f"     Tentatives SSH: {alert['attempts']['ssh']}")
                                f.write(f" | FTP: {alert['attempts']['ftp']}")
                                f.write(f" | HTTP: {alert['attempts']['http']}")
                                f.write(f" | Total: {alert['attempts']['total']}\n")
                                f.write(f"     Échecs: {alert['connection_stats']['failures']}")
                                f.write(f" | Succès: {alert['connection_stats']['successes']}\n")
                                f.write(f"     Durée: {alert['duration']:.2f}s\n\n")
                            
                            if len(bf_attacks) > 3:
                                f.write(f"     ... et {len(bf_attacks)-3} autres alertes de force brute\n\n")
                    
                    # Recommandations
                    f.write("=" * 80 + "\n")
                    f.write("💡 RECOMMANDATIONS DE SÉCURITÉ\n")
                    f.write("=" * 80 + "\n")
                    f.write("🔒 Actions immédiates:\n")
                    f.write("- Bloquer les adresses IP malveillantes dans le pare-feu\n")
                    f.write("- Surveiller les logs système pour d'autres activités suspectes\n")
                    f.write("- Vérifier l'intégrité des comptes utilisateurs\n\n")
                    
                    if total_port_alerts > 0:
                        f.write("🔴 Pour les scans de ports:\n")
                        f.write("- Activer la protection contre les scans de ports\n")
                        f.write("- Configurer des règles de limitation de débit (rate limiting)\n")
                        f.write("- Masquer les services non nécessaires\n\n")
                    
                    if total_bf_alerts > 0:
                        f.write("🟠 Pour les attaques par force brute:\n")
                        f.write("- Changer les mots de passe des comptes exposés\n")
                        f.write("- Activer l'authentification multi-facteurs (2FA)\n")
                        f.write("- Mettre en place un système de bannissement automatique\n")
                        f.write("- Utiliser des ports non-standards pour les services critiques\n\n")
                    
                    f.write("🛡️  Mesures préventives:\n")
                    f.write("- Déployer un système IDS/IPS\n")
                    f.write("- Mettre à jour les règles de sécurité réseau\n")
                    f.write("- Programmer des analyses de sécurité régulières\n")
                    f.write("- Former le personnel sur les bonnes pratiques de sécurité\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("Fin du rapport\n")
                f.write("=" * 80 + "\n")
            
            print(f"\n📄 Rapport sauvegardé: {self.output_file}")
            if total_alerts == 0:
                print("🔒 Résultat: Aucune attaque détectée")
            else:
                print(f"🚨 Résultat: {total_alerts} alertes - {unique_ips} IP(s) malveillante(s)")
                if total_port_alerts > 0:
                    print(f"   🔴 Scans de ports: {total_port_alerts} (TCP: {tcp_scans}, UDP: {udp_scans})")
                if total_bf_alerts > 0:
                    print(f"   🟠 Force brute: {total_bf_alerts} (SSH: {ssh_bf}, FTP: {ftp_bf}, HTTP: {http_bf}, High-Volume: {high_volume_bf})")
            print(f"   ⏱️  Durée d'analyse: {duration:.2f} secondes")
            
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde du rapport: {e}")

    # ------------------------------------------------------------------
    # Méthodes utilitaires pour le scan de ports externe
    # ------------------------------------------------------------------
    def set_external_scan_results(self, target_ip: str, open_ports: list[int], scanned_count: int):
        """Enregistre les résultats d'un scan de ports externe."""
        self.external_scan = {
            'target_ip': target_ip,
            'open_ports': open_ports,
            'scanned_count': scanned_count,
        }

    # ------------------------------------------------------------------
    # DVWA results
    # ------------------------------------------------------------------
    def set_dvwa_results(self, results: dict):
        self.dvwa_results = results

    def transform_to_pdf(self):
        """Convertit le rapport TXT en PDF lisible (monospace, pagination automatique)."""
        txt_path = self.output_file

        if not os.path.isfile(txt_path):
            print(f"[!] Impossible de trouver le fichier {txt_path} pour la conversion PDF")
            return

        # Déterminer le nom de sortie
        if txt_path.lower().endswith('.txt'):
            pdf_path = txt_path[:-4] + '.pdf'
        else:
            pdf_path = txt_path + '.pdf'

        pdf = FPDF(format='A4')
        pdf.set_auto_page_break(auto=True, margin=15)

        # Utiliser une police monospace pour préserver l'alignement
        pdf.add_page()
        pdf.set_font('Courier', size=10)

        line_height = 5  # Hauteur de ligne en mm

        # Dictionnaire de remplacement des emojis pour la compatibilité PDF
        emoji_replacements = {
            '📅': '[DATE]',
            '⏱️': '[TEMPS]',
            '⚙️': '[CONFIG]',
            '🔎': '[SCAN]',
            '🧪': '[TEST]',
            '🔒': '[SECURISE]',
            '🚨': '[ALERTE]',
            '📊': '[STATS]',
            '🌐': '[IP]',
            '🔴': '[TCP]',
            '🟠': '[BRUTEFORCE]',
            '🔵': '[UDP]',
            '🎯': '[ATTAQUANT]',
            '💡': '[CONSEIL]',
            '🛡️': '[PROTECTION]',
            '📄': '[RAPPORT]',
            '🔍': '[ANALYSE]',
            '🟢': '[OK]',
            '❌': '[ERREUR]',
            '⚠️': '[ATTENTION]',
            '✅': '[SUCCES]',
            '🔄': '[PROGRES]',
        }

        def clean_line_for_pdf(line):
            """Nettoie une ligne en remplaçant les emojis par du texte compatible PDF."""
            cleaned = line
            for emoji, replacement in emoji_replacements.items():
                cleaned = cleaned.replace(emoji, replacement)
            
            # Filtrer les autres caractères Unicode non supportés par latin-1
            cleaned = cleaned.encode('latin-1', errors='ignore').decode('latin-1')
            return cleaned

        with open(txt_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.rstrip('\n')
                # Nettoyer la ligne pour la compatibilité PDF
                clean_line = clean_line_for_pdf(line)
                # multi_cell gère les retours à la ligne automatiques
                pdf.multi_cell(0, line_height, txt=clean_line)

        try:
            pdf.output("Transfert/rapport_total.pdf")
            print(f"[RAPPORT] PDF généré: {pdf_path}")
        except Exception as e:
            print(f"[ERREUR] Erreur lors de la génération du PDF: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Générateur de rapports de sécurité réseau (Scans de ports + Force brute)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s --live                           # Surveillance en temps réel
  %(prog)s --pcap capture.pcap              # Analyse d'un fichier pcap
  %(prog)s --pcap capture.pcap -o report.txt  # Avec fichier de sortie personnalisé
        """
    )
    
    # Options pouvant être combinées (ex.: --scan + --pcap)
    parser.add_argument('--live', action='store_true',
                       help='Mode surveillance en temps réel')
    parser.add_argument('--pcap', metavar='FICHIER',
                       help='Fichier pcap à analyser')
    parser.add_argument('--scan', metavar='IP',
                       help="Scanner les ports ouverts de l'adresse IP cible")
    parser.add_argument('--fuzz', metavar='URL',
                       help="Fuzzer récursivement une application web (ex: 192.168.1.10)")
    parser.add_argument('--wordlist', metavar='FICHIER', default="vuln/directory-list-2.3-small.txt",
                       help='Chemin vers la wordlist pour le fuzz (défaut: directory-list-2.3-small.txt)')
    parser.add_argument('--depth', type=int, default=3,
                       help='Profondeur maximale de récursion pour le fuzz (défaut: 3)')
    parser.add_argument('--status', default='200', metavar='CODES',
                       help='Codes HTTP à afficher, séparés par des virgules (défaut: 200)')
    parser.add_argument('--dvwa', metavar='IP',
                       help='Exécuter automatiquement les tests DVWA (SQLi + XSS) sur la cible')
    
    parser.add_argument('-o', '--output', metavar='FICHIER',
                       help='Fichier de sortie pour le rapport TXT')
    
    args = parser.parse_args()

    # S'assurer qu'au moins une option d'action est fournie
    if not (args.live or args.pcap or args.scan or args.fuzz or args.dvwa):
        parser.error("Vous devez spécifier au moins l'une des options: --live, --pcap, --scan, --fuzz ou --dvwa.")

    # Vérifier les privilèges pour le mode live
    if args.live and os.geteuid() != 0:
        print("⚠️  ATTENTION: Le mode live nécessite des privilèges root.")
        print("   Utilisez: sudo python3 generate_rapport.py --live")
        sys.exit(1)

    # --- Exécution des actions demandées ---
    try:
        # Créer l'instance de générateur une seule fois
        generator = SecurityReportGenerator(args.output)

        # 0) Tests DVWA automatiques (SQLi + XSS)
        if args.dvwa:
            dvwa_summary = run_default_dvwa_tests(args.dvwa)
            generator.set_dvwa_results(dvwa_summary)

        # 1) Fuzzing web (exécuté avant le scan/analyses pour ne pas dépendre du générateur)
        if args.fuzz:
            print("🌐 Fuzzing web application…")
            fuzz_web_application(
                file_path=args.wordlist,
                target_url=args.fuzz,
                allowed_status_codes=args.status.split(','),
                max_depth=args.depth,
            )

        # 2) Scan de ports (s'exécute ensuite si demandé)
        if args.scan:
            target_ip = args.scan

            # Charger la liste de ports depuis le CSV si dispo, sinon plage 1-8888
            csv_path = os.path.join(os.path.dirname(__file__), "scan", "top-10000-most-popular-tcp-ports-nmap-sorted.csv")
            if os.path.exists(csv_path):
                ports_to_scan = load_ports_from_file(csv_path)
            else:
                ports_to_scan = range(1, 8888)

            print("🔍 Scan de ports TCP en cours…")
            open_ports = scan_ports(target_ip, ports_to_scan)
            print(f"[+] Ports ouverts sur {target_ip}: {_format_port_list(open_ports)}")

            # Enregistrer les résultats dans le rapport
            generator.set_external_scan_results(target_ip, open_ports, len(ports_to_scan))

        # 3) Analyse en temps réel
        if args.live:
            generator.run_live_analysis()

        # 4) Analyse PCAP
        if args.pcap:
            success = generator.run_pcap_analysis(args.pcap)
            if not success:
                sys.exit(1)

        # 5) Si aucune analyse live/pcap n'a été demandée mais qu'un scan a été fait, sauver le rapport ici
        if args.scan and not (args.live or args.pcap):
            generator.save_report()

        # 6) Transform the report to pdf
        generator.transform_to_pdf()

    except KeyboardInterrupt:
        print("\nInterruption par l'utilisateur…")
    except Exception as e:
        print(f"❌ Erreur fatale: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 