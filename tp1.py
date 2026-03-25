"""
TP1 - IDS/IPS maison
Capture et analyse du trafic réseau avec Scapy
Génération de rapport PDF avec statistiques

Auteur: Kano COULIBALY
Date: Mars 2026
"""

from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP, ARP, DNS
from collections import Counter
from fpdf import FPDF
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TP1")


def choose_interface():
    """
    Affiche les interfaces disponibles et demande à l'utilisateur d'en choisir une.
    
    Returns:
        str: Nom de l'interface choisie
    """
    interfaces = get_if_list()
    
    if not interfaces:
        logger.error("Aucune interface réseau trouvée")
        return ""
    
    print("\n=== Interfaces réseau disponibles ===")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    
    while True:
        try:
            choice = input(f"\nChoisissez une interface (1-{len(interfaces)}): ")
            index = int(choice) - 1
            
            if 0 <= index < len(interfaces):
                selected = interfaces[index]
                logger.info(f"Interface sélectionnée: {selected}")
                return selected
            else:
                print(f"Erreur: Choisissez un nombre entre 1 et {len(interfaces)}")
        except ValueError:
            print("Erreur: Entrez un nombre valide")
        except KeyboardInterrupt:
            print("\nAnnulation...")
            return ""


class Capture:
    """Classe pour capturer et analyser le trafic réseau."""
    
    def __init__(self, interface):
        """Initialise la capture."""
        self.interface = interface
        self.packets = []
        self.protocols = Counter()
        self.summary = ""
        
    def capture_traffic(self, count=100, timeout=30):
        """
        Capture le trafic réseau depuis une interface.
        
        Args:
            count: Nombre maximum de paquets à capturer
            timeout: Durée maximale de capture en secondes
        """
        if not self.interface:
            logger.error("Aucune interface sélectionnée")
            return
        
        logger.info(f"Début de la capture sur {self.interface}")
        print(f"\nCapture en cours sur {self.interface}... (Ctrl+C pour arrêter)")
        
        try:
            self.packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout
            )
            
            logger.info(f"Capture terminée: {len(self.packets)} paquets capturés")
            print(f"{len(self.packets)} paquets capturés")
            
        except PermissionError:
            logger.error("Erreur: Permissions insuffisantes")
            print("Erreur: Utilisez 'sudo python tp1.py'")
        except Exception as e:
            logger.error(f"Erreur lors de la capture: {e}")
            print(f"Erreur: {e}")
    
    def identify_protocol(self, packet):
        """Identifie le protocole d'un paquet."""
        if packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(IP):
            return "IP"
        else:
            return "Autre"
    
    def sort_network_protocols(self):
        """Trie et compte les protocoles réseau capturés."""
        if not self.packets:
            return {}
        
        for packet in self.packets:
            protocol = self.identify_protocol(packet)
            self.protocols[protocol] += 1
        
        sorted_protocols = dict(sorted(
            self.protocols.items(),
            key=lambda x: x[1],
            reverse=True
        ))
        
        logger.info(f"Protocoles détectés: {len(sorted_protocols)}")
        return sorted_protocols
    
    def get_all_protocols(self):
        """Retourne tous les protocoles capturés."""
        if not self.protocols:
            self.sort_network_protocols()
        return dict(self.protocols)
    
    def analyse(self):
        """Analyse les données capturées et détecte les anomalies."""
        logger.info("Début de l'analyse...")
        
        all_protocols = self.get_all_protocols()
        total_packets = len(self.packets)
        alerts = []
        
        if "ARP" in all_protocols:
            arp_count = all_protocols["ARP"]
            if arp_count > total_packets * 0.3:
                alerts.append(f"ALERTE: Nombre anormal de paquets ARP ({arp_count})")
        
        if "ICMP" in all_protocols:
            icmp_count = all_protocols["ICMP"]
            if icmp_count > 50:
                alerts.append(f"ALERTE: Nombre élevé de paquets ICMP ({icmp_count})")
        
        self.summary = self.gen_summary(all_protocols, total_packets, alerts)
        logger.info("Analyse terminée")
    
    def gen_summary(self, protocols, total, alerts):
        """Génère un résumé textuel de l'analyse."""
        summary = "\n" + "="*50 + "\n"
        summary += "           RÉSUMÉ DE LA CAPTURE\n"
        summary += "="*50 + "\n\n"
        
        summary += f"Interface: {self.interface}\n"
        summary += f"Total de paquets: {total}\n"
        summary += f"Protocoles détectés: {len(protocols)}\n\n"
        
        summary += "Répartition des protocoles:\n"
        summary += "-" * 50 + "\n"
        for proto, count in protocols.items():
            percentage = (count / total * 100) if total > 0 else 0
            summary += f"  {proto:10s} : {count:4d} paquets ({percentage:.1f}%)\n"
        
        if alerts:
            summary += "\n" + "="*50 + "\n"
            summary += "           ALERTES DÉTECTÉES\n"
            summary += "="*50 + "\n"
            for alert in alerts:
                summary += f"{alert}\n"
        else:
            summary += "\nAucune anomalie détectée\n"
        
        summary += "\n" + "="*50 + "\n"
        return summary
    
    def get_summary(self):
        """Retourne le résumé."""
        return self.summary


class Report:
    """Classe pour générer le rapport PDF."""
    
    def __init__(self, capture, filename):
        """Initialise le rapport."""
        self.capture = capture
        self.filename = filename
        self.title = "RAPPORT D'ANALYSE DE TRAFIC RESEAU"
        self.summary = capture.get_summary()
        self.protocols = capture.get_all_protocols()
        self.pdf = FPDF()
    
    def generate_array(self):
        """Génère un tableau des protocoles."""
        if not self.protocols:
            return
        
        self.pdf.add_page()
        self.pdf.set_font('Helvetica', 'B', 14)
        self.pdf.cell(0, 10, 'Tableau des protocoles', new_x="LMARGIN", new_y="NEXT")
        self.pdf.ln(5)
        
        self.pdf.set_font('Helvetica', 'B', 12)
        self.pdf.cell(60, 10, 'Protocole', border=1)
        self.pdf.cell(60, 10, 'Nombre de paquets', border=1)
        self.pdf.cell(60, 10, 'Pourcentage', border=1, new_x="LMARGIN", new_y="NEXT")
        
        self.pdf.set_font('Helvetica', '', 12)
        total = sum(self.protocols.values())
        
        for protocol, count in self.protocols.items():
            percentage = (count / total * 100) if total > 0 else 0
            self.pdf.cell(60, 10, protocol, border=1)
            self.pdf.cell(60, 10, str(count), border=1)
            self.pdf.cell(60, 10, f"{percentage:.1f}%", border=1, new_x="LMARGIN", new_y="NEXT")
    
    def save(self):
        """Sauvegarde le rapport PDF."""
        self.pdf.add_page()
        self.pdf.set_font('Helvetica', 'B', 16)
        self.pdf.cell(0, 10, self.title, align='C', new_x="LMARGIN", new_y="NEXT")
        self.pdf.ln(10)
        
        self.pdf.set_font('Courier', '', 9)
        
        for line in self.summary.split('\n'):
            if line.strip():
                clean_line = line[:90]
                self.pdf.cell(0, 4, clean_line, new_x="LMARGIN", new_y="NEXT")
            else:
                self.pdf.ln(2)
        
        self.pdf.output(self.filename)
        print(f"\nRapport PDF généré: {self.filename}")


def main():
    """Programme principal."""
    print("="*50)
    print("     TP1 - IDS/IPS MAISON")
    print("="*50)
    
    interface = choose_interface()
    if not interface:
        return
    
    capture = Capture(interface)
    capture.capture_traffic(count=100, timeout=30)
    capture.analyse()
    print(capture.get_summary())
    
    report = Report(capture, "rapport_tp1.pdf")
    report.generate_array()
    report.save()
    
    print("\nTerminé !")


if __name__ == "__main__":
    main()
