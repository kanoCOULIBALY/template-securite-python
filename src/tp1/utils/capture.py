"""Module de capture et analyse du trafic réseau."""
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
from collections import Counter
from src.tp1.utils.lib import choose_interface
from src.tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        """Initialise la capture."""
        self.interface = choose_interface()
        self.packets = []
        self.protocols = Counter()
        self.summary = ""
        
    def capture_traffic(self, count=100, timeout=30) -> None:
        """
        Capture le trafic réseau depuis une interface.
        
        Args:
            count: Nombre maximum de paquets à capturer (défaut: 100)
            timeout: Durée maximale de capture en secondes (défaut: 30)
        """
        if not self.interface:
            logger.error("Aucune interface sélectionnée")
            return
        
        logger.info(f"Début de la capture sur {self.interface} (max {count} paquets, {timeout}s)")
        print(f"\nCapture en cours sur {self.interface}... (Ctrl+C pour arrêter)")
        
        try:
            self.packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout,
                prn=lambda x: logger.debug(f"Paquet capturé: {x.summary()}")
            )
            
            logger.info(f"Capture terminée: {len(self.packets)} paquets capturés")
            print(f"{len(self.packets)} paquets capturés")
            
        except PermissionError:
            logger.error("Erreur: Permissions insuffisantes (utilisez sudo)")
            print("Erreur: Utilisez 'sudo poetry run tp1'")
        except Exception as e:
            logger.error(f"Erreur lors de la capture: {e}")
            print(f"Erreur: {e}")
    
    def sort_network_protocols(self) -> dict:
        """
        Trie et retourne tous les protocoles réseau capturés.
        
        Returns:
            dict: Dictionnaire {protocole: nombre} trié par nombre décroissant
        """
        if not self.packets:
            logger.warning("Aucun paquet à analyser")
            return {}
        
        for packet in self.packets:
            protocol = self._identify_protocol(packet)
            self.protocols[protocol] += 1
        
        sorted_protocols = dict(sorted(
            self.protocols.items(),
            key=lambda x: x[1],
            reverse=True
        ))
        
        logger.info(f"Protocoles détectés: {len(sorted_protocols)}")
        return sorted_protocols
    
    def _identify_protocol(self, packet) -> str:
        """
        Identifie le protocole d'un paquet.
        
        Args:
            packet: Paquet Scapy
            
        Returns:
            str: Nom du protocole
        """
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
    
    def get_all_protocols(self) -> dict:
        """
        Retourne tous les protocoles capturés avec leur nombre de paquets.
        
        Returns:
            dict: {protocole: nombre}
        """
        if not self.protocols:
            self.sort_network_protocols()
        
        return dict(self.protocols)
    
    def analyse(self, protocol_filter: str = None) -> None:
        """
        Analyse les données capturées et génère un rapport.
        
        Args:
            protocol_filter: Protocole spécifique à analyser (optionnel)
        """
        logger.info("Début de l'analyse...")
        
        all_protocols = self.get_all_protocols()
        sorted_protocols = self.sort_network_protocols()
        
        logger.debug(f"Tous les protocoles: {all_protocols}")
        logger.debug(f"Protocoles triés: {sorted_protocols}")
        
        total_packets = len(self.packets)
        alerts = []
        
        # Détection simple d'anomalies
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
    
    def gen_summary(self, protocols: dict, total: int, alerts: list) -> str:
        """
        Génère un résumé textuel de l'analyse.
        
        Args:
            protocols: Dictionnaire des protocoles
            total: Nombre total de paquets
            alerts: Liste des alertes détectées
            
        Returns:
            str: Résumé formaté
        """
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
    
    def get_summary(self) -> str:
        """Retourne le résumé de l'analyse."""
        return self.summary
