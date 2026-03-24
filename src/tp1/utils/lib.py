"""Fonctions utilitaires pour TP1."""
from scapy.all import get_if_list
from src.tp1.utils.config import logger


def hello_world() -> str:
    """
    Hello world function
    """
    return "hello world"


def choose_interface() -> str:
    """
    Affiche les interfaces disponibles et demande à l'utilisateur d'en choisir une.
    
    Returns:
        str: Nom de l'interface choisie
    """
    interfaces = get_if_list()
    
    if not interfaces:
        logger.error("Aucune interface réseau trouvée !")
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
