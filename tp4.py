"""
TP4 - Crazy Decoder
Décode rapidement des messages encodés (base64, hex, rot13, etc.)

Auteur: Kano COULIBALY
Date: Mars 2026
"""

from pwn import *
import base64
import binascii
import codecs
import logging

logging.basicConfig(level=logging.INFO, format='<Logger> - %(message)s')
logger = logging.getLogger("TP4")


def decode_base64(data):
    """Décode du base64."""
    try:
        decoded = base64.b64decode(data)
        return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        return None


def decode_hex(data):
    """Décode de l'hexadécimal."""
    try:
        decoded = binascii.unhexlify(data)
        return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        return None


def decode_rot13(data):
    """Décode du ROT13."""
    try:
        return codecs.decode(data, 'rot13')
    except Exception as e:
        return None


def auto_decode(data):
    """
    Essaie automatiquement plusieurs méthodes de décodage.
    
    Args:
        data: Données à décoder (string ou bytes)
    
    Returns:
        tuple: (méthode, données décodées)
    """
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='ignore')
    
    data = data.strip()
    
    # Essayer base64
    result = decode_base64(data)
    if result:
        return ("base64", result)
    
    # Essayer hex
    result = decode_hex(data)
    if result:
        return ("hex", result)
    
    # Essayer ROT13
    result = decode_rot13(data)
    if result and result != data:
        return ("rot13", result)
    
    return ("unknown", data)


def connect_to_server(host, port):
    """
    Se connecte à un serveur de challenge.
    
    Args:
        host: Adresse IP du serveur
        port: Port du serveur
    """
    logger.info(f"Connexion à {host}:{port}...")
    
    try:
        conn = remote(host, port)
        logger.info("Connecté !")
        
        while True:
            # Recevoir les données
            data = conn.recvline(timeout=5)
            
            if not data:
                logger.warning("Connexion fermée")
                break
            
            logger.info(f"Reçu: {data[:100]}")
            
            # Décoder automatiquement
            method, decoded = auto_decode(data)
            logger.info(f"Méthode: {method}")
            logger.info(f"Décodé: {decoded[:100]}")
            
            # Renvoyer la réponse
            conn.sendline(decoded.encode())
            
            # Voir la réponse du serveur
            response = conn.recvline(timeout=5)
            logger.info(f"Serveur: {response}")
            
    except Exception as e:
        logger.error(f"Erreur: {e}")
    finally:
        conn.close()
        logger.info("Déconnecté")


def interactive_mode():
    """Mode interactif pour tester le décodage."""
    print("="*70)
    print("     TP4 - CRAZY DECODER (Mode Interactif)")
    print("="*70)
    print("\nEntrez du texte encodé (ou 'quit' pour quitter)")
    
    while True:
        try:
            data = input("\n> ")
            
            if data.lower() in ['quit', 'exit', 'q']:
                break
            
            method, decoded = auto_decode(data)
            print(f"Méthode détectée: {method}")
            print(f"Résultat: {decoded}")
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Erreur: {e}")


def main():
    """Programme principal."""
    import argparse
    
    parser = argparse.ArgumentParser(description='TP4 - Crazy Decoder')
    parser.add_argument('-H', '--host', help='Adresse du serveur')
    parser.add_argument('-p', '--port', type=int, help='Port du serveur')
    parser.add_argument('-i', '--interactive', action='store_true', 
                       help='Mode interactif')
    
    args = parser.parse_args()
    
    if args.interactive:
        interactive_mode()
    elif args.host and args.port:
        connect_to_server(args.host, args.port)
    else:
        print("Usage:")
        print("  Mode serveur:    python tp4.py -H <host> -p <port>")
        print("  Mode interactif: python tp4.py -i")
        print("\nExemples:")
        print("  python tp4.py -H 31.220.95.27 -p 9003")
        print("  python tp4.py -i")


if __name__ == "__main__":
    main()
