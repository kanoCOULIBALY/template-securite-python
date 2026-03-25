"""
TP3 - CAPTCHA Solver
Résout automatiquement des CAPTCHAs avec OCR

Auteur: Kano COULIBALY
Date: Mars 2026
"""

from src.tp3.utils.config import logger
from src.tp3.utils.session import Session


def main():
    print("="*70)
    print("     TP3 - CAPTCHA SOLVER")
    print("="*70)
    
    logger.info("Starting TP3")

    ip = "31.220.95.27:9002"
    challenges = {"1": f"http://{ip}/captcha1/"}

    for i in challenges:
        url = challenges[i]
        logger.info(f"\n=== Challenge {i}: {url} ===")
        
        attempts = 0
        max_attempts = 10
        success = False
        
        # Créer UNE session
        session = Session(url)
        
        while not success and attempts < max_attempts:
            attempts += 1
            logger.info(f"Tentative {attempts}/{max_attempts}")
            
            # Reset la session pour chaque tentative (sauf la première)
            if attempts > 1:
                session.reset()
            
            # Préparer et envoyer
            session.prepare_request()
            session.submit_request()
            success = session.process_response()

        if success:
            logger.info("Smell good !")
            logger.info(f"Flag for {url}: {session.get_flag()}")
            print(f"\n✅ FLAG: {session.get_flag()}\n")
        else:
            logger.error(f"Échec après {max_attempts} tentatives")
            print(f"\n❌ Échec pour le challenge {i}\n")


if __name__ == "__main__":
    main()
