"""Module de gestion de session pour résolution de CAPTCHA."""
import requests
from bs4 import BeautifulSoup
from src.tp3.utils.captcha import Captcha
from src.tp3.utils.config import logger


class Session:
    """
    Classe gérant une session pour résoudre un CAPTCHA et récupérer un flag.
    """

    def __init__(self, url):
        """
        Initialise une nouvelle session.
        
        Args:
            url: URL du challenge CAPTCHA
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.session = requests.Session()
        # Charger la page UNE FOIS pour obtenir les cookies de session
        self.session.get(self.url, timeout=10)

    def reset(self):
        """
        Réinitialise la session pour une nouvelle tentative.
        """
        self.session = requests.Session()
        self.session.get(self.url, timeout=10)
        self.captcha_value = ""
        self.flag_value = ""

    def prepare_request(self):
        """
        Prépare la requête en capturant et résolvant le CAPTCHA.
        """
        try:
            # Capturer et résoudre le CAPTCHA (ne pas recharger la page)
            captcha = Captcha(self.url)
            captcha.capture(self.session.cookies)
            captcha.solve()
            
            self.captcha_value = captcha.get_value()
            
            logger.debug(f"Cookies: {self.session.cookies.get_dict()}")
            logger.debug(f"CAPTCHA value: {self.captcha_value}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la préparation: {e}")

    def submit_request(self):
        """
        Envoie le CAPTCHA résolu au serveur avec le flag.
        """
        try:
            data = {
                'flag': '1500',  # Flag entre 1000 et 2000
                'captcha': self.captcha_value,
                'submit': ''  # Champ submit obligatoire !
            }
            
            # POST avec la même session (cookies automatiquement inclus)
            response = self.session.post(
                self.url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=True,
                timeout=10
            )
            
            self.flag_value = response.text
            
            logger.debug(f"Response status: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi: {e}")

    def process_response(self):
        """
        Traite la réponse du serveur pour extraire le flag.
        
        Returns:
            bool: True si flag trouvé, False sinon
        """
        # DEBUG - Voir ce que le serveur renvoie
        print("\n=== RÉPONSE SERVEUR ===")
        print(self.flag_value[:800])
        print("======================\n")
        
        try:
            soup = BeautifulSoup(self.flag_value, 'html.parser')
            
            # Chercher le message de succès
            flag_element = soup.find('div', class_='alert-success')
            if flag_element:
                self.valid_flag = flag_element.get_text(strip=True)
                logger.info(f"Flag trouvé: {self.valid_flag}")
                return True
            
            # Chercher le message d'erreur
            error_element = soup.find('div', class_='alert-danger')
            if error_element:
                error_msg = error_element.get_text(strip=True)
                logger.warning(f"Erreur: {error_msg}")
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement de la réponse: {e}")
            return False

    def get_flag(self):
        """
        Retourne le flag valide.
        
        Returns:
            str: Le flag valide
        """
        return self.valid_flag
