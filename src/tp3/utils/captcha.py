"""Module de résolution de CAPTCHA avec OCR."""
import requests
from PIL import Image
import pytesseract
from io import BytesIO
from src.tp3.utils.config import logger


class Captcha:
    def __init__(self, url):
        """
        Initialise le solveur de CAPTCHA.
        
        Args:
            url: URL de la page avec le CAPTCHA
        """
        self.url = url
        self.image = None
        self.value = ""

    def capture(self, session_cookies=None):
        """
        Télécharge l'image du CAPTCHA depuis le serveur.
        
        Args:
            session_cookies: Cookies de session pour maintenir la connexion
        """
        try:
            # Extraire l'URL de base (http://31.220.95.27:9002)
            base_url = "/".join(self.url.split("/")[:3])
            captcha_url = base_url + "/captcha.php"
            
            response = requests.get(captcha_url, cookies=session_cookies, timeout=10)
            
            if response.status_code == 200:
                self.image = Image.open(BytesIO(response.content))
                logger.debug(f"CAPTCHA image téléchargée: {self.image.size}")
            else:
                logger.error(f"Erreur téléchargement CAPTCHA: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Erreur lors de la capture du CAPTCHA: {e}")

    def solve(self):
        """
        Résout le CAPTCHA en utilisant pytesseract (OCR).
        """
        if self.image is None:
            logger.error("Aucune image CAPTCHA à résoudre")
            return
        
        try:
            text = pytesseract.image_to_string(self.image)
            self.value = text.strip()
            logger.info(f"CAPTCHA résolu: '{self.value}'")
            
        except Exception as e:
            logger.error(f"Erreur lors de la résolution du CAPTCHA: {e}")
            self.value = ""

    def get_value(self):
        """
        Retourne la valeur résolue du CAPTCHA.
        
        Returns:
            str: Valeur du CAPTCHA
        """
        return self.value
