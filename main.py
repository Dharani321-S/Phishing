import os
import re
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
import whois
from datetime import datetime

app = Flask(__name__)
CORS(app)

# 1. Loading the Brain
try:
    model = joblib.load('cyber_threat_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print(f"✅ Model & Encoder Loaded!")
except Exception as e:
    print(f"❌ Load Error: {e}")

# 2. Domain Age Logic
def get_domain_age(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path.split('/')[0]
        # Remove 'www.' for better whois lookup
        domain = domain.replace('www.', '')
        
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            return age_days
        return None
    except:
        return None

# 3. Feature Extraction
def extract_95_accuracy_features(url):
    u = str(url).lower()
    hostname = urlparse(u).netloc or u.split('/')[0]
    
    features = [
        len(u),                                         # 1. URL Length
        u.count('.'),                                   # 2. Dot Count
        u.count('-'),                                   # 3. Hyphen Count
        u.count('@'),                                   # 4. At Symbol
        u.count('?'),                                   # 5. Query params
        u.count('/'),                                   # 6. Depth
        u.count('='),                                   # 7. Equal signs
        1 if "https" in u else 0,                       # 8. HTTPS Presence
        u.count('//'),                                  # 9. Double Slash
        sum(c.isdigit() for c in u),                    # 10. Digit Count
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', u) else 0, # 11. IP Address
        len(hostname),                                  # 12. Hostname length
        u.count('www'),                                 # 13. WWW count
        # 14. Suspicious Keywords Check
        1 if any(word in u for word in ['login', 'verify', 'update', 'bank', 'secure', 'signin']) else 0,
        # 15. Shortening Services Check
        1 if any(s in u for s in ['bit.ly', 'goo.gl', 't.co', 'tinyurl']) else 0
    ]
    return features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        raw_url = data.get('url', '').lower().strip()

        if not raw_url:
            return jsonify({"error": "No URL provided"}), 400

        # Protocol Fix
        url = raw_url
        if not raw_url.startswith(('http://', 'https://')):
            url = 'https://' + raw_url

        # --- STEP 1: ULTRA WHITELIST (Immediate Safe Pass) ---
        # Intha domains ellam model kitta pogaama direct-ah "Safe" aagidum
        whitelist = [
            'google.com', 'amazon.in', 'amazon.com', 'github.com', 
            'wikipedia.org', 'facebook.com', 'instagram.com', 
            'linkedin.com', 'youtube.com', 'netflix.com', 'microsoft.com'
        ]
        
        is_safe_domain = any(domain in url for domain in whitelist)

        # --- STEP 2: AI Model Prediction ---
        f_list = extract_95_accuracy_features(url)
        features = np.array([f_list])
        prediction_idx = int(model.predict(features)[0])
        
        # Initial AI Result
        result = "phishing" if prediction_idx == 0 else "safe"

        # --- STEP 3: DOMAIN AGE OVERRIDE ---
        age = get_domain_age(url)
        
        # Age 1 year (365 days) mela irundha, adhu phishing-ah irukka chance romba kammi
        if age and age > 365:
            result = "safe"
            
        # Whitelist override (Final Priority)
        if is_safe_domain:
            result = "safe"

        # 4. Generate Screenshot URL
        screenshot = f"https://api.screenshotmachine.com/?key=FREE&url={url}&dimension=1024x768"

        print(f"LOG: URL={url} | AI_Result={prediction_idx} | Final={result} | Age={age}")

        return jsonify({
            "url": url,
            "prediction": result,
            "prediction_index": prediction_idx,
            "domain_age_days": age,
            "screenshot_url": screenshot,
            "status": "success"
        })

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e), "status": "failed"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
