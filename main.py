import os
import re
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# 1. Loading the Brain
try:
    model = joblib.load('cyber_threat_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print(f"✅ Model Loaded! Classes: {le.classes_}")
except Exception as e:
    print(f"❌ Load Error: {e}")

# 2. THE CORRECT LOGIC (Must match your Colab exactly)
def extract_features(url):
    u = str(url).lower()
    
    # Intha list unga Colab-la irukura 15 columns order-la irukanum
    features = [
        len(u),                         # 1. len
        u.count('.'),                   # 2. dots
        u.count('-'),                   # 3. hyphen
        u.count('@'),                   # 4. at
        u.count('?'),                   # 5. query
        u.count('/'),                   # 6. depth
        u.count('='),                   # 7. equal
        1 if "https" in u else 0,       # 8. https
        u.count('//'),                  # 9. redirect
        sum(c.isdigit() for c in u),    # 10. digits
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', u) else 0, # 11. ip
        u.count('www'),                 # 12. www
        # 13. keyword
        1 if any(w in u for w in ['login', 'verify', 'bank', 'secure', 'signin', 'update']) else 0,
        # 14. shortener
        1 if any(s in u for s in ['bit.ly', 'goo.gl', 't.co', 'tinyurl']) else 0,
        # 15. tld (Most important check)
        len(re.findall(r'\.(com|in|org|net|gov|edu)', u))
    ]
    return features

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '').lower()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Feature extraction
        f_list = extract_features(url)
        features = np.array([f_list])
        
        # DEBUG: Intha lines Render logs-la rumba mukkiyam
        prediction_idx = int(model.predict(features)[0])
        print(f"DEBUG: URL={url} | Features={f_list} | Index={prediction_idx}")

        # Final Mapping (Based on your Colab verification)
        # Index 0 is mapped to: phishing
        # Index 1 is mapped to: safe
        result = "phishing" if prediction_idx == 0 else "safe"

        # --- THE EMERGENCY OVERRIDE ---
        # Model miss pannaalum namma catch pannanum
        if result == "safe":
            # Rule: If URL is too complex or has multiple suspicious patterns
            suspicious_count = sum([1 for p in ['login', 'verify', 'update', 'secure', 'free'] if p in url])
            if suspicious_count >= 2 or url.count('.') > 3 or "@" in url:
                result = "phishing"
                print("🚩 Manual Override Triggered")

        return jsonify({
            "url": url,
            "prediction": result,
            "prediction_index": prediction_idx,
            "status": "success"
        })

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e), "status": "failed"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)