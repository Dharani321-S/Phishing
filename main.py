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
    # Model and Encoder loading
    model = joblib.load('cyber_threat_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print(f"✅ Phishing Detection Model Loaded! Classes: {le.classes_}")
except Exception as e:
    print(f"❌ Model Load Error: {e}")

# 2. Advanced Feature Extraction
def extract_features(url):
    u = str(url).lower()
    features = [
        len(u),                         # 1. URL Length
        u.count('.'),                   # 2. Dots
        u.count('-'),                   # 3. Hyphens
        u.count('@'),                   # 4. At symbol
        u.count('?'),                   # 5. Query
        u.count('/'),                   # 6. Depth
        u.count('='),                   # 7. Equals
        1 if u.startswith("https") else 0, # 8. Security (Protocol based)
        u.count('//'),                  # 9. Redirects
        sum(c.isdigit() for c in u),    # 10. Digits
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', u) else 0, # 11. IP Address
        u.count('www'),                 # 12. WWW presence
        # 13. Suspicious keywords check
        1 if any(w in u for w in ['login', 'verify', 'bank', 'secure', 'signin', 'update', 'free', 'lucky', 'bonus']) else 0,
        # 14. Shortener check
        1 if any(s in u for s in ['bit.ly', 'goo.gl', 't.co', 'tinyurl']) else 0,
        # 15. TLD count (Added common suspicious TLDs like .xyz, .top)
        len(re.findall(r'\.(com|in|org|net|gov|edu|xyz|top|pw|info)', u))
    ]
    return features

@app.route('/', methods=['GET'])
def health_check():
    return "Cyber Threat API is Running Successfully!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '').lower()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Feature extraction
        features = np.array([extract_features(url)])
        
        # Model Prediction
        # Based on your Colab: 0 = phishing, 1 = safe
        prediction_idx = int(model.predict(features)[0])
        
        # Initial Result mapping
        result = "phishing" if prediction_idx == 0 else "safe"

        # --- MANUAL OVERRIDE LOGIC ---
        # Model "safe"-nu sonnaalum, obvious patterns irundha phishing-nu maathuvom
        suspicious_patterns = ['-login', 'verify-', 'secure-', 'signin-', 'update-password', 'free-gift', '00.net']
        
        if result == "safe":
            # Rule 1: Too many dots or hyphens
            if url.count('.') > 3 or url.count('-') > 3:
                result = "phishing"
            # Rule 2: Suspicious URL patterns
            elif any(pattern in url for pattern in suspicious_patterns):
                result = "phishing"
            # Rule 3: Using @ symbol in domain part
            elif "@" in url:
                result = "phishing"

        # Debug log for Render Console
        print(f"DEBUG: URL={url} | Pred_Index={prediction_idx} | Final_Label={result}")

        return jsonify({
            "url": url,
            "prediction": result,
            "prediction_index": prediction_idx,
            "status": "success",
            "message": f"This URL is predicted as {result}"
        })

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e), "status": "failed"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)