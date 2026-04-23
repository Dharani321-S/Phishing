import os
import re
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app) # Flutter app connect aaga idhu romba mukkiyam

# 1. Loading the Brain (Files andha folder-laye irukanum)
try:
    model = joblib.load('cyber_threat_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print("✅ Phishing Detection Model Loaded!")
except Exception as e:
    print(f"❌ Model Load Error: {e}")

# 2. Advanced Feature Extraction (Training-la use panna adhe logic)
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
        1 if "https" in u else 0,       # 8. Security
        u.count('//'),                  # 9. Redirects
        sum(c.isdigit() for c in u),    # 10. Digits
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', u) else 0, # 11. IP Address
        u.count('www'),                 # 12. WWW presence
        # 13. Suspicious keywords check
        1 if any(w in u for w in ['login', 'verify', 'bank', 'secure', 'signin', 'update']) else 0,
        # 14. Shortener check
        1 if any(s in u for s in ['bit.ly', 'goo.gl', 't.co', 'tinyurl']) else 0,
        # 15. TLD count
        len(re.findall(r'\.(com|in|org|net|gov|edu)', u))
    ]
    return features

@app.route('/', methods=['GET'])
def health_check():
    return "Cyber Threat API is Running Successfully!"

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Feature extraction
        features = np.array([extract_features(url)])
        
        # Model Prediction
        prediction_idx = model.predict(features)[0]
        # Probabilities (optional, for confidence score)
        # prob = model.predict_proba(features)[0]
        
        # Mapping index back to label ('safe' or 'phishing')
        result = le.inverse_transform([prediction_idx])[0]

        return jsonify({
            "url": url,
            "prediction": result,
            "status": "success",
            "message": f"This URL is predicted as {result}"
        })

    except Exception as e:
        return jsonify({"error": str(e), "status": "failed"}), 500

if __name__ == '__main__':
    # Render assigns a port dynamically
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)