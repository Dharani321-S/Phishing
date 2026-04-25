import os
import re
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# 1. Loading the Brain
try:
    model = joblib.load('cyber_threat_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print(f"✅ Model & Encoder Loaded! Mapping: {le.classes_}")
except Exception as e:
    print(f"❌ Load Error: {e}")

# 2. EXACT MATCH WITH YOUR COLAB FUNCTION
def extract_95_accuracy_features(url):
    u = str(url).lower()
    hostname = urlparse(u).netloc
    
    # Intha list unga Colab sequence-ai appadiyae follow pannudhu
    features = [
        len(u),                                         # 1. URL Length
        u.count('.'),                                   # 2. Dot Count
        u.count('-'),                                   # 3. Hyphen Count
        u.count('@'),                                   # 4. At Symbol
        u.count('?'),                                   # 5. Query params
        u.count('/'),                                   # 6. Depth
        u.count('='),                                   # 7. Equal signs
        1 if "https" in u else 0,                       # 8. HTTPS Presence
        u.count('//'),                                  # 9. Double Slash (Redirect)
        sum(c.isdigit() for c in u),                    # 10. Digit Count
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', u) else 0, # 11. IP Address presence
        len(hostname),                                  # 12. Hostname length (ITHU THAAN CHANGE!)
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
        url = data.get('url', '').lower()

        if not url:
            return jsonify({"error": "No URL provided"}), 400

        # Features extract panni array-va mathuruvom
        f_list = extract_95_accuracy_features(url)
        features = np.array([f_list])
        
        # Prediction
        prediction_idx = int(model.predict(features)[0])
        
        # IMPORTANT: Unga model-la Index 0 = Phishing, Index 1 = Safe
        # Oru velai re-deploy panniye results maarala na, inga 'safe' matrum 'phishing' labels-ai swap panni paarunga.
        result = "phishing" if prediction_idx == 0 else "safe"

        print(f"DEBUG: URL={url} | Pred_Index={prediction_idx} | Result={result}")

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