import re
import os
import joblib
from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing for React frontend

MODEL_FILE = 'proxyshield_model.pkl'
model = None

# Load model if it exists
if os.path.exists(MODEL_FILE):
    try:
        model = joblib.load(MODEL_FILE)
        print(f"⚡ Loaded trained AI Model ({MODEL_FILE})")
    except Exception as e:
        print(f"⚠️ Could not load model: {e}")

# =======================================================
# 1. ADVANCED FEATURE EXTRACTION
# =======================================================
def extract_features(url):
    if not isinstance(url, str):
        url = str(url)

    features = {}
    features['url_length'] = len(url)
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['num_hyphens'] = url.count('-')
    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_question_marks'] = url.count('?')
    features['num_equals'] = url.count('=')
    features['num_underscores'] = url.count('_')
    features['num_percent'] = url.count('%')
    features['num_ampersands'] = url.count('&')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
    features['has_https'] = 1 if url.lower().startswith('https') else 0
    features['has_ip'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    features['has_ext'] = 1 if ('.php' in url.lower() or '.html' in url.lower() or '.asp' in url.lower()) else 0

    suspicious_words = [
        'login', 'verify', 'update', 'secure', 'bank', 'account', 'free', 'win', 'admin', 'signin',
        'ebayisapi', 'webscr', 'confirm', 'pay', 'service', 'gift', 'bonus', 'refund', 'verification',
        'support', 'access', 'invoice'
    ]
    features['suspicious_word_count'] = sum(1 for word in suspicious_words if word in url.lower())

    suspicious_tlds = [
        '.xyz', '.info', '.top', '.tk', '.ml', '.ga', '.gq', '.cf', '.online', '.site', '.click',
        '.buzz', '.bid', '.shop', '.web'
    ]
    features['has_suspicious_tld'] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0

    return features

# =======================================================
# 2. API SCAN ENDPOINT
# =======================================================
@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def scan_url():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200

    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    url_features = extract_features(url)
    reasons = []

    # Check threat indicators
    if url_features['has_https'] == 0:
        reasons.append("Insecure Connection: Data is not encrypted (Missing HTTPS).")
    if url_features['has_ip'] == 1:
        reasons.append("Direct IP Access: Uses an IP address instead of a standard domain name.")
    if url_features['suspicious_word_count'] > 0:
        reasons.append("Deceptive Keywords: Contains words commonly used in credential harvesting (e.g., login, verify, free).")
    if url_features['has_suspicious_tld'] == 1:
        reasons.append("Shady Infrastructure: Hosted on a low-reputation or disposable domain extension.")
    if url_features['num_hyphens'] > 2:
        reasons.append("Lookalike Domain: Excessive hyphens used to mimic legitimate brands.")
    if url_features['url_length'] > 75:
        reasons.append("URL Obfuscation: Unusually long URL to hide the actual landing page.")

    # Calculate prediction and risk score
    if model is not None:
        try:
            import pandas as pd
            features_df_test = pd.DataFrame([url_features])
            prediction = int(model.predict(features_df_test)[0])
            probabilities = model.predict_proba(features_df_test)[0]
            risk_score = round(float(probabilities[1]) * 100, 2)
            is_safe = (prediction == 0)
        except Exception:
            # Fallback heuristic if dataframe or model evaluation errors
            risk_score = min(len(reasons) * 20.0 + (url_features['suspicious_word_count'] * 15.0), 100.0)
            is_safe = (len(reasons) == 0 and risk_score < 30.0)
    else:
        # Heuristic scoring when pkl is not yet trained
        score = 0
        if url_features['has_https'] == 0:
            score += 25
        if url_features['has_ip'] == 1:
            score += 30
        if url_features['suspicious_word_count'] > 0:
            score += min(url_features['suspicious_word_count'] * 20, 40)
        if url_features['has_suspicious_tld'] == 1:
            score += 25
        if url_features['num_hyphens'] > 2:
            score += 15
        if url_features['url_length'] > 75:
            score += 15
        risk_score = min(score, 100.0)
        is_safe = (len(reasons) == 0 and risk_score < 30.0)

    if not is_safe and len(reasons) == 0:
        reasons.append("Machine Learning Pattern Match: Structural similarities with known phishing campaigns detected.")

    return jsonify({
        'is_safe': is_safe,
        'risk_score': risk_score,
        'reasons': reasons
    })

if __name__ == '__main__':
    print("🚀 ProxySHIELD Flask Backend running on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)

