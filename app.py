import os
import requests
import base64
import socket
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
import json
import logging

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Firebase credentials (escaped newlines)
FIREBASE_SERVICE_ACCOUNT = """
{
  "type": "service_account",
  "project_id": "secucode-pro",
  "private_key_id": "131da2ca8578982b77e48fa71f8c4b65880b0784",
  "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwhV2C+HnRrp8\\nTemJc7bdbGw2JUb47hZ1ShXk2ReFbQ256bhud1AIO+rxHJ0fzq8Ba+ZTaAsodLxU\\nn74+dxpyrMUolvBONnWgFeQtgqFsHouAAy0j/iJs6yNny6o4f/TVp4UKixqY+jT0\\nTSBo8ixU7Dxh6VWdom62BsKUAGN8ALFM5N6+4z3fbCj9fB4mmvibIQLLAVwxZ703\\ndSP1ZFOJgd98LEHYOBYBKAOQ/fEyq20e8PEokuVnoLqvLxJDGCwGvv5aEadq2t3O\\nhJ9oJAefIDD2YsAPgeMu8MAtlHlTuoqu82FGehQ2v6mtC4121W2NFLORPC1fttWE\\nFr5U5La3AgMBAAECggEAAUqVcGNeFirBiZCBK7wwJ6P3mLGZpkmD9N5R6FByJyy+\\nr91nA2d4fZpiP3ZA9jTda0K8Hr9B2uEm8CjcqcJGXmtDC/UTsQIhAm5H9DE2gAyr\\nej0lkOh6l9ScwTHA0Z8MnTy0xOBpeRdjZ32pjiSSixW0QB8kj4u0NJ+yvW+3NDru\\ntErFEF03IaMgfnK279reWuNKC72lZfVlkFk9qoi6b34j1mdhAXlkIqPm1plkd8py\\nZDPxGf7/xdB32peadLpuWHvd/JyE9hLGa+CT9g12kKOcxh/KmJVD5MBkIriQAFoh\\nT7pvJm9SDju4uDtc6O26IME3/YIwjB+YfgrXMySMiQKBgQDOSdjq2/TJTYXoen2X\\ncvlssZGGVenb30rcQHIPtC9xHhczPJ6cAPhRltmeV37HO8g82unNnbsAePCsVZx+\\nX6p2y9VDzTDimAJEXd/JVjwBnFs8/8GwUwLoFvsbnAvA8pSFHYmKURDJolPjJ0Gw\\nqr40NrApbRG47JYQHyhHTfOPwwKBgQC+z5Xa2yT1rSzOsNoOwfJmTo0oThNaTExE\\n6/8/1F7NpeZLKbew5sai20CmmvWKljVKgiyUdJLZShlbnqv3QUvEL+PH9pWNftpd\\nphAlbEG9UPjF6nR8IrOwtAXK3tMyrGlYl7EI0dgwY8pzoYgUraRik2AqfaG2BRe/\\n8oUXZMKh/QKBgGmwaiOCB/su7cF7KGd0r5fhrgZedA+Dao5HsmibT4cr/ITytOyG\\njrL2j45Rk5Gt7lxHaGxBOLL4Q4532lLg3qw4qI4xTa96ZAb09Zfox5unqRMqkeit\\nzxpr08GEhH0Zi8BbrsEf4XL86O/DiCNkh0inEEBZMjBFfmjKHc/Sf0wTAoGALYVy\\nl9LeP2pAHVNdwlWM0dF9pZby0QEQ1QSEUaMFtwQUK+xY8XAtBV9PTi/70kNBlXP2\\n1Lf27LXb1NrG5ecC/1v5eJQgW7BewibDBVqNWG//2Z+0iITy334jP6HnOtidDVCr\\nIJKHhAvambl4sI44gHfuYlS0hqsyXk2qaMlWEbUCgYEAmSFfrOq4+I32/Aqr8f2v\\nWnU65jupo1jeBmzSDP+IZYCH4Ydf9msfzQS9eX4UoGnQ8qD07ICiVnXuP7hqY8JR\\n8sjwYcTcZ6JHiuLp4HP+PhwrhsM/govb8BCcBrDRpggTx7bXPhqFYKgPN5jb6n7Q\\nQgLue5qdPf3qb3a3n6CioWQ=\\n-----END PRIVATE KEY-----\\n",
  "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com",
  "client_id": "100797441781867873022",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40secucode-pro.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}
"""

# إعداد Firebase
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred, options={'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})
except Exception as e:
    logging.error(f"Firebase init failed: {e}")
    pass

WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'bing.com', 'yahoo.com',
    'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org', 
    'nasa.gov', 'facebook.com', 'x.com', 'linkedin.com', 'amazon.com'
]

# باقي الكود كما هو...

def get_server_forensics(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5, verify=True).json()
        return {
            "ip": ip,
            "country": geo.get("country_name", "Unknown"),
            "org": geo.get("org", "Private Provider")
        }
    except Exception as e:
        logging.error(f"Server forensics failed: {e}")
        return {"ip": "0.0.0.0", "country": "Unknown", "org": "CDN/Private"}

def get_vt_analysis(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8, verify=True)
        
        if res.status_code == 200:
            attr = res.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            return stats
        return None
    except Exception as e:
        logging.error(f"VT analysis failed: {e}")
        return None

def check_spyware_behavior(url, domain):
    if any(d in domain for d in WHITELIST_DOMAINS): return False
    try:
        headers = {"User-Agent": "SecuCode-Forensic/3.0 (Tarek Mostafa Intel)"}
        response = requests.get(url, timeout=5, headers=headers, verify=True)
        content = response.text.lower()
        spy_patterns = ['getusermedia', 'getcurrentposition', 'mediarecorder']
        return any(p in content for p in spy_patterns)
    except Exception as e:
        logging.error(f"Spyware check failed: {e}")
        return False

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        logging.error(f"Index render failed: {e}")
        return "Error loading page", 500

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url: return jsonify({"error": "Empty URL"}), 400
        
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        domain = urlparse(url).netloc.lower() or url
        
        server_info = get_server_forensics(domain)
        vt_stats = get_vt_analysis(url)
        m_count = vt_stats.get('malicious', 0) if vt_stats else 0
        p_count = vt_stats.get('phishing', 0) if vt_stats else 0
        spy_detected = check_spyware_behavior(url, domain)
        
        is_official = any(d in domain for d in WHITELIST_DOMAINS)
        is_blacklisted = False
        risk_score = 0
        
        if not is_official:
            if m_count > 0 or p_count > 0:
                is_blacklisted = True
                risk_score = min(50 + (m_count * 10) + (p_count * 15), 100)
            if spy_detected:
                is_blacklisted = True
                risk_score = max(risk_score, 90)
    
        try:
            db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
            if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
        except Exception as e:
            logging.error(f"Firebase transaction failed: {e}")
    
        try:
            icon = "🔴" if is_blacklisted else "🟢"
            msg = f"{icon} *SecuCode Scan*\nDomain: `{domain}`\nRisk: {risk_score}%\nIP: {server_info['ip']}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"}, verify=True)
        except Exception as e:
            logging.error(f"Telegram send failed: {e}")
    
        return jsonify({
            "is_official": is_official,
            "is_blacklisted": is_blacklisted,
            "risk_score": risk_score,
            "server": server_info,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
        })
    except Exception as e:
        logging.error(f"Analyze endpoint failed: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
