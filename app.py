import os
import requests
import base64
import socket
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from dotenv import load_dotenv
import json

load_dotenv()  # تحميل المتغيرات من .env

app = Flask(__name__)

# المفاتيح الآن من .env (غير موجودة في الكود)
VT_API_KEY = os.getenv("VT_API_KEY")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Firebase credentials من .env كـ JSON string
FIREBASE_SERVICE_ACCOUNT = os.getenv("FIREBASE_SERVICE_ACCOUNT")
if FIREBASE_SERVICE_ACCOUNT:
    try:
        cred_dict = json.loads(FIREBASE_SERVICE_ACCOUNT)
        cred = credentials.Certificate(cred_dict)
    except json.JSONDecodeError as e:
        print("Error parsing FIREBASE_SERVICE_ACCOUNT:", e)
        cred = None
else:
    cred = None

# إعداد Firebase
try:
    if not firebase_admin._apps:
        if cred:
            firebase_admin.initialize_app(cred, options={'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})
        else:
            print("No Firebase credentials provided. Skipping initialization.")
except Exception as e:
    print("Firebase initialization failed:", e)

WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'bing.com', 'yahoo.com',
    'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org', 
    'nasa.gov', 'facebook.com', 'x.com', 'linkedin.com', 'amazon.com'
]

def get_server_forensics(domain):
    """جلب بيانات الخادم الجنائية"""
    try:
        ip = socket.gethostbyname(domain)
        # جلب الدولة والشركة المستضيفة عبر API
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5, verify=True).json()
        return {
            "ip": ip,
            "country": geo.get("country_name", "Unknown"),
            "org": geo.get("org", "Private Provider")
        }
    except:
        return {"ip": "0.0.0.0", "country": "Unknown", "org": "CDN/Private"}

def get_vt_analysis(url):
    """تحليل مطور لجلب تفاصيل المحركات"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=8, verify=True)
        
        if res.status_code == 200:
            attr = res.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            return stats
        return None
    except:
        return None

def check_spyware_behavior(url, domain):
    if any(d in domain for d in WHITELIST_DOMAINS): return False
    try:
        headers = {"User-Agent": "SecuCode-Forensic/3.0 (Tarek Mostafa Intel)"}
        response = requests.get(url, timeout=5, headers=headers, verify=True)
        content = response.text.lower()
        spy_patterns = ['getusermedia', 'getcurrentposition', 'mediarecorder']
        return any(p in content for p in spy_patterns)
    except: return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
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
        if firebase_admin._apps:  # فقط لو نجح الـ init
            db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
            if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
    except: pass

    try:
        if TELEGRAM_TOKEN and CHAT_ID and is_blacklisted:  # فقط عند الخطر
            icon = "🔴" if is_blacklisted else "🟢"
            msg = f"{icon} *SecuCode Scan*\nDomain: `{domain}`\nRisk: {risk_score}%\nIP: {server_info['ip']}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"}, verify=True)
    except: pass

    return jsonify({
        "is_official": is_official,
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "server": server_info,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
