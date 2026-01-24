import os
import requests
import base64
import socket
import time
from flask import Flask, request, jsonify, render_template, make_response
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from weasyprint import HTML
from playwright.sync_api import sync_playwright
import redis

app = Flask(__name__)

# استخدم .env للمفاتيح (افترض إنك استخدمت dotenv)
from dotenv import load_dotenv
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
GOOGLE_SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")  # أضف مفتاحك
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Caching
r = redis.from_url(REDIS_URL)

# Firebase
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(os.getenv("FIREBASE_CREDENTIALS", "serviceAccountKey.json"))
        firebase_admin.initialize_app(cred, {'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'})
except Exception as e:
    print("Firebase init failed:", e)

WHITELIST_DOMAINS = [
    'google.com', 'google.com.eg', 'bing.com', 'yahoo.com',
    'microsoft.com', 'apple.com', 'github.com', 'wikipedia.org', 
    'nasa.gov', 'facebook.com', 'x.com', 'linkedin.com', 'amazon.com'
]

MALICIOUS_THRESHOLD = 3  # عتبة للـ malicious

def get_server_forensics(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        return {
            "ip": ip,
            "country": geo.get("country_name", "Unknown"),
            "org": geo.get("org", "Private Provider")
        }
    except:
        return {"ip": "0.0.0.0", "country": "Unknown", "org": "CDN/Private"}

def get_vt_analysis(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if res.status_code == 200:
            attr = res.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            return stats
        return None
    except:
        return None

def check_google_safe_browsing(url):
    try:
        payload = {
            'client': {'clientId': 'secucodepro', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        r = requests.post(f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}', json=payload)
        return bool(r.json().get('matches'))
    except:
        return False

def check_spyware_behavior(url, domain):
    if any(d in domain for d in WHITELIST_DOMAINS): return False
    try:
        headers = {"User-Agent": "SecuCode-Forensic/3.0 (Tarek Mostafa Intel)"}
        response = requests.get(url, timeout=5, headers=headers)
        content = response.text.lower()
        spy_patterns = ['getusermedia', 'getcurrentposition', 'mediarecorder']
        return any(p in content for p in spy_patterns)
    except: return False

def behavioral_analysis(url):
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, timeout=10000)
            scripts = page.evaluate('() => Array.from(document.scripts).map(s => s.src || s.innerText)')
            browser.close()
            suspicious = any('malicious' in s.lower() for s in scripts)  # تحليل بسيط، يمكن تحسينه
            return suspicious
    except:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze():
    data = request.get_json()
    raw_url = data.get('link', '').strip()
    if not raw_url: return jsonify({"error": "Empty URL"}), 400
    
    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
    domain = urlparse(url).netloc.lower() or url
    
    # Caching
    cached = r.get(url)
    if cached:
        return jsonify(json.loads(cached))
    
    server_info = get_server_forensics(domain)
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    p_count = vt_stats.get('phishing', 0) if vt_stats else 0
    spy_detected = check_spyware_behavior(url, domain)
    gs_detected = check_google_safe_browsing(url)
    behav_detected = behavioral_analysis(url)
    
    is_official = any(d in domain for d in WHITELIST_DOMAINS)
    is_blacklisted = False
    risk_score = 0
    
    if not is_official:
        if m_count >= MALICIOUS_THRESHOLD or p_count > 0 or gs_detected:
            is_blacklisted = True
            risk_score = min(50 + (m_count * 10) + (p_count * 15), 100)
        if spy_detected or behav_detected:
            is_blacklisted = True
            risk_score = max(risk_score, 70)  # خفضتها من 90

    try:
        db.reference('stats/clicks').transaction(lambda c: (c or 0) + 1)
        if is_blacklisted: db.reference('stats/threats').transaction(lambda t: (t or 0) + 1)
    except: pass

    if is_blacklisted and TELEGRAM_TOKEN:
        try:
            icon = "🔴"
            msg = f"{icon} *SecuCode Scan*\nDomain: `{domain}`\nRisk: {risk_score}%\nIP: {server_info['ip']}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except: pass

    response_data = {
        "is_official": is_official,
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "server": server_info,
        "vt_stats": vt_stats,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    }

    r.set(url, json.dumps(response_data), ex=3600)  # cache for 1 hour

    return jsonify(response_data)

@app.route('/generate_report', methods=['POST'])
def generate_report():
    data = request.get_json()
    result = data.get('result', {})
    lang = data.get('lang', 'en')
    
    # استخدم template report.html (أنشئ ملف report.html في templates)
    html_content = render_template('report.html', data=result, lang=lang, i18n=i18n[lang])  # افترض i18n في python إذا لزم

    pdf_bytes = HTML(string=html_content).write_pdf()
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=SecuCode_Report.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True)
