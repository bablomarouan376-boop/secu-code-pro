import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

# إعداد التطبيق - SecuCode Pro v2.7
app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات متصفح احترافية (Stealth Mode) لضمان عدم الحظر أثناء الفحص
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
    "Referer": "https://www.google.com/"
}

def get_domain_age(domain):
    """جلب عمر النطاق لكشف مواقع التصيد الحديثة"""
    try:
        if not domain or '.' not in domain: return None
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if res.status_code == 200:
            events = res.json().get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date = datetime.strptime(event.get('eventDate')[:10], "%Y-%m-%d")
                    return (datetime.now() - reg_date).days
    except: pass
    return None

def deobfuscate_logic(content):
    """فك تشفير Base64 لكشف البرمجيات الخبيثة المخفية"""
    logic = ""
    found = re.findall(r'["\']([A-Za-z0-9+/]{40,})={0,2}["\']', content)
    for b in found:
        try:
            logic += " " + base64.b64decode(b).decode('utf-8', errors='ignore')
        except: continue
    return logic

def perform_ultimate_scan(target_url):
    """المحرك الرئيسي: تحليل شامل للروابط والتهديدات"""
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    redirect_path = [target_url]

    try:
        session = requests.Session()
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        content = response.text
        domain = urlparse(final_url).netloc

        # 1. تحليل عمر النطاق
        age = get_domain_age(domain)
        if age is not None:
            if age < 31:
                risk_points += 60
                violated_rules.append({"name": "نطاق حديث جداً", "risk_description": f"عمر الموقع {age} يوم فقط. المواقع الجديدة هي الأعلى خطورة للتصيد."})
            elif age < 180:
                risk_points += 30
                violated_rules.append({"name": "نطاق غير مستقر", "risk_description": "عمر الموقع أقل من 6 أشهر، مما يتطلب الحذر."})

        # 2. كشف الأذونات المشبوهة (كاميرا، موقع، إلخ)
        threats = {
            'الوصول للكاميرا/المايك': r'getUserMedia|mediaDevices|camera|video|microphone',
            'تتبع الموقع الجغرافي': r'getCurrentPosition|watchPosition|geolocation',
            'سحب بيانات النماذج': r'password|credit_card|cvv|pin_code|billing'
        }
        
        full_logic = content + deobfuscate_logic(content)
        for name, pattern in threats.items():
            if re.search(pattern, full_logic, re.I):
                risk_points += 40
                violated_rules.append({"name": f"طلب إذن: {name}", "risk_description": "تم رصد كود يحاول الوصول لبيانات حساسة فور الدخول."})

        # 3. فحص التشفير والأمان
        if not final_url.startswith('https'):
            risk_points += 50
            violated_rules.append({"name": "اتصال غير مشفر (HTTP)", "risk_description": "الموقع لا يستخدم بروتوكول أمان SSL، بياناتك عرضة للاختراق."})

        # 4. كشف انتحال الشخصية
        brands = ['facebook', 'google', 'paypal', 'binance', 'apple', 'microsoft', 'instagram']
        for b in brands:
            if b in domain.lower() and domain.lower() != f"{b}.com":
                risk_points += 50
                violated_rules.append({"name": "اشتباه انتحال علامة تجارية", "risk_description": f"الموقع يستخدم اسم '{b}' بشكل مضلل في الرابط."})

    except Exception:
        risk_points = 35
        violated_rules.append({"name": "نظام صد الفحص التلقائي", "risk_description": "الموقع يمنع أدوات الرادار من التحليل، وهذا سلوك مريب وشائع في المواقع الضارة."})
        final_url = target_url

    score = min(risk_points, 100)
    label = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"

    return {
        "risk_score": label,
        "suspicious_points": score,
        "violated_rules": violated_rules,
        "final_url": final_url,
        "scan_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"message": "يرجى إدخال الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "الرابط غير صالح"}), 400
    return jsonify(perform_ultimate_scan(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)

