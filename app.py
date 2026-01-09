import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin

app = Flask(__name__, static_folder='static', template_folder='templates')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
}

def deep_scanner(html, url):
    """ميزة فحص الـ JS وفك Base64 المدمجة"""
    intel = html
    # 1. جلب السكربتات الخارجية
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    for s in scripts[:5]:
        try:
            r = requests.get(urljoin(url, s), headers=HEADERS, timeout=4)
            intel += "\n" + r.text
        except: continue
    
    # 2. فك تشفير Base64 تلقائياً لكشف الروابط المستترة
    potential_b64 = re.findall(r'["\']([A-Za-z0-9+/]{30,})={0,2}["\']', intel)
    for b in potential_b64:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            if any(k in decoded.lower() for k in ['http', 'eval', 'camera', 'getusermedia']):
                intel += "\n" + decoded
        except: continue
    return intel

@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    target = request.json.get('link', '').strip()
    if not target: return jsonify({"message": "فارغ"}), 400
    if not target.startswith('http'): target = 'https://' + target
    
    start = time.time()
    path = [target]
    risk = 0
    rules = []

    try:
        session = requests.Session()
        # Advanced Redirection Tracker
        res = session.get(target, headers=HEADERS, timeout=12, allow_redirects=True)
        for r in res.history: path.append(r.url)
        if res.url not in path: path.append(res.url)
        
        final_url = res.url
        # جلب المحتوى العميق (JS + Base64)
        full_intel = deep_scanner(res.text, final_url)
        
        # Deep Pattern Matching (الكاميرا والخصوصية)
        if re.search(r'getUserMedia|mediaDevices\.getUserMedia|camera|videoChat', full_intel, re.I):
            risk += 85
            rules.append({"name": "تجسس: الوصول للكاميرا", "risk_description": "تم رصد كود برمجي يحاول تشغيل الكاميرا أو المايك تلقائياً."})

        # إصلاح خطأ الماركات الرسمية (جوجل، فيسبوك...)
        domain = urlparse(final_url).netloc.lower()
        brands = {'google': 'google.com', 'facebook': 'facebook.com', 'paypal': 'paypal.com', 'instagram': 'instagram.com'}
        for b, official in brands.items():
            if b in domain and official not in domain:
                risk += 90
                rules.append({"name": "انتحال هوية", "risk_description": f"الموقع ينتحل اسم {b} لكنه لا يتبع الرابط الرسمي."})

        if not final_url.startswith('https'):
            risk += 20
            rules.append({"name": "اتصال غير آمن", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS المشفر."})

    except:
        risk = 15
        final_url = target

    score_label = "Critical" if risk >= 75 else "High" if risk >= 40 else "Medium" if risk >= 20 else "Low"
    
    return jsonify({
        "risk_score": score_label,
        "suspicious_points": min(risk, 100),
        "violated_rules": rules,
        "redirect_path": path,
        "execution_time": round(time.time() - start, 2)
    })

if __name__ == '__main__':
    app.run(debug=True)
