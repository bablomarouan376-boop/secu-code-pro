import os
import re
import requests
import socket
import ssl
import time
import base64
import json
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')

# إعدادات الرأس لمحاكاة متصفح بشري فائق الجودة
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.7,en;q=0.3",
    "Referer": "https://www.google.com/"
}

def get_domain_age(domain):
    """
    فحص عمر النطاق باستخدام خدمة RDAP (بديلة لـ WHOIS التقليدية لسرعتها)
    المواقع الجديدة (أقل من 30 يوم) تعتبر شديدة الخطورة
    """
    try:
        # استخدام خدمة RDAP المجانية لجلب بيانات التسجيل
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if res.status_code == 200:
            data = res.json()
            # البحث عن تاريخ الإنشاء في سجلات الأحداث
            events = data.get('events', [])
            for event in events:
                if event.get('eventAction') == 'registration':
                    reg_date_str = event.get('eventDate')
                    # تحويل التاريخ وحساب الفرق بالأيام
                    reg_date = datetime.strptime(reg_date_str[:10], "%Y-%m-%d")
                    age_days = (datetime.now() - reg_date).days
                    return age_days
    except:
        pass
    return None

def deobfuscate_logic(content):
    """فك تشفير الأكواد المخفية لكشف الفخاخ البرمجية"""
    findings = ""
    # البحث عن سلاسل Base64 الطويلة (التي غالباً ما تخفي أكواد خبيثة)
    potential_b64 = re.findall(r'["\']([A-Za-z0-9+/]{40,})={0,2}["\']', content)
    for b in potential_b64:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            findings += " " + decoded
        except:
            continue
    return findings

def fetch_external_scripts(html, base_url):
    """جلب وتحليل ملفات الـ JS المرتبطة بالموقع"""
    scripts = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    js_code = ""
    for s in scripts[:3]: # نكتفي بأول 3 ملفات لضمان سرعة الاستجابة
        try:
            full_url = urljoin(base_url, s)
            r = requests.get(full_url, headers=HEADERS, timeout=4)
            js_code += "\n" + r.text
        except:
            continue
    return js_code

def perform_ultimate_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    try:
        session = requests.Session()
        # تتبع التحويلات بشكل كامل
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        main_html = response.text
        
        # تجميع كل الأكواد (HTML + JS خارجي + فك تشفير)
        full_code = main_html + fetch_external_scripts(main_html, final_url)
        full_code += deobfuscate_logic(full_code)

        # 1. تحليل عمر النطاق (Domain Age)
        domain = urlparse(final_url).netloc
        age = get_domain_age(domain)
        if age is not None:
            if age < 30: # موقع تم إنشاؤه في آخر شهر
                points += 50
                violated_rules.append({"name": "نطاق حديث جداً", "risk_description": f"هذا الموقع تم إنشاؤه منذ {age} يوم فقط. المواقع الجديدة هي البيئة المفضلة لهجمات التصيد.", "points_added": 50})
            elif age < 180: # أقل من 6 شهور
                points += 20
                violated_rules.append({"name": "نطاق غير مستقر", "risk_description": "عمر الموقع أقل من 6 أشهر، مما يجعله تحت مجهر المراجعة الأمنية.", "points_added": 20})

        # 2. كشف سلاسل التحويل (Redirect Chains)
        if len(response.history) > 2:
            points += 30
            violated_rules.append({"name": "سلسلة تحويل مريبة", "risk_description": "تم رصد قفزات متعددة للرابط، وهو أسلوب يستخدم لتجاوز أنظمة الحماية.", "points_added": 30})
        
        for r in response.history:
            if r.url not in redirect_path: redirect_path.append(r.url)
        if final_url not in redirect_path: redirect_path.append(final_url)

        # 3. رادار الأذونات المتقدم (Privacy & Exploit Detection)
        threat_map = {
            'Camera/Microphone': r'getUserMedia|mediaDevices|camera|video|microphone|record|capture',
            'Location/GPS': r'getCurrentPosition|watchPosition|geolocation',
            'Data Theft/Exfil': r'canvas\.toDataURL|atob\(|btoa\(|upload|POST|fetch|XMLHttpRequest',
            'Phishing Forms': r'password|credit_card|cvv|exp_month|ssn|social_security|pin_code'
        }

        for category, pattern in threat_map.items():
            if re.search(pattern, full_code, re.I):
                p_added = 70 if 'Camera' in category or 'Phishing' in category else 40
                points += p_added
                violated_rules.append({
                    "name": f"نشاط: {category}", 
                    "risk_description": "تم رصد محاولة برمجية للوصول إلى أجهزة النظام أو بيانات حساسة.", 
                    "points_added": p_added
                })

        # 4. تحليل النطاق وانتحال الصفة (Brand Protection)
        brands = ['facebook', 'google', 'paypal', 'microsoft', 'apple', 'amazon', 'netflix', 'binance']
        for b in brands:
            if b in domain.lower() and domain.lower() != f"{b}.com":
                points += 45
                violated_rules.append({"name": "اشتباه انتحال علامة تجارية", "risk_description": f"اسم النطاق يحاول تقليد موقع {b} الرسمي بطريقة مضللة.", "points_added": 45})

        if not final_url.startswith('https'):
            points += 50
            violated_rules.append({"name": "اتصال غير مشفر", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS الآمن.", "points_added": 50})

    except Exception:
        points += 30
        violated_rules.append({"name": "فشل التحليل العميق", "risk_description": "الموقع يستخدم تقنيات متقدمة لحجب الفحص، وهو مؤشر خطر عالي.", "points_added": 30})
        final_url = target_url

    # تصنيف الخطر النهائي
    total_points = min(points, 100)
    risk_level = "Critical" if total_points >= 80 else "High" if total_points >= 50 else "Medium" if total_points >= 25 else "Low"

    return {
        "risk_score": risk_level,
        "suspicious_points": total_points,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"message": "يرجى إدخال الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"message": "الرابط غير صالح"}), 400
    return jsonify(perform_ultimate_analysis(url))

@app.route('/robots.txt')
def robots(): return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory(app.static_folder, 'sitemap.xml')

if __name__ == '__main__':
    app.run(debug=True)

