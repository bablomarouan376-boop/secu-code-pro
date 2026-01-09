import os
import re
import requests
import time
import base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse, urljoin
from validators import url as validate_url
from datetime import datetime

app = Flask(__name__, static_folder='static', template_folder='templates')

# رؤوس طلبات احترافية لمحاكاة متصفح حقيقي بالكامل
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
}

def decode_base64_in_text(text):
    """البحث عن نصوص Base64 داخل الكود وفكها لكشف الروابط المستترة"""
    decoded_fragments = ""
    # نمط للبحث عن نصوص قد تكون Base64 (طولها أكثر من 20 حرف)
    potential_b64 = re.findall(r'["\']([A-Za-z0-9+/]{20,})={0,2}["\']', text)
    for b in potential_b64:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            if any(key in decoded for key in ['http', 'eval', 'script', 'camera', 'token']):
                decoded_fragments += "\n" + decoded
        except: continue
    return decoded_fragments

def get_all_js_content(html, base_url):
    """جلب كل محتوى الجافا سكريبت (الداخلي والخارجي)"""
    all_js = ""
    # 1. استخراج السكربتات الداخلية (Inline Scripts)
    inline_scripts = re.findall(r'<script>(.*?)</script>', html, re.DOTALL | re.I)
    all_js += "\n".join(inline_scripts)

    # 2. جلب السكربتات الخارجية (External Scripts)
    script_urls = re.findall(r'<script src=["\'](.*?)["\']', html, re.I)
    for s_url in script_urls[:5]: # فحص أول 5 ملفات لضمان السرعة
        try:
            full_url = urljoin(base_url, s_url)
            res = requests.get(full_url, headers=HEADERS, timeout=4)
            all_js += "\n" + res.text
        except: continue
    return all_js

def perform_ultimate_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    risk_points = 0
    redirect_path = [target_url]
    
    try:
        session = requests.Session()
        # تتبع التحويلات بالكامل
        response = session.get(target_url, headers=HEADERS, timeout=12, allow_redirects=True)
        final_url = response.url
        main_html = response.text
        
        # تجميع كل "أحشاء" الصفحة (HTML + JS + Decoded Base64)
        js_content = get_all_js_content(main_html, final_url)
        hidden_logic = decode_base64_in_text(main_html + js_content)
        full_page_intel = main_html + js_content + hidden_logic

        # --- المحرك التحليلي ---
        
        # 1. كشف محاولات فتح الكاميرا/الميكروفون (البرمجية)
        privacy_triggers = {
            'الوصول للكاميرا/المايك': r'getUserMedia|mediaDevices\.getUserMedia|camera|videoChat',
            'تسجيل الصوت': r'AudioContext|createMediaStreamSource|record',
            'تتبع الموقع': r'getCurrentPosition|watchPosition'
        }
        for label, pattern in privacy_triggers.items():
            if re.search(pattern, full_page_intel, re.I):
                risk_points += 80
                violated_rules.append({"name": f"انتهاك خصوصية: {label}", "risk_description": "تم رصد كود يحاول الوصول للأجهزة الحساسة تلقائياً."})

        # 2. تحليل الروابط والتحويلات (القفزات)
        if len(response.history) > 1:
            risk_points += 30
            violated_rules.append({"name": "تعدد التحويلات", "risk_description": f"الرابط قام بالقفز {len(response.history)} مرة لإخفاء هويته."})
        for r in response.history: redirect_path.append(r.url)

        # 3. كشف التصيد وانتحال الهوية
        domain = urlparse(final_url).netloc.lower()
        brands = ['facebook', 'google', 'instagram', 'snapchat', 'paypal', 'binance', 'apple']
        for b in brands:
            if b in domain and not (domain.endswith(f"{b}.com") or domain.endswith(f"{b}.net")):
                risk_points += 70
                violated_rules.append({"name": "انتحال علامة تجارية", "risk_description": f"الموقع يدعي أنه {b} لكن الرابط غير رسمي."})

        # 4. تحليل الـ HTML (نماذج سرقة البيانات)
        if re.search(r'type=["\']password["\']', main_html, re.I):
            if risk_points > 20: # إذا اجتمع مع عامل خطر آخر
                risk_points += 40
                violated_rules.append({"name": "صفحة دخول مريبة", "risk_description": "يوجد نموذج طلب كلمة مرور في موقع غير موثوق."})

    except Exception:
        risk_points = 25
        violated_rules.append({"name": "فحص غير مكتمل", "risk_description": "الموقع حظر محرك الفحص، وهذا سلوك مريب جداً."})
        final_url = target_url

    # النتيجة النهائية
    final_score = min(risk_points, 100)
    risk_label = "Critical" if final_score >= 75 else "High" if final_score >= 45 else "Medium" if final_score >= 20 else "Safe"

    return {
        "risk_score": risk_label,
        "suspicious_points": final_score,
        "violated_rules": violated_rules,
        "link_final": final_url,
        "redirect_path": list(dict.fromkeys(redirect_path)),
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
