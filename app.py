import os
import re
import requests
import socket
import ssl
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from validators import url as validate_url

app = Flask(__name__)

# إعدادات الرأس لمحاكاة متصفح حقيقي وتجنب الحظر
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
}

def check_ssl_status(hostname):
    """فحص عميق لصحة شهادة SSL عبر الـ Sockets"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return True, "شهادة صالحة وموثوقة"
    except Exception:
        return False, "شهادة غير صالحة أو مفقودة"

def perform_deep_analysis(target_url):
    start_time = time.time()
    violated_rules = []
    redirect_path = [target_url]
    points = 0
    
    # --- 1. التحليل الديناميكي وتتبع التحويلات ---
    try:
        response = requests.get(target_url, headers=HEADERS, timeout=10, allow_redirects=True)
        final_url = response.url
        content = response.text
        
        # تتبع مسار الروابط بالكامل (Redirect Map)
        for resp in response.history:
            if resp.url not in redirect_path:
                redirect_path.append(resp.url)
        if final_url not in redirect_path:
            redirect_path.append(final_url)

        # فحص بروتوكول التشفير
        if not final_url.startswith('https'):
            points += 45
            violated_rules.append({"name": "اتصال غير مشفر (HTTP)", "risk_description": "الموقع لا يستخدم بروتوكول HTTPS، مما يعرض بياناتك لخطر التنصت.", "points_added": 45})
        else:
            is_valid, msg = check_ssl_status(urlparse(final_url).netloc)
            if not is_valid:
                points += 35
                violated_rules.append({"name": "خلل في شهادة SSL", "risk_description": "شهادة الأمان غير صالحة أو غير موثقة، مما يضعف الثقة في الموقع.", "points_added": 35})

    except Exception:
        points += 30
        violated_rules.append({"name": "تعذر الوصول للموقع", "risk_description": "الموقع لا يستجيب أو يحظر أدوات الفحص التلقائية.", "points_added": 30})
        final_url = target_url
        content = ""

    # --- 2. التحليل الساكن (Static Regex Analysis) ---
    parsed = urlparse(final_url)
    static_rules = [
        (r'@', 50, "استخدام رمز @ المريب", "يستخدم المخترقون هذا الرمز لتضليل المستخدمين وإخفاء النطاق الحقيقي."),
        (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 60, "عنوان IP مباشر", "استخدام الأرقام بدلاً من الأسماء هو سلوك كلاسيكي في مواقع التصيد."),
        (r'(login|verify|update|secure|bank|paypal|account|gift|bonus)', 30, "كلمات هندسة اجتماعية", "الرابط يحتوي على كلمات تهدف للتلاعب بمشاعر المستخدم واستعجاله."),
        (r'\.zip$|\.exe$|\.rar$|\.apk$|\.bat$', 90, "رابط تحميل مباشر لملف", "هذا الرابط سيقوم بتحميل ملف قد يحتوي على برمجيات ضارة فور النقر.")
    ]

    for pattern, pts, name, desc in static_rules:
        if re.search(pattern, final_url, re.I):
            points += pts
            violated_rules.append({"name": name, "risk_description": desc, "points_added": pts})

    if content and re.search(r'<input[^>]*type="password"', content, re.I):
        points += 50
        violated_rules.append({"name": "طلب كلمة مرور", "risk_description": "تم رصد نموذج إدخال كلمة مرور في موقع مشبوه يطلب بيانات حساسة.", "points_added": 50})

    # التصنيف النهائي للمخاطر
    risk = "Critical" if points >= 80 else "High" if points >= 45 else "Medium" if points >= 20 else "Low"

    return {
        "risk_score": risk,
        "suspicious_points": points,
        "violated_rules": violated_rules,
        "link_input": target_url,
        "link_final": final_url,
        "redirect_path": redirect_path,
        "execution_time": round(time.time() - start_time, 2)
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    raw_url = data.get('link', '').strip()
    if not raw_url:
        return jsonify({"message": "يرجى إدخال الرابط أولاً"}), 400
    
    if not raw_url.startswith(('http://', 'https://')):
        raw_url = 'https://' + raw_url
    
    if not validate_url(raw_url):
        return jsonify({"message": "تنسيق الرابط غير صحيح"}), 400
        
    return jsonify(perform_deep_analysis(raw_url))

if __name__ == '__main__':
    app.run(debug=True)

