import os
import re
import requests
import time
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
from urllib.parse import urlparse
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- نظام تخطي شروط الربط وتقديم الملفات (PWA & SEO) ---
@app.route('/manifest.json')
def manifest():
    """تخطي مشاكل الربط بتقديم المانيفست مباشرة"""
    return send_from_directory(app.static_folder, 'manifest.json')

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

# --- محرك الذكاء الأمني المطور (The Core Engine) ---

# أنماط متقدمة جداً لكشف الاختراق وسرقة البيانات
ADVANCED_PATTERNS = {
    "Stealth Phishing": r'(?i)(secure-login|verify-account|update-billing|auth-check)',
    "JS-Malware": r'(?i)(atob\(|btoa\(|String\.fromCharCode|String\.raw|Buffer\.from)',
    "Session Hijacking": r'(?i)(document\.cookie|sessionStorage|indexedDB|bearer\s)',
    "UI Redressing": r'(?i)(iframe|opacity:\s?0|pointer-events:\s?none)',
    "Keylogging Pattern": r'(?i)(addEventListener\("keydown"|onkeypress|input\.value)'
}

def perform_ultra_scan(url):
    """فحص فائق السرعة والدقة يتخطى قيود المواقع"""
    start_time = time.time()
    results = {"risk_score": "Safe", "points": 0, "details": [], "analysis_time": 0}
    
    try:
        # استخدام نظام محاكاة المتصفحات البشرية لتجنب الحظر
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9,ar;q=0.8"
        }
        
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        content = response.text.lower()
        
        # 1. فحص تشفير الدومين
        if not response.url.startswith('https'):
            results["points"] += 50
            results["details"].append("اتصال غير مشفر (Insecure SSL)")

        # 2. تحليل الكود البرمجي (Heuristic Scan)
        for threat, pattern in ADVANCED_PATTERNS.items():
            if re.search(pattern, content):
                results["points"] += 30
                results["details"].append(f"سلوك مريب: {threat}")

        # 3. فحص الروابط المخفية (Hidden Redirects)
        if len(response.history) > 3:
            results["points"] += 20
            results["details"].append("تحويلات متعددة مشبوهة")

    except Exception as e:
        results["risk_score"] = "Blocked"
        results["details"].append("الموقع يرفض الفحص أو غير متاح")

    # تحديد التقييم النهائي
    score = min(results["points"], 100)
    results["points"] = score
    if score >= 75: results["risk_score"] = "Dangerous"
    elif score >= 40: results["risk_score"] = "Suspicious"
    else: results["risk_score"] = "Verified Safe"
    
    results["analysis_time"] = round(time.time() - start_time, 2)
    return results

# --- المسارات الذكية ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    url = data.get('link', '').strip()
    
    if not url: return jsonify({"error": "Missing URL"}), 400
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"error": "Invalid URL format"}), 400
        
    return jsonify(perform_ultra_scan(url))

if __name__ == '__main__':
    app.run(debug=True)
