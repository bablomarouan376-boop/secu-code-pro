import os
import re
import requests
import time
from flask import Flask, request, jsonify, render_template, send_from_directory, make_response
from urllib.parse import urlparse
from validators import url as validate_url

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- مسارات ملفات الأرشفة و PWA ---
@app.route('/sitemap.xml')
def sitemap():
    response = make_response(send_from_directory(app.static_folder, 'sitemap.xml'))
    response.headers['Content-Type'] = 'application/xml'
    return response

@app.route('/robots.txt')
def robots():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/manifest.json')
def manifest():
    return send_from_directory(app.static_folder, 'manifest.json')

# --- محرك الفحص الأمني (النسخة الاحترافية) ---
SENSITIVE_PATTERNS = {
    "Credential Harvesting": r'(?i)(password|passwd|signin|login|credential|verification)',
    "Browser Exploitation": r'(?i)(eval\(|unescape\(|document\.write\(|setTimeout\(|setInterval\()',
    "Data Exfiltration": r'(?i)(XMLHttpRequest|fetch|ajax|\.post\(|\.get\()',
    "Privacy Violation": r'(?i)(navigator\.mediaDevices|getUserMedia|geolocation|cookie|localStorage)'
}

WHITELIST = ['google.com', 'facebook.com', 'vercel.app', 'github.com', 'microsoft.com', 'apple.com']

def is_trusted(url):
    domain = urlparse(url).netloc.lower().replace('www.', '')
    return any(domain == d or domain.endswith('.' + d) for d in WHITELIST)

def perform_deep_scan(url):
    start_time = time.time()
    results = {"risk_score": "Low", "points": 0, "violations": [], "analysis_time": 0}
    try:
        session = requests.Session()
        response = session.get(url, timeout=7, headers={"User-Agent": "Mozilla/5.0 SecuCode/2.0"}, allow_redirects=True)
        final_url = response.url
        
        if is_trusted(final_url): 
            return {"risk_score": "Safe", "points": 5, "analysis_time": 0.1, "violations": []}

        full_payload = response.text.lower()
        if not final_url.startswith('https'):
            results["points"] += 45
            results["violations"].append({"name": "اتصال غير مشفر", "desc": "الموقع لا يستخدم بروتوكول HTTPS."})

        for threat, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, full_payload):
                results["points"] += 25
                results["violations"].append({"name": threat, "desc": "تم رصد أكواد برمجية مشبوهة."})

    except:
        results["risk_score"] = "Unknown"
        results["violations"].append({"name": "فشل الفحص", "desc": "الموقع قد يحظر أدوات التحليل الآلي."})
    
    score = min(results["points"], 100)
    results["points"] = score
    results["risk_score"] = "Critical" if score >= 80 else "High" if score >= 50 else "Medium" if score >= 25 else "Low"
    results["analysis_time"] = round(time.time() - start_time, 2)
    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json or {}
    url = data.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    if not validate_url(url): return jsonify({"error": "الرابط غير صالح"}), 400
    return jsonify(perform_deep_scan(url))

if __name__ == '__main__':
    app.run(debug=True)
