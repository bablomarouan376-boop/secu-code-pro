import os, re, requests, time
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse
from threading import Thread

app = Flask(__name__)

# بيانات المطور: طارق مصطفى
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# مسارات الملفات الثابتة (للتوافق مع محركات البحث)
@app.route('/robots.txt')
def robots(): return send_from_directory('static', 'robots.txt')

@app.route('/sitemap.xml')
def sitemap(): return send_from_directory('static', 'sitemap.xml')

@app.route('/sw.js')
def sw(): return send_from_directory('static', 'sw.js')

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, v_key = 0, "CLEAN"
    domain = urlparse(url).netloc.lower().replace('www.', '')

    try:
        # 1. فحص القوائم الموثوقة
        WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'github.com'}
        if any(w in domain for w in WHITELIST):
            score, v_key = 0, "TRUSTED"
        else:
            # 2. محاكاة فحص سلوكي (Request)
            res = requests.get(url, timeout=7, verify=False, headers={"User-Agent": "SecuCode-AI"})
            html = res.text
            if re.search(r'getUserMedia|camera|microphone', html, re.I):
                score, v_key = 95, "SPYWARE"
            elif len(re.findall(r'<script', html)) > 50:
                score, v_key = 65, "EXCESSIVE_SCRIPTS"
            else:
                score, v_key = 20, "CLEAN"
    except:
        score, v_key = 45, "SHIELD"

    # إشعار تليجرام
    try:
        msg = f"🔍 [SCAN] {domain}\n📊 Risk: {score}%\n🛡️ Key: {v_key}"
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg}, timeout=1)
    except: pass

    return jsonify({
        "risk_score": "Critical" if score >= 75 else "Safe",
        "points": score,
        "violation_key": v_key, # هذا هو مفتاح الترجمة
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

if __name__ == '__main__':
    app.run(debug=True)
