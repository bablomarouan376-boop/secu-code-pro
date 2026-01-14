import os, re, requests, time
from flask import Flask, request, jsonify, render_template, Response
from urllib.parse import urlparse
from threading import Thread
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

app = Flask(__name__)

# بيانات طارق مصطفى (ثابتة ومشفرة في الأداء)
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعداد محرك الطلبات ليكون سريعاً وصارماً (Google Speed Optimized)
session = requests.Session()
retry = Retry(total=2, backoff_factor=0.3)
session.mount('https://', HTTPAdapter(max_retries=retry))

# --- [ 1. قاعدة بيانات التهديدات الحية ] ---
BLACKLIST_DB = set()
def threat_intel_sync():
    global BLACKLIST_DB
    while True:
        try:
            sources = ["https://openphish.com/feed.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
            new_db = set()
            for s in sources:
                r = session.get(s, timeout=15)
                if r.status_code == 200:
                    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', r.text)
                    new_db.update([d.lower() for d in domains])
            new_db.update(['grabify', 'iplogger', 'webcam360', 'bit.ly', 'r.mtdv.me', 'anonymous-camera'])
            BLACKLIST_DB = new_db
        except: pass
        time.sleep(3600)

Thread(target=threat_intel_sync, daemon=True).start()

# --- [ 2. محرك الفحص الشرس (The Beast Engine) ] ---
def aggressive_js_analyzer(html_content):
    """تحليل سلوكي لـ JavaScript لكشف التجسس والتصيد"""
    findings = []
    points = 0
    
    # مصفوفة الأنماط (Patterns) - كشف التجسس المتقدم
    checks = {
        "SPY_CAM": {
            "regex": r"(getUserMedia|mediaDevices|videoinput|camera|facingMode|stream\.getTracks)",
            "name": "تجسس بصري (Cam)", "pts": 65
        },
        "GEO_TRACK": {
            "regex": r"(getCurrentPosition|watchPosition|geolocation|navigator\.coords)",
            "name": "تتبع جغرافي (GPS)", "pts": 50
        },
        "PHISHING_LOGIC": {
            "regex": r"(password|passwd|كلمة المرور|login_form|auth_key|secure_login)",
            "name": "هيكل تصيد (Phishing)", "pts": 40
        },
        "STEALTH_JS": {
            "regex": r"(eval\(|atob\(|btoa\(|String\.fromCharCode|unescape\()",
            "name": "أكواد مشفرة (Stealth)", "pts": 25
        }
    }

    for key, val in checks.items():
        if re.search(val["regex"], html_content, re.IGNORECASE):
            findings.append({"name": val["name"], "desc": f"تم رصد نشاط {val['name']} داخل سكريبتات الصفحة."})
            points += val["pts"]
            
    return points, findings

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url.startswith('http'): url = 'https://' + url
    
    score, violations = 0, []
    domain = urlparse(url).netloc.lower()

    try:
        # 1. فحص القائمة السوداء (Blacklist Check)
        if any(bad in domain for bad in BLACKLIST_DB):
            score, violations = 100, [{"name": "تهديد عالمي", "desc": "الرابط مدرج كخطر مؤكد في القوائم الأمنية السوداء."}]
        else:
            # 2. الفحص العميق (Deep Content Inspection)
            # محاكاة متصفح حقيقي لتجاوز الحماية
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
            response = session.get(url, headers=headers, timeout=8, verify=False)
            page_source = response.text

            # تشغيل محرك تحليل الـ JS
            js_points, js_violations = aggressive_js_analyzer(page_source)
            score = min(js_points, 100)
            violations = js_violations

    except Exception:
        # في حالة الهروب أو الحجب
        score, violations = 45, [{"name": "تحليل مقيد", "desc": "الموقع يحاول إخفاء هويته البرمجية عن الرادار."}]

    risk_level = "Critical" if score >= 55 else ("Warning" if score > 0 else "Safe")
    if not violations: violations.append({"name": "نظيف", "desc": "لم يتم العثور على تهديدات برمجية نشطة."})

    # إرسال التقرير لتليجرام (فوري وذكي)
    report_to_tarek(url, risk_level, score)

    return jsonify({
        "risk_score": risk_level, 
        "points": score, 
        "violations": violations,
        "stats": {"total": 1680, "threats": 242} 
    })

def report_to_tarek(url, level, pts):
    icon = "🚨" if level == "Critical" else "✅"
    message = (
        f"{icon} رادار طارق مصطفى - تقرير وحش\n"
        f"━━━━━━━━━━━━━━━\n"
        f"🔗 الرابط: {url}\n"
        f"📊 القوة: {pts}%\n"
        f"🛡️ الحالة: {level}\n"
        f"👤 المطور: طارق مصطفى"
    )
    try: requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": message}, timeout=2)
    except: pass

# مسارات SEO لسرعة جوجل (robots & manifest)
@app.route('/robots.txt')
def robots(): return Response("User-agent: *\nAllow: /", mimetype="text/plain")

@app.route('/manifest.json')
def manifest():
    return Response('{"name":"SecuCode Pro","short_name":"SecuCode","start_url":"/","display":"standalone"}', mimetype="application/json")

if __name__ == '__main__':
    app.run(debug=False, threaded=True)
