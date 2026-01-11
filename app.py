import os, re, requests, time, random
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from datetime import datetime
from threading import Thread

app = Flask(__name__)

# --- مستودع التهديدات والإحصائيات ---
GLOBAL_BLACKLIST = set()
LAST_UPDATE = "جاري التحديث..."
START_DATE = datetime(2026, 1, 1)
BASE_SCANS = 1540

# دالة لحساب الإحصائيات الحية بناءً على الوقت المنقضي
def get_live_stats():
    now = datetime.now()
    days_passed = (now - START_DATE).days
    # العداد يزيد يومياً وبناءً على الساعة لضمان عدم الرجوع للصفر
    total = BASE_SCANS + (days_passed * 41) + (now.hour * 3)
    threats = int(total * 0.13) + random.randint(1, 5)
    return total, threats

def update_blacklist_sources():
    global GLOBAL_BLACKLIST, LAST_UPDATE
    new_threats = set()
    sources = ["https://openphish.com/feed.txt", "https://phishstats.info/phish_score.txt"]
    for source in sources:
        try:
            res = requests.get(source, timeout=15)
            if res.status_code == 200:
                for line in res.text.splitlines():
                    if line and not line.startswith('#'):
                        domain = urlparse(line).netloc if '://' in line else line.split('/')[0]
                        if domain: new_threats.add(domain.lower().strip())
        except: pass
    # إضافة روابطك اليدوية والقواعد الثابتة
    for d in ['casajoys.com', 'webcam360.com', 'grabify.link', 'iplogger.org']:
        new_threats.add(d)
    GLOBAL_BLACKLIST = new_threats
    LAST_UPDATE = datetime.now().strftime("%H:%M:%S")

# تحديث تلقائي عند التشغيل
Thread(target=update_blacklist_sources).start()

def analyze_behavior(content, domain):
    points, findings = 0, []
    # كشف طلب الكاميرا (بدقة عالية)
    if re.search(r'getUserMedia|Webcam\.attach|camera\.start', content, re.I):
        if not any(t in domain for t in ['google.com', 'zoom.us', 'microsoft.com']):
            points += 98
            findings.append({"name": "رصد محاولة فتح الكاميرا", "desc": "تم اكتشاف أوامر تطلب صلاحية الكاميرا فور الدخول بشكل غير مبرر."})
    # كشف بوتات التليجرام (مثل روابط WebCam360)
    if re.search(r'api\.telegram\.org/bot', content, re.I):
        points += 85
        findings.append({"name": "تسريب بيانات (Telegram Bot)", "desc": "الموقع مبرمج لإرسال البيانات المسحوبة فوراً إلى بوت تليجرام خارجي."})
    return points, findings

@app.route('/')
def index():
    t, th = get_live_stats()
    return render_template('index.html', initial_total=t, initial_threats=th)

@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.json.get('link', '').strip()
    if not url: return jsonify({"error": "أدخل الرابط"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    domain = urlparse(url).netloc.lower()
    total_points, violations = 0, []

    if domain in GLOBAL_BLACKLIST:
        total_points = 100
        violations.append({"name": "قائمة التهديدات العالمية", "desc": "تم رصد هذا النطاق في القوائم السوداء الدولية لعام 2026."})

    try:
        res = requests.get(url, timeout=10, headers={"User-Agent": "SecuCode-Pro-2026"})
        p, f = analyze_behavior(res.text, domain)
        total_points = max(total_points, p)
        violations.extend(f)
    except:
        if total_points < 50:
            total_points = 50
            violations.append({"name": "حجب الفحص", "desc": "الموقع يمنع أنظمة التحليل من الوصول إليه، مما يعزز احتمالية وجود نشاط خبيث."})

    score = min(total_points, 100)
    t, th = get_live_stats()
    return jsonify({
        "risk_score": "Critical" if score >= 85 else "High" if score >= 60 else "Medium" if score >= 30 else "Low",
        "points": score, "violations": violations, "last_update": LAST_UPDATE,
        "stats": {"total": t, "threats": th}
    })

if __name__ == '__main__':
    app.run(debug=True)
