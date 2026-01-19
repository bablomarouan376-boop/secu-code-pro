import os, json, requests, time, base64
from flask import Flask, render_template, request, jsonify
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)

# إعداد Firebase (تأكد من وضع البيانات في Environment Variables في Vercel)
fb_creds = os.environ.get('FIREBASE_CREDENTIALS')
if fb_creds:
    try:
        creds_dict = json.loads(fb_creds)
        if not firebase_admin._apps:
            cred = credentials.Certificate(creds_dict)
            firebase_admin.initialize_app(cred, {'databaseURL': 'https://secucode-pro-default-rtdb.firebaseio.com/'})
    except: pass

VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY') or '07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564'
TG_TOKEN = os.environ.get('TELEGRAM_TOKEN') or '8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o'
CH_ID = os.environ.get('CHAT_ID') or '7421725464'

@app.route('/')
def index(): return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.json
    url = data.get('url')
    user_id = data.get('user_id', 'anonymous')
    
    # تحويل الرابط لـ ID متوافق مع VirusTotal
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {"x-apikey": VT_API_KEY}
    vt_result = {"malicious": 0, "harmless": 0, "undetected": 0}
    
    try:
        # جلب التحليل الأخير مباشرة لتسريع العملية
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if res.status_code == 200:
            vt_result = res.json()['data']['attributes']['last_analysis_stats']
        else:
            # إذا لم يكن موجوداً، نطلب فحصاً جديداً
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    except: pass

    status = "danger" if vt_result.get('malicious', 0) > 0 else "safe"

    # تحديث Firebase
    try:
        db.reference('stats/total_scans').transaction(lambda curr: (curr or 0) + 1)
        if status == "danger":
            db.reference('stats/malicious_found').transaction(lambda curr: (curr or 0) + 1)
        
        db.reference(f'history/{user_id}').push({
            'url': url, 'status': status, 'vt': vt_result, 'timestamp': time.time()
        })
    except: pass

    # إرسال تلجرام صامت (بدون إزعاج المستخدم في الواجهة)
    try:
        msg = f"🛡️ *SecuCode Scan*\n🔗 URL: {url}\n🚦 Status: {status.upper()}\n📊 Stats: {vt_result}"
        requests.post(f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage", json={"chat_id": CH_ID, "text": msg, "parse_mode": "Markdown"})
    except: pass

    return jsonify({"status": "success", "data": vt_result, "risk": status})

@app.route('/history/<user_id>')
def get_history(user_id):
    data = db.reference(f'history/{user_id}').get() or {}
    return jsonify(list(data.values())[::-1])

if __name__ == '__main__':
    app.run(debug=True)
