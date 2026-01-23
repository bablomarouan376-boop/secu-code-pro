import os
import json
import requests
import base64
import urllib3
import time
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db

# كتم تحذيرات SSL لضمان عدم توقف الفحص الجنائي عند فحص مواقع غير مؤمنة
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, template_folder='templates')

# ==========================================================
# إعدادات النظام - المطور: طارق مصطفى (SecuCode Pro 2026)
# ==========================================================
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"
FIREBASE_URL = "https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app"

# إعداد قاعدة بيانات Firebase للعدادات الحية
try:
    if not firebase_admin._apps:
        # ملاحظة: إذا كنت ترفع الكود على Vercel، يفضل استخدام Certificate
        # هنا نستخدم الطريقة المباشرة للربط عبر رابط قاعدة البيانات
        firebase_admin.initialize_app(options={
            'databaseURL': FIREBASE_URL
        })
    print("[+] Firebase Connected Successfully")
except Exception as e:
    print(f"[-] Firebase Connection Alert: {e}")

# ==========================================================
# وظائف الفحص الجنائي (Forensic Functions)
# ==========================================================

def check_spyware_behavior(url):
    """
    تحليل كود الصفحة (HTML/JS) لكشف طلبات التجسس
    مثل فتح الكاميرا، الميكروفون، أو تتبع الموقع الجغرافي
    """
    try:
        headers = {
            "User-Agent": "SecuCode-Forensic/2.0 (Security Audit by Tarek Mostafa)",
            "Accept-Language": "en-US,en;q=0.9"
        }
        # جلب محتوى الصفحة
        response = requests.get(url, timeout=7, headers=headers, verify=False)
        content = response.text.lower()
        
        # أنماط برمجية مشبوهة
        spy_patterns = [
            'getusermedia', 'navigator.mediadevices', 'video', 
            'canvas.todataurl', 'geolocation.getcurrentposition', 
            'track.stop', 'recorder.start', 'webcam.js'
        ]
        
        # البحث عن أي نمط داخل الكود
        found_threats = [p for p in spy_patterns if p in content]
        return len(found_threats) > 0
    except Exception as e:
        print(f"[-] Behavioral Analysis Error: {e}")
        return False

def get_vt_analysis(url):
    """جلب بيانات الاستخبارات الأمنية من VirusTotal API v3"""
    try:
        # تشفير الرابط حسب متطلبات API v3 (Base64 URL Safe)
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        
        # طلب بيانات الفحص الأخير
        res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", 
            headers=headers, 
            timeout=10
        )
        
        if res.status_code == 200:
            return res.json()['data']['attributes']['last_analysis_stats']
        else:
            # إذا لم يكن الرابط مفحوصاً مسبقاً، نطلب فحصاً جديداً
            requests.post(
                "https://www.virustotal.com/api/v3/urls", 
                headers=headers, 
                data={"url": url}
            )
            return None
    except Exception as e:
        print(f"[-] VirusTotal API Connection Error: {e}")
        return None

def send_telegram_alert(domain, is_spyware, m_count, score):
    """إرسال تقرير الفحص فوراً إلى بوت التليجرام الخاص بطارق"""
    try:
        status_icon = "🚨" if (is_spyware or m_count > 0) else "✅"
        threat_status = "CRITICAL THREAT" if (is_spyware or m_count > 0) else "SECURE DOMAIN"
        
        msg = (
            f"{status_icon} *SecuCode Pro: Forensic Report*\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"🌐 *Domain:* `{domain}`\n"
            f"🛡️ *Status:* {threat_status}\n"
            f"📸 *Spyware:* {'DETECTED' if is_spyware else 'CLEAN'}\n"
            f"🚨 *Malicious Engines:* {m_count}\n"
            f"📊 *Risk Level:* {score}%\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"👤 *Analyst:* Tarek Mostafa Core"
        )
        
        tg_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": CH_ID if 'CH_ID' in locals() else CHAT_ID,
            "text": msg,
            "parse_mode": "Markdown"
        }
        
        requests.post(tg_url, json=payload, timeout=5)
    except Exception as e:
        print(f"[-] Telegram Notification Error: {e}")

# ==========================================================
# مسارات السيرفر (Server Routes)
# ==========================================================

@app.route('/')
def index():
    """عرض الواجهة الرئيسية"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """نقطة النهاية لمعالجة طلبات الفحص"""
    data = request.json
    raw_url = data.get('link', '').strip()
    
    if not raw_url:
        return jsonify({"error": "Empty URL"}), 400
    
    # تصحيح صيغة الرابط وإضافة البروتوكول إذا نقص
    url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
    domain = urlparse(url).netloc.lower() or url
    
    # 1. تنفيذ الفحص السلوكي (تجسس الكاميرا والموقع)
    spy_detected = check_spyware_behavior(url)
    
    # 2. تنفيذ فحص الاستخبارات العالمية (VirusTotal)
    vt_stats = get_vt_analysis(url)
    m_count = vt_stats.get('malicious', 0) if vt_stats else 0
    
    # 3. منطق حساب معامل الخطورة (Risk Scoring Logic)
    if spy_detected:
        risk_score = 99.9
    elif m_count > 0:
        # كل محرك يكتشف التهديد يزيد النسبة بـ 20% بحد أقصى 100%
        risk_score = min(m_count * 20, 100)
    else:
        risk_score = 0

    is_blacklisted = (spy_detected or m_count > 0)

    # 4. تحديث العدادات اللحظية في Firebase
    try:
        stats_ref = db.reference('stats')
        # زيادة عدد الفحوصات الكلية
        stats_ref.child('clicks').transaction(lambda c: (c or 0) + 1)
        
        # إذا كان تهديداً، نزيد عداد التهديدات المكتشفة
        if is_blacklisted:
            stats_ref.child('threats').transaction(lambda t: (t or 0) + 1)
    except Exception as e:
        print(f"[-] Firebase Update Error: {e}")

    # 5. إرسال التنبيه الفوري للمطور طارق
    send_telegram_alert(domain, spy_detected, m_count, risk_score)

    # 6. الاستجابة للواجهة الأمامية بالبيانات الكاملة
    return jsonify({
        "is_official": (risk_score == 0 and ("google" in domain or "microsoft" in domain or ".gov" in domain)),
        "is_blacklisted": is_blacklisted,
        "risk_score": risk_score,
        "spy_detected": spy_detected,
        "engines_found": m_count,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

# ==========================================================
# تشغيل النظام
# ==========================================================

if __name__ == '__main__':
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("   SecuCode Pro Backend - Version 2.0")
    print("   Developed by: Tarek Mostafa (2026)")
    print("   Status: Operational / Port: 5000")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    app.run(host='0.0.0.0', port=5000, debug=True)
