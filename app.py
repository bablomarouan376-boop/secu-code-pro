import time
import re
import requests
from flask import Flask, render_template, send_from_directory, request, jsonify

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- 1. خدمات الأرشفة والملفات التعريفية (SEO, PWA, Google) ---

@app.route('/manifest.json')
def manifest():
    # لضمان ظهور أيقونة التطبيق SecuCode Pro
    return send_from_directory(app.static_folder, 'manifest.json')

@app.route('/sitemap.xml')
def sitemap():
    # لضمان أرشفة جوجل للموقع يومياً
    return send_from_directory(app.static_folder, 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    # لتوجيه محركات البحث ومنع العناكب من ملفات النظام
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/googlecc048452b42b8f02.html')
def google_verify():
    # إثبات ملكية جوجل Search Console الخاص بك
    return "google-site-verification: googlecc048452b42b8f02.html"


# --- 2. محرك الفحص الأمني المطور لـ SecuCode Pro ---

def deep_analyze(url):
    start_time = time.time()
    # الهيكل المتوافق مع تصميم واجهة المستخدم الخاصة بك
    data = {
        "points": 0,
        "risk_score": "Low",
        "redirects": [url],
        "violations": [],
        "analysis_time": 0
    }
    
    try:
        # استخدام هيدرز احترافي لتجنب حظر السيرفرات أثناء الفحص
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecuCodePro/3.5 (Tarek Mostafa Security Research)'
        }
        
        # تتبع التحويلات (Redirect Tracker) وكشف الرابط النهائي
        response = requests.get(url, timeout=10, headers=headers, allow_redirects=True)
        
        # تسجيل مسار التحويل بالكامل
        data["redirects"] = [r.url for r in response.history] + [response.url]
        content = response.text
        
        # الفحص الأول: تشفير الاتصال SSL
        if not response.url.startswith('https'):
            data["points"] += 45
            data["violations"].append({
                "name": "اتصال غير مشفر (HTTP)", 
                "desc": "هذا الموقع لا يستخدم بروتوكول HTTPS، مما يجعل البيانات المتبادلة عرضة للتنصت."
            })

        # الفحص الثاني: كشف التشفير المريب (Base64)
        # البحث عن نصوص مشفرة طويلة جداً غالباً ما تخفي برمجيات خبيثة
        if len(re.findall(r"([A-Za-z0-9+/]{60,}=*)", content)) > 0:
            data["points"] += 35
            data["violations"].append({
                "name": "تشفير Base64 مشبوه", 
                "desc": "تم رصد محاولات إخفاء أكواد برمجية في بنية الموقع."
            })

        # الفحص الثالث: تحليل أنماط التصيد الاحتيالي (Phishing)
        phish_keywords = ['login', 'verify', 'password', 'bank', 'signin', 'secure', 'account']
        if any(word in content.lower() for word in phish_keywords):
            data["points"] += 20
            data["violations"].append({
                "name": "اشتباه تصيد (Phishing)", 
                "desc": "الصفحة تحتوي على حقول تطلب بيانات حساسة في سياق يثير الريبة."
            })

    except Exception as e:
        # في حال فشل الوصول للموقع (محمي أو معطل)
        data["risk_score"] = "Medium"
        data["violations"].append({
            "name": "فحص محدود", 
            "desc": "الموقع يمنع أدوات الفحص التلقائي أو غير متاح حالياً، يرجى الحذر."
        })

    # حساب تصنيف الخطورة النهائي
    p = data["points"]
    if p >= 80:
        data["risk_score"] = "Critical"
    elif p >= 50:
        data["risk_score"] = "High"
    elif p >= 25:
        data["risk_score"] = "Medium"
    else:
        data["risk_score"] = "Low"
    
    data["analysis_time"] = round(time.time() - start_time, 2)
    return data


# --- 3. المسارات الرئيسية (Routes) ---

@app.route('/')
def index():
    # عرض الواجهة الرئيسية المصممة بواسطة طارق مصطفى
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # استقبال طلبات الفحص من الواجهة
    req = request.json or {}
    url = req.get('link', '').strip()
    
    if not url:
        return jsonify({"error": "يرجى إدخال رابط صالح"}), 400
    
    # التأكد من وجود البروتوكول قبل الفحص
    if not url.startswith('http'):
        url = 'https://' + url
        
    return jsonify(deep_analyze(url))

if __name__ == '__main__':
    # تشغيل السيرفر في وضع التطوير
    app.run(debug=True)
