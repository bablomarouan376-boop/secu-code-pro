import os
import time
from flask import Flask, request, jsonify, render_template
from validators import url  # للتحقق الاحترافي من الروابط
import requests
import json
import re # لمكتبة التعبيرات العادية لتطبيق القواعد

app = Flask(__name__)

# --- تعريف الـ 20 قاعدة أمنية مع الوصف التفصيلي ---
# كل عنصر هو قاموس يحتوي على (دالة الفحص، الاسم، الوصف التفصيلي للخطر)
SECURITY_RULES = [
    {
        "check": lambda link: any(service in link.lower() for service in ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "cutt.ly", "is.gd"]),
        "name": "اختصار الرابط (URL Shortener)",
        "risk": "قد يخفي الوجهة الحقيقية الضارة خلف رابط قصير وموثوق.",
        "points": 3
    },
    {
        "check": lambda link: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', link)),
        "name": "استخدام رقم IP مباشر",
        "risk": "قد يشير إلى خادم مؤقت أو موقع غير مسجل رسمياً، يستخدم لتجنب فحص DNS.",
        "points": 4
    },
    {
        "check": lambda link: '@' in link,
        "name": "وجود رمز @ في الرابط",
        "risk": "يستخدم لخداع المتصفح والزائر حول الوجهة الحقيقية للرابط (Phishing).",
        "points": 5
    },
    {
        "check": lambda link: len(link) > 80,
        "name": "الطول المبالغ فيه للرابط",
        "risk": "الروابط الطويلة جداً تستخدم أحياناً لإخفاء محتوى ضار أو لتجنب الفلاتر الأمنية.",
        "points": 2
    },
    {
        "check": lambda link: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'discount']),
        "name": "استخدام كلمات خداع شائعة",
        "risk": "يشير إلى محاولة خداع اجتماعي أو إغراء المستخدم لتقديم بيانات حساسة.",
        "points": 3
    },
    {
        "check": lambda link: link.lower().startswith('http://'),
        "name": "بروتوكول HTTP غير الآمن",
        "risk": "الرابط غير مشفر (غير HTTPS)، مما يعرض بيانات المستخدمين (مثل كلمات المرور) للتجسس.",
        "points": 6
    },
    {
        "check": lambda link: bool(re.search(r':\d{4,}', link)),
        "name": "استخدام منفذ غير قياسي",
        "risk": "قد يشير إلى تشغيل خدمات غير تقليدية أو غير معتادة على المنافذ المعروفة.",
        "points": 2
    },
    {
        "check": lambda link: link.count('=') > 5,
        "name": "كثرة المتغيرات في الرابط",
        "risk": "قد تكون محاولة لحقن أو تمرير معلمات ضخمة غير مرغوب فيها.",
        "points": 2
    },
    {
        "check": lambda link: link.count('.') > 3,
        "name": "كثرة النطاقات الفرعية العميقة",
        "risk": "تستخدم لتقليد المواقع الشرعية (مثل: secure.login.google.com.xyz).",
        "points": 3
    },
    {
        "check": lambda link: link.lower().endswith(('.cf', '.tk', '.ga', '.ml', '.xyz')),
        "name": "انتهاء نطاق مشبوه (TLD)",
        "risk": "امتدادات النطاقات هذه غالباً ما تستخدم في حملات التصيد والاحتيال لأنها مجانية أو رخيصة.",
        "points": 4
    },
    {
        "check": lambda link: any(word in link.lower() for word in ['secure', 'safe', 'trust', 'login', 'verify']) and 'https' not in link.lower(),
        "name": "كلمات أمان زائفة بدون تشفير",
        "risk": "محاولة إيهام المستخدم بالأمان (مثل رابط فيه 'secure' ولكنه HTTP).",
        "points": 5
    },
    {
        "check": lambda link: len(link.split('.')) > 2 and link.split('.')[0].lower() == link.split('.')[-2].lower(),
        "name": "تكرار النطاق الفرعي",
        "risk": "نوع من الخداع لتمرير اسم النطاق الأساسي مرتين لخداع العين.",
        "points": 2
    },
    {
        "check": lambda link: any(char.isdigit() for char in link.split('.')[1]) and link.count('.') >= 1,
        "name": "نطاق رئيسي يحتوي على أرقام",
        "risk": "النطاقات الرئيسية التي تحتوي على أرقام (مثل: pay123.com) غالباً ما تكون مشبوهة.",
        "points": 3
    },
    {
        "check": lambda link: bool(re.search(r'/\d{8,}/', link)),
        "name": "سلسلة أرقام طويلة في المسار",
        "risk": "قد تشير إلى ملفات تم تحميلها عشوائياً أو مسار مخفي وضخم.",
        "points": 2
    },
    {
        "check": lambda link: len(link) > 30 and link != link.lower() and link != link.upper(),
        "name": "أحرف كبيرة وصغيرة عشوائية",
        "risk": "تستخدم لتجاوز فلاتر البريد المزعج والفلاتر الأمنية البسيطة.",
        "points": 1
    },
    {
        "check": lambda link: '#' in link,
        "name": "استخدام رمز الـ Hash (#) كعلامة",
        "risk": "يستخدم لتمرير بيانات غير مرئية أو لتوجيه المستخدم إلى جزء معين من الصفحة.",
        "points": 1
    },
    {
        "check": lambda link: any(word in link.lower() for word in ['admin', 'upload', 'config']),
        "name": "كلمات إدارة وحساسة في الرابط",
        "risk": "قد يشير إلى محاولة الوصول لصفحة إدارة أو تحميل ملفات حساسة.",
        "points": 4
    },
    {
        "check": lambda link: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr')),
        "name": "الانتهاء بملف تنفيذي ضار",
        "risk": "يشير إلى أن الرابط سيقوم بتحميل أو تشغيل ملف تنفيذي مباشرة على جهاز المستخدم.",
        "points": 7
    },
    {
        "check": lambda link: link.count('http') > 1,
        "name": "تكرار البروتوكول",
        "risk": "محاولة خداع متقدمة لتمرير http/https داخل مسار الرابط (مثلاً: https://google.com/http:/malware).",
        "points": 5
    },
    {
        "check": lambda link: any(re.search(rf'f[ae]ceb?ook|go0gle|appple', link.lower())),
        "name": "خطأ إملائي في النطاق (Typosquatting)",
        "risk": "انتحال شخصية المواقع الكبرى باستخدام أخطاء إملائية (مثل goog1e.com) لسرقة بيانات الاعتماد.",
        "points": 7
    }
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    
    suspicious_points = 0
    detected_warnings = 0
    page_content_warning = "جاري الاتصال والتحليل..."
    
    # 1. فحص الاتصال بالرابط
    try:
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        
        if status_code != 200:
            suspicious_points += 5
            detected_warnings += 1
            page_content_warning = f"تحذير: الرابط يسبب خطأ {status_code}. (هذا يُعتبر مشبوهاً)."
        else:
            page_content_warning = "تم جلب محتوى الصفحة بنجاح."
            
    except requests.exceptions.RequestException:
        suspicious_points += 10
        detected_warnings += 1
        page_content_warning = "خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout)."
        status_code = 0
        
    # 2. تطبيق الـ 20 قاعدة أمنية
    violated_rules = []
    for i, rule in enumerate(SECURITY_RULES):
        try:
            if rule["check"](link):
                suspicious_points += rule["points"] # إضافة النقاط المخصصة للقاعدة
                detected_warnings += 1
                # تضمين اسم القاعدة ووصفها التفصيلي في النتيجة
                violated_rules.append({
                    "name": rule["name"],
                    "risk_description": rule["risk"],
                    "points_added": rule["points"]
                })
        except Exception as e:
            print(f"Error applying rule {rule['name']}: {e}") 
            pass

    # 3. تحديد مستوى الخطورة بناءً على النقاط
    risk_score = "Low"
    result_message = "آمن نسبيًا: لم يتم اكتشاف مخاطر واضحة."

    if suspicious_points > 35:
        risk_score = "Critical"
        result_message = "خطير! يحتوي على عدد كبير من نقاط الضعف والمخالفات الأمنية، مما يشير لاحتمالية عالية لكونه رابط تصيد أو ضار."
    elif suspicious_points > 20:
        risk_score = "High"
        result_message = "مرتفع: تم اكتشاف مخالفات هيكلية وسلوكية متعددة في الرابط. يفضل تجنبه."
    elif suspicious_points > 10:
        risk_score = "Medium"
        result_message = "متوسط: يحتوي على بعض العناصر المشبوهة التي قد تشكل خطراً. استخدم بحذر."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points <= 10 else "warning" if suspicious_points <= 20 else "error",
        "message": f"تحليل مكتمل. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص.",
        "link": link,
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": detected_warnings,
        "page_content_warning": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقطة النهاية الرئيسية (حل مشكلة الكاش) ---
@app.route('/', methods=['GET'])
def index():
    cache_buster = int(time.time()) 
    return render_template('index.html', cache_buster=cache_buster)


# --- نقطة النهاية للتحليل ---
@app.route('/analyze', methods=['POST'])
def analyze_link():
    
    try:
        data = request.get_json()
        link_to_analyze = data.get('link')
    except Exception:
        return jsonify({
            "status": "critical_error",
            "message": "خطأ في معالجة بيانات الطلب (JSON).",
            "error_code": 400
        }), 400

    if not link_to_analyze or link_to_analyze.strip() == "":
        return jsonify({
            "status": "validation_error",
            "message": "❌ فشل التحقق: الرجاء إدخال رابط. حقل الرابط لا يمكن أن يكون فارغاً.",
            "error_code": 400
        }), 400

    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    try:
        if url(link_to_analyze) is not True:
             return jsonify({
                "status": "validation_error",
                "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
                "error_code": 400
            }), 400
    except ImportError:
         pass


    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
