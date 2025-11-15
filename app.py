import os
from flask import Flask, request, jsonify, render_template
import requests
import re 
from urllib.parse import urlparse
from validators import url

# تهيئة تطبيق Flask
app = Flask(__name__)

# --- تعريف 42 قاعدة أمنية احترافية ومُعدلة (نقاط المخاطر مضخمة جداً) ---
SECURITY_RULES = [
    # ----------------------------------------------------
    # مجموعة 1: قواعد فحص البنية العامة والتخفي (Obfuscation)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(service in link.lower() for service in ["bit.ly", "goo.gl", "tinyurl", "ow.ly", "cutt.ly", "is.gd", "t.co", "rebrand.ly"]),
        "name": "اختصار الرابط (URL Shortener)",
        "risk": "قد يخفي الوجهة الحقيقية الضارة خلف رابط قصير وموثوق.",
        "points": 10 
    },
    {
        "check": lambda link, content: bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(link).netloc)),
        "name": "استخدام رقم IP مباشر في النطاق",
        "risk": "يشير إلى خادم مؤقت أو موقع غير مسجل رسمياً. **خطر عالٍ جداً.**",
        "points": 30 
    },
    {
        "check": lambda link, content: '@' in link,
        "name": "وجود رمز @ في الرابط (User Info Obfuscation)",
        "risk": "يستخدم لخداع المتصفح والزائر حول الوجهة الحقيقية. **خطر حرج.**",
        "points": 40 
    },
    {
        "check": lambda link, content: len(link) > 100,
        "name": "الطول المبالغ فيه للرابط (>100 حرف)",
        "risk": "الروابط الطويلة جداً تستخدم أحياناً لإخفاء محتوى ضار.",
        "points": 5 
    },
    {
        "check": lambda link, content: link.lower().startswith('http://'),
        "name": "بروتوكول HTTP غير الآمن",
        "risk": "الرابط غير مشفر (غير HTTPS). **خطر حرج.**",
        "points": 30 
    },
    {
        "check": lambda link, content: bool(re.search(r':\d{4,}', link)),
        "name": "استخدام منفذ غير قياسي",
        "risk": "قد يشير إلى تشغيل خدمات غير تقليدية أو غير معتادة.",
        "points": 8 
    },
    {
        "check": lambda link, content: link.count('=') > 7,
        "name": "كثرة المتغيرات في الرابط (>7)",
        "risk": "قد تكون محاولة لحقن أو تمرير معلمات ضخمة.",
        "points": 4
    },
    {
        "check": lambda link, content: link.count('.') > 4,
        "name": "كثرة النطاقات الفرعية العميقة (>4)",
        "risk": "تستخدم لتقليد المواقع الشرعية (مثل: secure.login.google.com.xyz.com). **خداع بصري واضح.**",
        "points": 15 
    },
    {
        "check": lambda link, content: link.count('http') > 1,
        "name": "تكرار البروتوكول داخل الرابط",
        "risk": "محاولة خداع متقدمة لتمرير http/https داخل مسار الرابط.",
        "points": 15 
    },
    {
        "check": lambda link, content: 'xn--' in link.lower(),
        "name": "وجود Punycode/IDN (خداع الأحرف الدولية)",
        "risk": "يشير إلى استخدام أسماء نطاقات دولية قد تُستخدم لانتحال شخصية موقع آخر. **خطر حرج.**",
        "points": 35 
    },
    {
        "check": lambda link, content: bool(re.search(r'%.{2}', link)),
        "name": "وجود ترميز URL (%XX)",
        "risk": "يشير إلى وجود أحرف مشفرة قد تخفي كلمات مفتاحية ضارة.",
        "points": 5
    },
    {
        "check": lambda link, content: 'data:' in link.lower() or 'javascript:' in link.lower(),
        "name": "استخدام أنظمة URI خطيرة (Data/JavaScript)",
        "risk": "يسمح بتشغيل كود JavaScript مباشرة أو تضمين محتوى كقاعدة 64. **خطر عالٍ جداً.**",
        "points": 30 
    },
    {
        "check": lambda link, content: bool(re.search(r'\.\./|\.\.\\|\.\.%2f|\.\.%5c', link, re.IGNORECASE)),
        "name": "مؤشر لـ Directory Traversal",
        "risk": "محاولة للوصول إلى ملفات خارج المسار المخصص على الخادم.",
        "points": 12 
    },
    {
        "check": lambda link, content: '//' in urlparse(link).path,
        "name": "مسارات مزدوجة متكررة (Redundant Slashes)",
        "risk": "قد يُستخدم للتخفي أو لإرباك المتصفحات والفلاتر الأمنية البسيطة.",
        "points": 4
    },
    {
        "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 25,
        "name": "طول مبالغ فيه للنطاق الفرعي (Subdomain)",
        "risk": "النطاقات الفرعية الطويلة جداً غالباً ما تكون مؤشراً على الإزعاج أو الخداع.",
        "points": 6
    },
    
    # ----------------------------------------------------
    # مجموعة 2: قواعد فحص النطاق و Typosquatting (الاحتيال الإملائي)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(ext in link.lower() for ext in ['.cf', '.tk', '.ga', '.ml', '.xyz', '.cc', '.info', '.biz', '.top']),
        "name": "انتهاء نطاق مشبوه (TLD)",
        "risk": "امتدادات النطاقات هذه غالباً ما تستخدم في حملات التصيد والاحتيال.",
        "points": 10 
    },
    {
        "check": lambda link, content: any(re.search(rf'{word}', link.lower()) for word in ['faceb?ook', 'g00gle', 'appple', 'micr0s0ft', 'am@zon', 'payp@l']),
        "name": "خطأ إملائي في النطاق (Typosquatting - متقدم)",
        "risk": "انتحال شخصية المواقع الكبرى باستخدام أخطاء إملائية ذكية. **خطر حرج.**",
        "points": 50 
    },
    {
        "check": lambda link, content: any(company in link.lower() for company in ['microsoft', 'apple', 'amazon', 'facebook', 'google']) and 'https' not in link.lower(),
        "name": "استخدام اسم شركة كبرى بدون تشفير HTTPS",
        "risk": "لا يمكن لشركة كبرى أن تستخدم HTTP. هذا تزوير واضح. **خطر عالٍ جداً.**",
        "points": 30 
    },
    {
        "check": lambda link, content: any(char.isdigit() for char in urlparse(link).netloc.split('.')[1]) and link.count('.') >= 1,
        "name": "نطاق رئيسي يحتوي على أرقام",
        "risk": "النطاقات الرئيسية التي تحتوي على أرقام غالباً ما تكون مشبوهة.",
        "points": 8 
    },
    {
        "check": lambda link, content: len(urlparse(link).netloc.split('.')[0]) > 20 and len(urlparse(link).netloc.split('.')[0].split('-')) > 3,
        "name": "نطاق فرعي ضخم ومفصول بالواصلات",
        "risk": "حشو كلمات مفتاحية لتجنب الفلاتر.",
        "points": 6
    },
    {
        "check": lambda link, content: link.count('free') > 1 or link.count('verify') > 1,
        "name": "تكرار كلمات الخداع (Free/Verify)",
        "risk": "الاستخدام المفرط لكلمات الإغراء والحاجة للتحقق.",
        "points": 9 
    },
    # ----------------------------------------------------
    # مجموعة 3: قواعد فحص المسار والملفات (Path & Files)
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['gift', 'prize', 'free', 'win', 'claim', 'discount', 'bonus', 'crypto', 'wallet']),
        "name": "استخدام كلمات خداع اجتماعي شائعة في المسار",
        "risk": "يشير إلى محاولة خداع اجتماعي.",
        "points": 7 
    },
    {
        "check": lambda link, content: any(word in link.lower() for word in ['admin', 'upload', 'config', 'backup', 'db', 'password', 'clientarea']),
        "name": "كلمات إدارة وحساسة في الرابط",
        "risk": "قد يشير إلى محاولة الوصول لصفحة إدارة.",
        "points": 10 
    },
    {
        "check": lambda link, content: link.lower().endswith(('.exe', '.bat', '.cmd', '.scr', '.vbs', '.js', '.jar', '.zip', '.rar', '.7z', '.iso', '.bin')),
        "name": "الانتهاء بملف تنفيذي أو مضغوط ضار",
        "risk": "يشير إلى أن الرابط سيقوم بتحميل أو تشغيل ملف تنفيذي ضار مباشرة. **خطر حرج للغاية.**",
        "points": 80 
    },
    {
        "check": lambda link, content: bool(re.search(r'/\d{10,}/', link)),
        "name": "سلسلة أرقام طويلة جداً في المسار",
        "risk": "قد تشير إلى ملفات تم تحميلها عشوائياً.",
        "points": 4
    },
    {
        "check": lambda link, content: link.count('?') > 1,
        "name": "وجود أكثر من علامة استفهام في الرابط",
        "risk": "الاستخدام غير القياسي لعلامة الاستفهام.",
        "points": 5 
    },
    {
        "check": lambda link, content: 'base64' in link.lower() or 'hex' in link.lower(),
        "name": "استخدام كلمات الترميز (Base64/Hex)",
        "risk": "يشير إلى محاولة تمرير بيانات مشفرة لتجاوز فلاتر التحليل البسيط.",
        "points": 8 
    },
    {
        "check": lambda link, content: bool(re.search(r'[\u0600-\u06FF]', link)) and 'xn--' not in link.lower(),
        "name": "أحرف عربية أو غير لاتينية غير مشفرة",
        "risk": "قد يشير إلى ترميز غير صحيح.",
        "points": 5 
    },
    {
        "check": lambda link, content: link.lower().count('/') > 7,
        "name": "عمق المسار المبالغ فيه (>7 مستويات)",
        "risk": "قد يدل على موقع يتمتع ببنية ملفات معقدة ومخفية بشكل غير طبيعي.",
        "points": 4
    },
    {
        "check": lambda link, content: 'index.html' in link.lower() or 'default.aspx' in link.lower(),
        "name": "اسم ملف صفحة افتراضية في المسار",
        "risk": "في الغالب لا تحتاج المواقع الكبيرة لذكر هذه الملفات بشكل صريح في الرابط.",
        "points": 2
    },
    {
        "check": lambda link, content: 'login' in link.lower() and urlparse(link).netloc.count('.') > 2,
        "name": "كلمة 'Login' في نطاق فرعي عميق",
        "risk": "مثل: `login.secure.paypal.com.scam.com` - محاولة للتخفي. **خطر عالٍ.**",
        "points": 20 
    },
    {
        "check": lambda link, content: any(param in urlparse(link).query for param in ['redir', 'forward', 'url']),
        "name": "وجود متغيرات إعادة التوجيه (Redirect Parameters)",
        "risk": "قد تسمح هذه المتغيرات (مثل ?url=) بالاستغلال لتنفيذ عمليات إعادة توجيه مفتوحة.",
        "points": 10 
    },
    # ----------------------------------------------------
    # مجموعة 4: قواعد فحص الأمان والسلوك والمحتوى
    # ----------------------------------------------------
    {
        "check": lambda link, content: any(word in link.lower() for word in ['secure', 'safe', 'trust', 'login', 'verify', 'ssl']) and 'https' not in link.lower(),
        "name": "كلمات أمان زائفة بدون تشفير",
        "risk": "محاولة إيهام المستخدم بالأمان (مثلاً: رابط فيه 'secure' ولكنه HTTP). **خطر عالٍ جداً.**",
        "points": 30 
    },
    {
        "check": lambda link, content: any(word in urlparse(link).query.lower() for word in ['session', 'cookie', 'token', 'auth', 'apikey']),
        "name": "تضمين بيانات الجلسة/المصادقة الحساسة في متغيرات الرابط",
        "risk": "قد يشير إلى محاولة حقن أو سرقة بيانات الجلسة عبر الرابط.",
        "points": 15 
    },
    {
        "check": lambda link, content: len(link) > 40 and link != link.lower() and link != link.upper(),
        "name": "أحرف كبيرة وصغيرة عشوائية",
        "risk": "تستخدم لتجاوز فلاتر البريد المزعج.",
        "points": 3
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<form[^>]*\b(password|user|credit|card|cvv|secure|login|pin|social security)\b', content, re.IGNORECASE | re.DOTALL)),
        "name": "نموذج يطلب معلومات حساسة (Phishing Form)",
        "risk": "وجود نموذج إدخال يطلب كلمات مرور أو بيانات بطاقة ائتمان. **هذا هو المؤشر الأقوى على موقع تصيد.**",
        "points": 100 
    },
    {
        # التعديل: لن يتم الفحص هنا، سيتم التعامل مع طول المحتوى وحالة 200/غير 200 في دالة perform_security_scan
        "check": lambda link, content: False, # تم تعطيل هذه القاعدة هنا
        "name": "محتوى صفحة قصير جداً (Under Construction/Redirect)",
        "risk": "يشير إلى أن الصفحة فارغة أو أنها مجرد صفحة إعادة توجيه فورية مخفية.",
        "points": 15 
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'iframe\s*src\s*=\s*("|)\s*(http|https)', content, re.IGNORECASE)),
        "name": "استخدام IFRAME لتحميل محتوى من نطاق خارجي",
        "risk": "قد يُستخدم لتحميل صفحة التصيد داخل إطار مخفي.",
        "points": 10 
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'document\.write|eval\(|unescape\(', content, re.IGNORECASE)),
        "name": "كود JavaScript مُشفر أو خطير",
        "risk": "وجود دوال تُستخدم غالباً لتنفيذ كود ضار أو إعادة توجيه مخفية.",
        "points": 20 
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'window\.location\.replace|window\.location\.href|meta\s*http-equiv\s*=\s*"refresh"', content, re.IGNORECASE)),
        "name": "كود إعادة توجيه متقدم (Client-Side Redirect)",
        "risk": "يشير إلى محاولة نقل المستخدم فوراً إلى رابط آخر باستخدام جافاسكريبت أو Meta Tags.",
        "points": 15 
    },
    {
        "check": lambda link, content: content is not None and bool(re.search(r'<script\s*src\s*=\s*".*?"\s*async\s*defer', content, re.IGNORECASE)),
        "name": "تحميل ملفات جافاسكريبت خارجية بـ 'Async/Defer'",
        "risk": "قد يشير إلى برامج تتبع ضارة أو سكربتات تعدين خفية.",
        "points": 7 
    },
    {
        "check": lambda link, content: content is not None and 'paypal' in link.lower() and 'title' in content.lower() and 'update' in content.lower(),
        "name": "عنوان الصفحة يطلب 'تحديث' أو 'التحقق' لعلامة تجارية مشهورة",
        "risk": "نمط نموذجي لصفحات التصيد التي تحاول إجبارك على تحديث معلوماتك البنكية.",
        "points": 25 
    }
]


# --- دالة التحليل الأمني (منطق العمل المُحدث) ---
def perform_security_scan(link):
    suspicious_points = 0
    detected_warnings = 0
    page_content = None 
    status_code = 0
    final_link = link 
    page_content_warning = "لم يتم إجراء تحليل للمحتوى بعد..."
    
    # 1. فحص الاتصال بالرابط والحصول على المحتوى
    try:
        # requests.get يتبع عمليات إعادة التوجيه تلقائياً
        response = requests.get(link, timeout=10, allow_redirects=True) 
        status_code = response.status_code
        final_link = response.url
        page_content = response.text 
        
        # قاعدة إعادة التوجيه المفرطة
        if len(response.history) > 3:
            suspicious_points += 15
            detected_warnings += 1
            page_content_warning = f"تحذير: تمت {len(response.history)} عملية إعادة توجيه. (مشبوه)."

        # قاعدة خطأ الحالة (403/404)
        if status_code != 200:
            if status_code in [403, 404]:
                suspicious_points += 20
            else:
                suspicious_points += 8
                
            detected_warnings += 1
            page_content_warning = f"تحذير: الرابط يسبب خطأ {status_code}. (هذا يُعتبر مشبوهاً)."
        else:
            page_content_warning = f"تم جلب محتوى الصفحة بنجاح. (الحالة: {status_code})"

            # تطبيق القاعدة 37 هنا (خارج حلقة القواعد لتجنب مشاكل النطاق)
            if page_content is not None and len(page_content) < 500:
                rule_37_points = 15
                suspicious_points += rule_37_points
                detected_warnings += 1
                
                # إضافة القاعدة 37 إلى القواعد المخترقة يدوياً
                violated_rules = [{
                    "name": SECURITY_RULES[36]['name'], # القاعدة 37 هي في الفهرس 36
                    "risk_description": SECURITY_RULES[36]['risk'],
                    "points_added": rule_37_points
                }]
            else:
                violated_rules = []
            
    except requests.exceptions.RequestException as e:
        suspicious_points += 30 
        detected_warnings += 1
        page_content_warning = f"خطأ حاد في الاتصال بالرابط أو حدوث مهلة (Timeout). ({e})"
        status_code = 0
        final_link = link 
        violated_rules = [] # في حالة الفشل لا يوجد محتوى لتحليله
        
    # 2. تطبيق جميع القواعد الأمنية 
    link_for_rules = final_link
    content_to_check = page_content if page_content else ""

    # تطبيق القواعد الأخرى (بدءًا من القاعدة التي تلي القاعدة 37)
    for i, rule in enumerate(SECURITY_RULES):
        try:
            # تخطي القاعدة 37 (index 36) لأنها تم تطبيقها يدوياً
            if i == 36:
                continue

            if rule["check"](link_for_rules, content_to_check):
                suspicious_points += rule["points"] 
                detected_warnings += 1
                
                # التأكد من عدم تكرار القاعدة 37
                is_rule_37 = (i == 36)
                if not is_rule_37:
                    violated_rules.append({
                        "name": rule["name"],
                        "risk_description": rule["risk"],
                        "points_added": rule["points"]
                    })
        except Exception as e:
            # طباعة الخطأ في حال فشل تطبيق قاعدة معينة
            print(f"Error applying rule {rule['name']}: {e}") 
            pass
    
    # 3. تحديد مستوى الخطورة بناءً على النقاط 
    risk_score = "Low"
    result_message = "🟢 آمن: لم يتم اكتشاف مخاطر واضحة بناءً على التحليل عالي الدقة."

    if suspicious_points > 60: 
        risk_score = "Critical"
        result_message = "🔴 خطر حرج جداً! تجاوزت النقاط 60، مما يشير إلى وجود مؤشرات قوية جداً على التصيد أو البرامج الضارة. **يجب عدم فتح هذا الرابط تحت أي ظرف.**"
    elif suspicious_points > 35: 
        risk_score = "High"
        result_message = "🔥 خطر عالٍ! تم اكتشاف مخالفات هيكلية وسلوكية متعددة في الرابط (مثل Typosquatting أو HTTP). يفضل تجنبه تماماً."
    elif suspicious_points > 15: 
        risk_score = "Medium"
        result_message = "⚠️ خطر متوسط. يحتوي على بعض العناصر المشبوهة التي تقلل من الثقة به. يجب استخدامه بحذر شديد."
    
    # 4. إعادة النتيجة
    return {
        "status": "success" if suspicious_points <= 15 else "warning" if suspicious_points <= 35 else "error",
        "message": f"تحليل مكتمل بدقة قصوى. تم تطبيق {len(SECURITY_RULES)} قاعدة فحص على الرابط النهائي ({link_for_rules}).",
        "link_input": link, 
        "link_final": link_for_rules, 
        "result_message": result_message,
        "risk_score": risk_score,
        "suspicious_points": suspicious_points,
        "detected_warnings": detected_warnings,
        "page_content_status": page_content_warning,
        "violated_rules": violated_rules 
    }

# --- نقطة النهاية الرئيسية لعرض الواجهة الأمامية ---
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


# --- نقطة النهاية للتحليل (API) ---
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

    # تعديل صغير: إضافة البروتوكول في حالة عدم وجوده
    if not link_to_analyze.lower().startswith(('http://', 'https://')):
        link_to_analyze = 'https://' + link_to_analyze
    
    # التحقق من صلاحية الرابط باستخدام مكتبة validators
    if url(link_to_analyze) is not True:
         return jsonify({
            "status": "validation_error",
            "message": "❌ الإدخال غير صحيح. الرجاء إدخال رابط حقيقي وصالح بصيغة URL.",
            "error_code": 400
        }), 400
    
    
    analysis_result = perform_security_scan(link_to_analyze) 
    
    return jsonify(analysis_result), 200

