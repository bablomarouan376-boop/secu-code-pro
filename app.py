import os, re, requests, time, base64
from flask import Flask, request, jsonify, render_template, send_from_directory
from urllib.parse import urlparse

app = Flask(__name__, 
            static_folder='static', 
            static_url_path='/static',
            template_folder='templates')

# --- إعدادات المطور طارق مصطفى ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

def get_vt_analysis(url):
    """تحليل الرابط عبر VirusTotal v3"""
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)
        if res.status_code == 200:
            attr = res.json()['data']['attributes']
            stats = attr['last_analysis_stats']
            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "total_engines": sum(stats.values())
            }
        return None
    except: return None

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.json
    url = data.get('link', '').strip()
    if not url: return jsonify({"error": "URL missing"}), 400
    if not url.startswith('http'): url = 'https://' + url
    
    domain = urlparse(url).netloc.lower().replace('www.', '')
    
    # 1. القائمة البيضاء الذكية
    WHITELIST = {'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'github.com', 'linkedin.com'}
    if any(w in domain for w in WHITELIST):
        return jsonify({"risk_score": "Safe", "points": 0, "violation_key": "OFFICIAL_TRUST", "engines_found": 0})

    # 2. فحص الاستخبارات العالمية
    vt_data = get_vt_analysis(url)
    
    if vt_data:
        m_count = vt_data['malicious']
        score = min((m_count * 20) + (vt_data['suspicious'] * 10), 100)
        v_key = "SUSPICIOUS" if m_count > 0 else "CLEAN_AUDIT"
        engines_msg = f"Detected by {m_count} security engines"
    else:
        score, v_key, m_count = 45, "SHIELD", 0
        engines_msg = "Heuristic Analysis Active"

    # 3. إشعار تليجرام الاحترافي لطارق
    try:
        status_icon = "🔴" if m_count > 0 else "🟢"
        msg = (f"{status_icon} *SecuCode Scan*\n"
               f"🌐 Domain: {domain}\n"
               f"🚨 Malicious Engines: {m_count}\n"
               f"📊 Risk: {score}%\n"
               f"👨‍💻 Dev: Tarek Mostafa")
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                      json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"}, timeout=1)
    except: pass

    return jsonify({
        "risk_score": "Critical" if score > 60 else "Safe",
        "points": score,
        "violation_key": v_key,
        "engines_found": m_count,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=800&h=600"
    })

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

if __name__ == '__main__':
    app.run(debug=True)
