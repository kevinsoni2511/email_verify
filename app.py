import os
import csv
import re
import dns.resolver
import smtplib
import ssl
from flask import Flask, render_template_string, request, send_file

# Flask setup
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Config
USE_EMOJIS = True
DISPOSABLE_DOMAINS = {'mailinator.com', 'tempmail.com', '10minutemail.com'}
ROLE_KEYWORDS = {"admin","administrator","support","info","contact","sales",
                 "billing","help","postmaster","abuse","webmaster"}
DNS_TIMEOUT = 3
SMTP_TIMEOUT = 8
PROBE_FROM = "noreply@example.com"

# DNS resolver
resolver = dns.resolver.Resolver()
resolver.timeout = DNS_TIMEOUT
resolver.lifetime = DNS_TIMEOUT

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# --- Verification functions ---
def is_valid_format(email):
    return bool(EMAIL_REGEX.match(email or ""))

def is_disposable(email):
    domain = email.split("@")[-1].lower()
    return domain in DISPOSABLE_DOMAINS

def is_role_based(email):
    local = email.split("@")[0].lower()
    return any(k == local or local.startswith(k + ".") or ("+" in local and local.split("+")[0] == k) or (k in local) for k in ROLE_KEYWORDS)

def get_mx(domain):
    try:
        answers = resolver.resolve(domain, "MX")
        mxs = sorted(answers, key=lambda r: r.preference)
        return str(mxs[0].exchange).rstrip(".")
    except:
        try:
            resolver.resolve(domain, "A")
            return domain
        except:
            return None

def smtp_check(email, mx_host):
    server = None
    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT)
        server.ehlo()
        try:
            server.starttls(context=context)
            server.ehlo()
        except smtplib.SMTPException:
            pass
        server.mail(PROBE_FROM)
        code, _ = server.rcpt(email)
        return int(code) in (250, 251)
    except smtplib.SMTPRecipientsRefused:
        return False
    except Exception:
        return None
    finally:
        if server:
            try: server.quit()
            except: pass

def check_dmarc(domain):
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        return any("v=DMARC1" in str(r) for r in answers)
    except: return False

def check_dkim(domain, selector="default"):
    try:
        answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
        return any("v=DKIM1" in str(r) for r in answers)
    except: return False

def verify_email(email):
    email = (email or "").strip()
    if not is_valid_format(email):
        return "❌ Invalid Format"
    if is_disposable(email):
        return "⚠️ Disposable Email"
    if is_role_based(email):
        return "⚠️ Role Email"

    domain = email.split("@")[1]
    mx = get_mx(domain)
    if not mx:
        return "❌ Invalid Domain"

    smtp = smtp_check(email, mx)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)

    if smtp:
        return f"✅ Valid | DMARC: {'✔️' if dmarc else '❌'} | DKIM: {'✔️' if dkim else '❌'}"
    elif smtp is False:
        return "❌ Rejected"
    else:
        return "⚠️ SMTP Unverifiable"

# --- Flask Routes ---
INDEX_HTML = """
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>Bulk Email Verifier</title>
<style>
body{font-family:Arial,sans-serif;max-width:900px;margin:32px auto;}
table{width:100%;border-collapse:collapse;margin-top:12px;}
th,td{padding:8px;border-bottom:1px solid #eee;text-align:left;}
</style>
</head>
<body>
<h1>Bulk Email Verifier</h1>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">Upload & Verify</button>
</form>

{% if results %}
<table>
<thead><tr><th>Email</th><th>Status</th></tr></thead>
<tbody>
{% for r in results %}
<tr><td>{{ r.email }}</td><td>{{ r.status }}</td></tr>
{% endfor %}
</tbody>
</table>
<a href="{{ url_for('download') }}">Download CSV</a>
{% endif %}
</body>
</html>
"""

@app.route("/", methods=["GET","POST"])
def index():
    results = []
    result_file = None
    if request.method=="POST":
        file = request.files.get("file")
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            resultpath = os.path.join(RESULT_FOLDER, "result.csv")
            try:
                with open(filepath, newline='', encoding='utf-8') as csvfile, \
                     open(resultpath, mode='w', newline='', encoding='utf-8') as resultfile:
                    reader = csv.DictReader(csvfile)
                    fieldnames = ['email','status']
                    writer = csv.DictWriter(resultfile, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in reader:
                        email = row.get('email')
                        if email:
                            status = verify_email(email.strip())
                            results.append({'email': email, 'status': status})
                            writer.writerow({'email': email, 'status': status})
                result_file = "result.csv"
            except Exception as e:
                results.append({'email':'Error','status':f'Processing failed: {str(e)}'})
    return render_template_string(INDEX_HTML, results=results, result_file=result_file)

@app.route("/download")
def download():
    return send_file(os.path.join(RESULT_FOLDER, "result.csv"), as_attachment=True)

if __name__=="__main__":
    app.run(debug=True)