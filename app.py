import os
import csv
import re
import dns.resolver
import smtplib
import ssl
from flask import Flask, render_template, request, send_file

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

USE_EMOJIS = True
disposable_domains = ['mailinator.com', 'tempmail.com', '10minutemail.com']

# Configure DNS resolver with timeout
resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 3

def is_valid_format(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

def is_disposable(email):
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

def is_role_based(email):
    roles = [
        'info', 'admin', 'support', 'contact', 'sales',
        'billing', 'help', 'postmaster', 'abuse', 'webmaster'
    ]
    user = email.split('@')[0].lower()
    return any(role in user for role in roles)

def get_mx(domain):
    try:
        answers = resolver.resolve(domain, 'MX')
        return str(answers[0].exchange)
    except:
        return None

def smtp_check(email, mx):
    server = None
    try:
        context = ssl.create_default_context()
        server = smtplib.SMTP(mx, 25, timeout=8)
        server.ehlo()
        try:
            server.starttls(context=context)
        except smtplib.SMTPException:
            pass  # not all servers support TLS
        server.mail('test@example.com')
        code, _ = server.rcpt(email)
        return code == 250
    except:
        return None
    finally:
        if server:
            try:
                server.quit()
            except:
                pass

def check_dmarc(domain):
    try:
        result = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in result:
            if 'v=DMARC1' in str(r):
                return True
    except:
        return False

def check_dkim(domain):
    selector = "default"
    try:
        result = resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
        for r in result:
            if 'v=DKIM1' in str(r):
                return True
    except:
        return False

def verify_email(email):
    email = email.strip()
    if not is_valid_format(email):
        return "❌ Invalid Format"

    if is_disposable(email):
        return "⚠️ Disposable Email"

    if is_role_based(email):
        return "⚠️ Role-Based Email"

    domain = email.split('@')[1]
    mx = get_mx(domain)
    if not mx:
        return "❌ Invalid Domain"

    smtp = smtp_check(email, mx)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)

    if smtp:
        return f"✅ Valid | DMARC: {'✔️' if dmarc else '❌'} | DKIM: {'✔️' if dkim else '❌'}"
    elif smtp is False:
        return "❌ Rejected by Server"
    else:
        return "⚠️ SMTP Unverifiable"

@app.route("/", methods=["GET", "POST"])
def index():
    result_file = None
    results = []
    if request.method == "POST":
        file = request.files.get("file")
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)
            resultpath = os.path.join(RESULT_FOLDER, "result.csv")

            try:
                with open(filepath, newline='', encoding='utf-8') as csvfile, \
                     open(resultpath, mode='w', newline='', encoding='utf-8') as resultfile:
                    reader = csv.DictReader(csvfile)
                    fieldnames = ['email', 'status']
                    writer = csv.DictWriter(resultfile, fieldnames=fieldnames)
                    writer.writeheader()

                    for row in reader:
                        email = row.get('email')
                        if email:
                            status = verify_email(email)
                            results.append({'email': email, 'status': status})
                            writer.writerow({'email': email, 'status': status})

                result_file = "result.csv"

            except Exception as e:
                results.append({'email': 'Error', 'status': f'Processing failed: {str(e)}'})

    return render_template("index.html", results=results, result_file=result_file)

@app.route("/download")
def download():
    return send_file(os.path.join(RESULT_FOLDER, "result.csv"), as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)