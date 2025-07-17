import os
import csv
import re
import dns.resolver
import smtplib
from flask import Flask, render_template, request, send_file

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
RESULT_FOLDER = 'results'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

# Optional: toggle emoji usage
USE_EMOJIS = True

# Common disposable domains
disposable_domains = ['mailinator.com', 'tempmail.com', '10minutemail.com']

# Email format checker
def is_valid_format(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# Disposable email checker
def is_disposable(email):
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

# Role-based email checker
def is_role_based(email):
    roles = ['info', 'admin', 'support', 'contact', 'sales']
    user = email.split('@')[0].lower()
    return any(role in user for role in roles)

# MX record checker
def get_mx(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return str(records[0].exchange)
    except:
        return None

# SMTP deliverability test
def smtp_check(email, mx):
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx)
        server.helo(server.local_hostname)
        server.mail('test@example.com')
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250
    except:
        return None

# Final email verification
def verify_email(email):
    if not is_valid_format(email):
        return "❌ Invalid Format" if USE_EMOJIS else "Invalid Format"
    if is_disposable(email):
        return "⚠️ Disposable" if USE_EMOJIS else "Disposable"
    if is_role_based(email):
        return "⚠️ Role Email" if USE_EMOJIS else "Role Email"
    domain = email.split('@')[1]
    mx = get_mx(domain)
    if not mx:
        return "❌ Invalid Domain" if USE_EMOJIS else "Invalid Domain"
    result = smtp_check(email, mx)
    if result is True:
        return "✅ Valid" if USE_EMOJIS else "Valid"
    elif result is False:
        return "❌ Rejected" if USE_EMOJIS else "Rejected"
    else:
        return "⚠️ SMTP Unverifiable" if USE_EMOJIS else "SMTP Unverifiable"

# Home route
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
                     open(resultpath, mode='w', newline='', encoding='utf-8-sig') as resultfile:

                    reader = csv.DictReader(csvfile)
                    fieldnames = ['email', 'status']
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
                results.append({'email': 'Error', 'status': f'File processing failed: {str(e)}'})
    return render_template("index.html", results=results, result_file=result_file)

# Download route
@app.route("/download")
def download():
    return send_file(os.path.join(RESULT_FOLDER, "result.csv"), as_attachment=True)

# Run app
if __name__ == "__main__":
    app.run(debug=True)
