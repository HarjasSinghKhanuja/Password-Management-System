from flask import Flask, render_template, request
import re
import hashlib
import requests

app = Flask(__name__)

# --- Password Strength Checker ---
def check_strength(password):
    common_weak = {
        "123456", "123456789", "1234567890", "password", "qwerty",
        "111111", "abc123", "password1", "12345", "letmein",
        "welcome", "iloveyou", "admin", "root"
    }

    score = 0
    suggestions = []

    # Check if password is in the common weak list
    if password.lower() in common_weak:
        return "😢Very Weak👎", ["❌Avoid using common passwords like '1234567890' or 'password'❌"]

    # Check length
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 Characters✔")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add Uppercase Letters✔")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add Lowercase Letters✔")

    # Numbers
    if re.search(r"[0-9]", password):
        score += 1
    else:
        suggestions.append("Add Numbers✔")

    # Special characters
    if re.search(r"[@$!%*?&]", password):
        score += 1
    else:
        suggestions.append("Add Special Characters✔")

    # Evaluate score
    if score <= 2:
        return "⚠️Weak⚠️", suggestions
    elif score == 3:
        return "😐Medium👍", suggestions
    else:
        return "💪Strong💯", suggestions


# --- Breach Check using HaveIBeenPwned API ---
def check_breach(password):
    try:
        sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1pwd[:5], sha1pwd[5:]
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)

        if response.status_code == 200 and suffix in response.text:
            return "🚨Found in Data Breaches🚨"
        else:
            return "✅Not Found in Breaches✅"
    except requests.RequestException:
        return "❗Breach Check Unavailable (Connection Issue)❗"


# --- Flask Route ---
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    breach_status = None
    suggestions = []

    if request.method == 'POST':
        password = request.form['password']
        result, suggestions = check_strength(password)
        breach_status = check_breach(password)

    return render_template(
        'index.html',
        result=result,
        breach_status=breach_status,
        suggestions=suggestions
    )


if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5500))
    app.run(host="0.0.0.0", port=port, debug=True)