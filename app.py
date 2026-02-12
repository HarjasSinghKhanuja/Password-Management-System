from flask import Flask, render_template, request, jsonify
import re, hashlib, requests
import sqlite3, os, secrets
from cryptography.fernet import Fernet

app = Flask(__name__)

# ==========================================================
# 🔐 ENCRYPTION + DATABASE SETUP
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "password_manager.db")
KEY_PATH = os.path.join(BASE_DIR, "secret.key")

# Create encryption key
if not os.path.isfile(KEY_PATH):
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)

with open(KEY_PATH, "rb") as f:
    key = f.read()

cipher = Fernet(key)

# Init database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS passwords(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        username TEXT,
        password TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS passkeys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT,
        passkey TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ==========================================================
# 🔐 PASSWORD ANALYZER (ENHANCED WITH COMMON PASSWORD CHECK)
# ==========================================================

def check_strength(password):
    score = 0
    suggestions = []

    # Common weak passwords list
    common_passwords = [
        "123456", "123456789", "1234567890",
        "password", "qwerty", "abc123",
        "111111", "123123", "admin",
        "letmein", "welcome", "QWERTY"
    ]

    # Check if password is a known common password
    if password.lower() in common_passwords:
        suggestions.append(
            "❌Do not use common passwords like '123456', 'password', 'qwerty'❌"
        )
        suggestions.append("✅Always Use a Unique and Unpredictable Password✅")
        return "Weak", suggestions

    # Length check
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    # Uppercase check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add uppercase letters.")

    # Lowercase check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add lowercase letters.")

    # Numbers check
    if re.search(r"[0-9]", password):
        score += 1
    else:
        suggestions.append("Add numbers.")

    # Special characters check
    if re.search(r"[@$!%*?&]", password):
        score += 1
    else:
        suggestions.append("Add special characters.")

    # Final Strength Decision
    if score <= 2:
        return "Weak", suggestions
    elif score == 3:
        return "Medium", suggestions
    else:
        return "Strong", suggestions


def check_breach(password):
    sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1pwd[:5], sha1pwd[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}")
    if suffix in response.text:
        return "🚨Alert!🚨⚠️Found in Data Breaches⚠️"
    return "✅Not Found in Breaches✅"

# ==========================================================
# 🏠 HOME ROUTE
# ==========================================================

@app.route("/", methods=["GET","POST"])
def index():
    result=None
    suggestions=[]
    breach_status=None

    if request.method=="POST":
        pwd=request.form["password"]
        result,suggestions=check_strength(pwd)
        breach_status=check_breach(pwd)

    return render_template("index.html",
        result=result,
        suggestions=suggestions,
        breach_status=breach_status)

# ==========================================================
# 💾 SAVE PASSWORD (FINAL VERSION)
# ==========================================================

@app.route("/save-password", methods=["POST"])
def save_password():
    try:
        site = request.form.get("site", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Validation
        if not site or not username or not password:
            return jsonify({"status": "error", "message": "All fields are required"}), 400

        encrypted = cipher.encrypt(password.encode()).decode()

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO passwords (site, username, password)
                VALUES (?, ?, ?)
            """, (site, username, encrypted))
            conn.commit()

        return jsonify({"status": "success", "message": "Password saved successfully"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================================
# ⚡ AUTOFILL (FINAL VERSION)
# ==========================================================

@app.route("/autofill", methods=["POST"])
def autofill():
    try:
        site = request.form.get("site", "").strip().lower()

        if not site:
            return jsonify({"status": "error", "message": "Site is required"}), 400

        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT username, password
                FROM passwords
                WHERE site = ?
                ORDER BY id DESC
                LIMIT 1
            """, (site,))
            row = c.fetchone()

        if row:
            decrypted = cipher.decrypt(row[1].encode()).decode()
            return jsonify({
                "status": "success",
                "username": row[0],
                "password": decrypted
            })

        return jsonify({"status": "not_found", "message": "No saved credentials"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================================
# 📂 GET PASSWORD LIST (FINAL VERSION)
# ==========================================================

@app.route("/get-passwords")
def get_passwords():
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("""
                SELECT site, username
                FROM passwords
                ORDER BY id DESC
            """)
            rows = c.fetchall()

        return jsonify({
            "status": "success",
            "data": [
                {"site": r[0], "username": r[1]}
                for r in rows
            ]
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ==========================================================
# 🔑 PASSKEY (UNCHANGED)
# ==========================================================

@app.route("/create-passkey",methods=["POST"])
def create_passkey():
    site=request.form["site"]
    passkey=secrets.token_urlsafe(32)

    conn=sqlite3.connect(DB_PATH)
    c=conn.cursor()
    c.execute("INSERT INTO passkeys(site,passkey) VALUES(?,?)",
              (site,passkey))
    conn.commit()
    conn.close()

    return jsonify({"passkey":passkey})


@app.route("/get-passkeys")
def get_passkeys():
    conn=sqlite3.connect(DB_PATH)
    c=conn.cursor()
    c.execute("SELECT site,passkey FROM passkeys")
    rows=c.fetchall()
    conn.close()

    return jsonify([{"site":r[0],"passkey":r[1]} for r in rows])

if __name__=="__main__":
    app.run(debug=True,port=5500)