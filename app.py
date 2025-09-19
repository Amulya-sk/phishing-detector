from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import time
from urllib.parse import urlparse
from detector.heuristics import analyze_url
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
import os

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devkey")

client = MongoClient(os.getenv("MONGO_URI"))
db = client.get_database("phishingdb")
users = db.users

# --- START: New Security Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# --- END: New Security Decorators ---


@app.context_processor
def inject_asset_version():
    return {"asset_v": int(time.time())}


@app.route("/")
def home():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.")
            return render_template("login.html")

        user = users.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not password:
            flash("Username and password are required.")
            return render_template("register.html")

        if users.find_one({"username": username}):
            flash("Username already exists.")
        else:
            users.insert_one(
                {
                    "username": username,
                    "password": generate_password_hash(password),
                    "role": "admin" if username == "admin" else "user", # Assign role
                }
            )
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("index.html")


# --- START: New Admin Security Decorator ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = users.find_one({"username": session.get("user")})
        if not user or user.get("role") != "admin":
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated_function
# --- END: New Admin Security Decorator ---

@app.route("/api/check", methods=["POST"])
@login_required
def api_check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if url.startswith("@"):
        url = url[1:].strip()
    if not url:
        return jsonify({"error": "Missing 'url'"}), 400

    # Ensure the URL has a scheme and a domain with a dot.
    if "://" not in url:
        url = f"http://{url}"
    parsed = urlparse(url if "://" in url else f"http://{url}")
    if not parsed.hostname or "." not in parsed.hostname:
        return jsonify({"error": "Invalid URL format. Please enter a valid URL."}), 400
    # --- END: New, stricter validation ---

    result = analyze_url(parsed.geturl())
    return jsonify(result)


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    all_users = list(users.find({}, {"_id": 0, "username": 1}))
    return render_template("admin_users.html", users=all_users)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
