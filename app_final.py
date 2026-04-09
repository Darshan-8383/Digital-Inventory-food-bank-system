import os
import hashlib
import hmac
import psycopg2
import psycopg2.extras
from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret")
DATABASE_URL = os.environ.get("DATABASE_URL")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query(sql, args=(), one=False):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def mutate(sql, args=()):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(sql, args)
    conn.commit()
    cur.close()

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE,
        password TEXT
    )
    """)
    conn.commit()
    cur.close()
    conn.close()

def hash_password(password):
    salt = os.urandom(16).hex()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"pbkdf2:sha256:{salt}:{dk.hex()}"

def check_password(plain, stored):
    try:
        _, _, salt, dk_hex = stored.split(":")
        new_dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 260000)
        return hmac.compare_digest(new_dk.hex(), dk_hex)
    except:
        return False

@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    try:
        hashed = hash_password(password)
        mutate("INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed))
        return jsonify({"message": "User registered"})
    except:
        return jsonify({"error": "User already exists"}), 400

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = query("SELECT * FROM users WHERE email=%s", (email,), one=True)

    if user and check_password(password, user["password"]):
        return jsonify({"message": "Login successful"})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
