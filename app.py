import os
import sqlite3
from functools import wraps

from flask import Flask, request, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# إعدادات البيئة
SECRET_KEY = os.environ.get("SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

DB_NAME = os.environ.get("DB_PATH", "liveboost.db")

if not SECRET_KEY or not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise RuntimeError("Missing required environment variables")

serializer = URLSafeTimedSerializer(SECRET_KEY)


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def setup():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            balance REAL DEFAULT 0
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            service TEXT,
            target TEXT,
            quantity INTEGER,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    password_hash = generate_password_hash(ADMIN_PASSWORD)

    cur.execute("""
        INSERT INTO admins (username, password)
        VALUES (?, ?)
        ON CONFLICT(username)
        DO UPDATE SET password = excluded.password
    """, (ADMIN_USERNAME, password_hash))

    conn.commit()
    conn.close()


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401

        token = auth_header[7:]

        try:
            data = serializer.loads(token, max_age=43200)

            if data.get("role") != "admin":
                return jsonify({"error": "Unauthorized"}), 401

        except (BadSignature, SignatureExpired):
            return jsonify({"error": "Invalid or expired token"}), 401

        return func(*args, **kwargs)

    return wrapper


@app.route("/")
def home():
    return jsonify({
        "status": "LIVE BOOST server is running"
    })


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()

    admin = conn.execute(
        "SELECT * FROM admins WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not admin or not check_password_hash(admin["password"], password):
        return jsonify({
            "error": "Wrong username or password"
        }), 401

    token = serializer.dumps({
        "role": "admin",
        "username": username
    })

    return jsonify({
        "token": token,
        "message": "Login successful"
    })


@app.route("/api/admin/orders", methods=["GET"])
@admin_required
def get_orders():
    conn = get_db()

    rows = conn.execute(
        "SELECT * FROM orders ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/approve/<int:order_id>", methods=["POST"])
@admin_required
def approve_order(order_id):
    conn = get_db()

    cur = conn.execute(
        "UPDATE orders SET status = 'approved' WHERE id = ?",
        (order_id,)
    )

    conn.commit()
    changed = cur.rowcount
    conn.close()

    if not changed:
        return jsonify({"error": "Order not found"}), 404

    return jsonify({"message": "Order approved"})


@app.route("/api/admin/reject/<int:order_id>", methods=["POST"])
@admin_required
def reject_order(order_id):
    conn = get_db()

    cur = conn.execute(
        "UPDATE orders SET status = 'rejected' WHERE id = ?",
        (order_id,)
    )

    conn.commit()
    changed = cur.rowcount
    conn.close()

    if not changed:
        return jsonify({"error": "Order not found"}), 404

    return jsonify({"message": "Order rejected"})


@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_users():
    conn = get_db()

    rows = conn.execute(
        "SELECT id, username, balance FROM users ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def get_stats():
    conn = get_db()

    users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    orders = conn.execute(
        "SELECT COUNT(*) FROM orders"
    ).fetchone()[0]

    pending = conn.execute(
        "SELECT COUNT(*) FROM orders WHERE status = 'pending'"
    ).fetchone()[0]

    conn.close()

    return jsonify({
        "users": users,
        "orders": orders,
        "pending_orders": pending
    })


setup()
