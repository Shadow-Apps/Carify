#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e-Dziennik Serwisowy Pojazdu — single-file Flask 3.x

- Rejestracja/logowanie (sesja)
- Pojazdy + wpisy serwisowe (upload plików)
- Przypomnienia (data/przebieg, typ z listy + "Inne", mail, ile dni wcześniej)
- Wysyłka maili przez Gmail SMTP: carifynotification@gmail.com
- Dashboard: koszty dziennie + tabela przebiegów
- Eksport CSV
- SQLite w pliku (trwałe dane)
"""

import os
import re
import csv
import sqlite3
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# --- Scheduler opcjonalny (aplikacja działa też bez tej paczki) ---
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _HAS_APS = True
except Exception:
    BackgroundScheduler = None
    _HAS_APS = False

# --- KONFIGURACJA ---
APP_TITLE = "e-Dziennik Serwisowy"

BASE_DIR = os.path.dirname(__file__)
# Możesz podać FILES_DIR w env (np. na hostingu) – tam trafi baza i uploady.
FILES_DIR = os.environ.get("FILES_DIR", os.path.join(BASE_DIR, "uploads"))
os.makedirs(FILES_DIR, exist_ok=True)

DB_PATH = os.path.join(FILES_DIR, "service_log.db")
UPLOAD_DIR = FILES_DIR
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "webp"}

# Sesja/flask
SECRET = os.environ.get("EDZIENNIK_SECRET", "dev-secret-change-me")
app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET,
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,  # 20 MB
)

# --- SMTP: NADAWCA USTAWIONY NA konto Gmail z Twojej prośby ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "carifynotification@gmail.com")
# WAŻNE: ustaw App Password w zmiennej środowiskowej SMTP_PASS
SMTP_PASS = os.environ.get("SMTP_PASS", "jbqc dpmi wjkk huct")  # <= TU W KONSOLI/TRZEBA USTAWIĆ
EMAIL_FROM = os.environ.get("EMAIL_FROM", "carifynotification@gmail.com")

DEFAULT_NOTIFY_BEFORE_DAYS = int(os.environ.get("NOTIFY_BEFORE_DAYS", "7"))

# --- DB helpers ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table})")
    return any(r["name"] == column for r in cur.fetchall())

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            make TEXT NOT NULL,
            model TEXT NOT NULL,
            year INTEGER,
            vin TEXT,
            reg_plate TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS service_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vehicle_id INTEGER NOT NULL,
            date TEXT NOT NULL,          -- YYYY-MM-DD
            mileage INTEGER,
            service_type TEXT NOT NULL,
            description TEXT,
            cost REAL,
            attachment TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            FOREIGN KEY(vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vehicle_id INTEGER,
            title TEXT NOT NULL,
            due_date TEXT,
            due_mileage INTEGER,
            notify_email INTEGER DEFAULT 0,
            notify_before_days INTEGER DEFAULT 7,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
        );
        """
    )
    # migracje ewentualnych brakujących kolumn
    try:
        if not column_exists(conn, "reminders", "notify_email"):
            conn.execute("ALTER TABLE reminders ADD COLUMN notify_email INTEGER DEFAULT 0")
        if not column_exists(conn, "reminders", "notify_before_days"):
            conn.execute("ALTER TABLE reminders ADD COLUMN notify_before_days INTEGER DEFAULT 7")
    except Exception as e:
        print("[DB] ALTER warnings:", e)
    conn.commit()
    conn.close()

# Lazy-init DB dla Flask 3 i każdego sposobu uruchomienia
_db_ready = False
@app.before_request
def _ensure_db_ready():
    global _db_ready
    if _db_ready:
        return
    try:
        conn = get_db()
        conn.execute("SELECT 1 FROM users LIMIT 1")
        conn.close()
        _db_ready = True
    except sqlite3.OperationalError:
        init_db()
        _db_ready = True

# --- Utils / auth ---
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"error": "auth_required"}), 401
        return f(*args, **kwargs)
    return wrapper

# --- Mail ---
def send_email(to_email: str, subject: str, html: str, plain: str = None):
    if not (SMTP_HOST and SMTP_USER and EMAIL_FROM and SMTP_PASS):
        print("[MAIL] Brak konfiguracji SMTP (ustaw SMTP_PASS itd.).")
        return False
    msg = EmailMessage()
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg["Subject"] = subject
    if plain:
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
    else:
        msg.set_content("Masz nowe przypomnienie serwisowe.")
        msg.add_alternative(html, subtype="html")

    context = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls(context=context)
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
    print(f"[MAIL] Wysłano do {to_email}")
    return True

def find_due_email_reminders():
    """
    Zwraca listę (user_email, reminder_dict) do powiadomienia:
    - jeśli notify_email==1 i (dzisiaj >= due_date - notify_before_days)
    - lub gdy ostatni przebieg >= due_mileage - 500 km
    """
    conn = get_db()
    today = datetime.utcnow().date()
    out = []
    users = {r["id"]: r for r in conn.execute("SELECT id, email, name FROM users").fetchall()}
    rows = conn.execute("""
        SELECT r.*, v.make, v.model, v.reg_plate
        FROM reminders r
        LEFT JOIN vehicles v ON v.id = r.vehicle_id
        WHERE r.completed_at IS NULL
    """).fetchall()

    for r in rows:
        rd = dict(r)
        email = users.get(rd["user_id"], {}).get("email")
        if not email:
            continue
        should_notify = False

        # data (jeśli zaznaczony e-mail)
        if rd.get("notify_email"):
            try:
                nbd = int(rd.get("notify_before_days") if rd.get("notify_before_days") is not None else DEFAULT_NOTIFY_BEFORE_DAYS)
            except Exception:
                nbd = DEFAULT_NOTIFY_BEFORE_DAYS
            if rd.get("due_date"):
                try:
                    due_date = datetime.strptime(rd["due_date"], "%Y-%m-%d").date()
                    if today >= (due_date - timedelta(days=nbd)):
                        should_notify = True
                except Exception:
                    pass

        # przebieg (niezależnie od notify_email)
        if rd.get("due_mileage") and rd.get("vehicle_id"):
            last = conn.execute(
                "SELECT MAX(COALESCE(mileage,0)) AS m FROM service_entries WHERE vehicle_id=?",
                (rd["vehicle_id"],)
            ).fetchone()
            if last and last["m"] is not None:
                margin = 500
                if last["m"] >= (int(rd["due_mileage"]) - margin):
                    should_notify = True

        if should_notify:
            out.append((email, rd))

    conn.close()
    return out

def run_email_reminder_job():
    """Wyślij zalegające/zbliżające się przypomnienia."""
    try:
        items = find_due_email_reminders()
        for to_email, r in items:
            veh = " ".join([x for x in (r.get("make"), r.get("model"), r.get("reg_plate")) if x]).strip()
            subject = f"Przypomnienie serwisowe: {r.get('title')}"
            html = f"""
              <div style="font-family:Segoe UI,Arial,sans-serif;">
                <h3 style="margin:0 0 10px">🔧 {subject}</h3>
                <p><b>Pojazd:</b> {veh or '—'}</p>
                <p><b>Termin (data):</b> {r.get('due_date') or '—'}<br>
                   <b>Termin (przebieg):</b> {r.get('due_mileage') or '—'} km</p>
                <p>Zaloguj się, aby zarządzać przypomnieniami.</p>
              </div>
            """
            send_email(to_email, subject, html)
    except Exception as e:
        print("[JOB] Email reminders error:", e)

# --- Diagnostyka/testy ---
@app.get("/api/health")
def health():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/test-mail")
@login_required
def test_mail():
    conn = get_db()
    row = conn.execute("SELECT email FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "user_not_found"}), 404
    to = row["email"]
    ok = send_email(to, "Test: e-Dziennik Serwisowy", "<p>To jest testowy e-mail 🚗🔧</p>")
    return jsonify({"ok": bool(ok), "to": to})

@app.post("/api/run-reminder-job")
def run_job_now():
    try:
        run_email_reminder_job()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# --- Auth ---
@app.post("/api/register")
def register():
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or "").strip().lower()
        name = (data.get("name") or "").strip()
        password = data.get("password") or ""
        if not (email and name and password):
            return jsonify({"error": "missing_fields"}), 400
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({"error": "invalid_email"}), 400
        conn = get_db()
        conn.execute(
            "INSERT INTO users(email,name,password_hash,created_at) VALUES (?,?,?,?)",
            (email, name, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
        return jsonify({"ok": True})
    except sqlite3.IntegrityError:
        return jsonify({"error": "email_in_use"}), 400
    except Exception as e:
        print("[REGISTER] error:", e)
        return jsonify({"error": "server_error", "detail": str(e)}), 500

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not (email and password):
        return jsonify({"error": "missing_fields"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid_credentials"}), 401
    session["user_id"] = row["id"]
    session["user_name"] = row["name"]
    return jsonify({"ok": True, "user": {"id": row["id"], "name": row["name"], "email": row["email"]}})

@app.post("/api/logout")
@login_required
def logout():
    session.clear()
    return jsonify({"ok": True})

# --- Vehicles ---
@app.get("/api/vehicles")
@login_required
def list_vehicles():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM vehicles WHERE owner_id=? ORDER BY created_at DESC",
        (session["user_id"],),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/vehicles")
@login_required
def add_vehicle():
    data = request.get_json(silent=True) or {}
    make = (data.get("make") or "").strip()
    model = (data.get("model") or "").strip()
    year = data.get("year")
    vin = (data.get("vin") or "").strip()
    reg = (data.get("reg_plate") or "").strip()
    if not (make and model):
        return jsonify({"error": "missing_fields"}), 400
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO vehicles(owner_id,make,model,year,vin,reg_plate,created_at) VALUES (?,?,?,?,?,?,?)",
        (session["user_id"], make, model, year, vin, reg, datetime.utcnow().isoformat()),
    )
    conn.commit()
    vid = cur.lastrowid
    conn.close()
    return jsonify({"ok": True, "id": vid})

@app.delete("/api/vehicles/<int:vehicle_id>")
@login_required
def delete_vehicle(vehicle_id):
    conn = get_db()
    conn.execute("DELETE FROM vehicles WHERE id=? AND owner_id=?", (vehicle_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# --- Entries ---
@app.get("/api/entries")
@login_required
def list_entries():
    vehicle_id = request.args.get("vehicle_id", type=int)
    q = request.args.get("q", type=str)
    params = [session["user_id"]]
    sql = "SELECT e.* FROM service_entries e JOIN vehicles v ON v.id=e.vehicle_id WHERE v.owner_id=?"
    if vehicle_id:
        sql += " AND e.vehicle_id=?"
        params.append(vehicle_id)
    if q:
        sql += " AND (e.service_type LIKE ? OR e.description LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    sql += " ORDER BY date DESC, id DESC"
    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.post("/api/entries")
@login_required
def add_entry():
    data = request.form if request.form else (request.get_json(silent=True) or {})
    try:
        vehicle_id = int(data.get("vehicle_id"))
    except Exception:
        return jsonify({"error": "vehicle_id_required"}), 400
    date = (data.get("date") or datetime.utcnow().date().isoformat())
    mileage = int(data.get("mileage") or 0)
    service_type = (data.get("service_type") or "").strip()
    description = (data.get("description") or "").strip()
    cost = float(data.get("cost") or 0)
    if not service_type:
        return jsonify({"error": "service_type_required"}), 400

    attachment_name = None
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        fname = secure_filename(f.filename)
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": "file_type_not_allowed"}), 400
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        attachment_name = f"{ts}_{fname}"
        f.save(os.path.join(UPLOAD_DIR, attachment_name))

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO service_entries(vehicle_id,date,mileage,service_type,description,cost,attachment,created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (vehicle_id, date, mileage, service_type, description, cost, attachment_name, datetime.utcnow().isoformat()),
    )
    conn.commit()
    eid = cur.lastrowid
    conn.close()
    return jsonify({"ok": True, "id": eid, "attachment": attachment_name})

@app.put("/api/entries/<int:entry_id>")
@login_required
def update_entry(entry_id):
    data = request.get_json(silent=True) or {}
    fields = [("date", str), ("mileage", int), ("service_type", str), ("description", str), ("cost", float)]
    sets, params = [], []
    for key, caster in fields:
        if key in data:
            sets.append(f"{key}=?")
            try:
                params.append(caster(data[key]) if data[key] is not None else None)
            except Exception:
                return jsonify({"error": f"invalid_{key}"}), 400
    if not sets:
        return jsonify({"error": "no_fields"}), 400
    params.extend([datetime.utcnow().isoformat(), entry_id, session["user_id"]])
    sql = "UPDATE service_entries SET " + ",".join(sets) + ", updated_at=? WHERE id=? AND vehicle_id IN (SELECT id FROM vehicles WHERE owner_id=?)"
    conn = get_db()
    conn.execute(sql, params)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.delete("/api/entries/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    conn = get_db()
    conn.execute("DELETE FROM service_entries WHERE id=? AND vehicle_id IN (SELECT id FROM vehicles WHERE owner_id=?)", (entry_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# --- Files ---
@app.get("/uploads/<path:filename>")
@login_required
def get_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

# --- Export CSV ---
@app.get("/api/export/csv")
@login_required
def export_csv():
    vehicle_id = request.args.get("vehicle_id", type=int)
    conn = get_db()
    params = [session["user_id"]]
    sql = (
        "SELECT e.id, e.vehicle_id, e.date, e.mileage, e.service_type, e.description, e.cost, e.attachment "
        "FROM service_entries e JOIN vehicles v ON v.id = e.vehicle_id WHERE v.owner_id=?"
    )
    if vehicle_id:
        sql += " AND e.vehicle_id=?"
        params.append(vehicle_id)
    sql += " ORDER BY e.date DESC, e.id DESC"
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    out_path = os.path.join(FILES_DIR, "export.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "vehicle_id", "date", "mileage", "service_type", "description", "cost", "attachment"])
        for r in rows:
            writer.writerow([r["id"], r["vehicle_id"], r["date"], r["mileage"], r["service_type"], r["description"], r["cost"], r["attachment"]])

    resp = make_response(open(out_path, "rb").read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=service_entries.csv"
    return resp

# --- Stats (dzienne) ---
@app.get("/api/stats")
@login_required
def stats():
    conn = get_db()
    user_id = session["user_id"]
    by_day = conn.execute(
        """
        SELECT e.date AS ymd, SUM(COALESCE(e.cost,0)) AS total_cost, COUNT(*) AS entries
        FROM service_entries e
        JOIN vehicles v ON v.id = e.vehicle_id
        WHERE v.owner_id=?
        GROUP BY e.date
        ORDER BY e.date
        """,
        (user_id,),
    ).fetchall()
    last_mileage = conn.execute(
        """
        SELECT v.id, v.make||' '||v.model AS label,
               (SELECT e.mileage FROM service_entries e
                WHERE e.vehicle_id=v.id AND e.mileage IS NOT NULL
                ORDER BY e.date DESC, e.id DESC LIMIT 1) AS mileage
        FROM vehicles v
        WHERE v.owner_id=?
        ORDER BY v.id
        """,
        (user_id,),
    ).fetchall()
    conn.close()
    return jsonify({
        "by_day": [dict(r) for r in by_day],
        "last_mileage": [dict(r) for r in last_mileage],
    })

# --- Reminders ---
@app.get("/api/reminders")
@login_required
def list_reminders():
    conn = get_db()
    user_id = session["user_id"]
    rows = conn.execute(
        "SELECT * FROM reminders WHERE user_id=? ORDER BY COALESCE(due_date, '9999-12-31'), id DESC",
        (user_id,),
    ).fetchall()
    result = []
    for r in rows:
        rec = dict(r)
        due = False
        if rec.get("due_date"):
            try:
                due = due or (rec["due_date"] <= datetime.utcnow().date().isoformat())
            except Exception:
                pass
        if rec.get("due_mileage") and rec.get("vehicle_id"):
            last = conn.execute("SELECT MAX(COALESCE(mileage,0)) AS m FROM service_entries WHERE vehicle_id=?", (rec["vehicle_id"],)).fetchone()
            if last and last["m"] is not None:
                due = due or (last["m"] >= (rec["due_mileage"] or 0))
        rec["is_due"] = bool(due)
        result.append(rec)
    conn.close()
    return jsonify(result)

@app.post("/api/reminders")
@login_required
def create_reminder():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"error": "title_required"}), 400
    due_date = data.get("due_date") or None
    due_mileage = data.get("due_mileage") if data.get("due_mileage") not in ("", None) else None
    vehicle_id = data.get("vehicle_id") if data.get("vehicle_id") not in ("", None) else None
    notify_email = 1 if str(data.get("notify_email")).lower() in ("1", "true", "on") else 0
    try:
        notify_before_days = int(data.get("notify_before_days")) if data.get("notify_before_days") not in ("", None) else DEFAULT_NOTIFY_BEFORE_DAYS
    except Exception:
        notify_before_days = DEFAULT_NOTIFY_BEFORE_DAYS

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO reminders(user_id, vehicle_id, title, due_date, due_mileage, notify_email, notify_before_days, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (session["user_id"], vehicle_id, title, due_date, due_mileage, notify_email, notify_before_days, datetime.utcnow().isoformat()),
    )
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return jsonify({"ok": True, "id": rid})

@app.put("/api/reminders/<int:rid>")
@login_required
def update_reminder(rid):
    data = request.get_json(silent=True) or {}
    fields, params = [], []
    for k in ("title", "due_date", "due_mileage", "vehicle_id", "completed_at", "notify_email", "notify_before_days"):
        if k in data:
            fields.append(f"{k}=?")
            params.append(data[k])
    if not fields:
        return jsonify({"error":"no_fields"}), 400
    params.extend([rid, session["user_id"]])
    conn = get_db()
    conn.execute("UPDATE reminders SET " + ",".join(fields) + " WHERE id=? AND user_id=?", params)
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.delete("/api/reminders/<int:rid>")
@login_required
def delete_reminder(rid):
    conn = get_db()
    conn.execute("DELETE FROM reminders WHERE id=? AND user_id=?", (rid, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

# --- Frontend (dark carbon + red, dashboard dzienny) ---
INDEX_HTML = """
<!doctype html>
<html lang=pl>
<head>
  <meta charset=utf-8>
  <meta name=viewport content="width=device-width,initial-scale=1">
  <title>{APP_TITLE}</title>

  <script>
    async function api(path, opts={}) {
      const res = await fetch(path, Object.assign({headers: {}}, opts));
      const ct = res.headers.get('content-type')||'';
      if (ct.includes('application/json')) {
        const data = await res.json();
        if (!res.ok) throw data; else return data;
      } else {
        if (!res.ok) throw new Error('Błąd'); return res;
      }
    }
  </script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <style>
    :root{
      --bg:#0a0a0a; --bg2:#1a0000;
      --card:#141414; --text:#f3f4f6; --muted:#9ca3af;
      --border:#262626; --accent:#ff3232; --accent-600:#cc2727;
      --radius:14px; --pad:14px; --gap:18px; --shadow:0 10px 28px rgba(0,0,0,.7);
    }
    *{box-sizing:border-box}
    body{margin:0; background:linear-gradient(180deg,var(--bg),var(--bg2)); color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial}
    header{position:sticky;top:0;z-index:10;background:#0f0f0f;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:var(--gap);padding:var(--pad) calc(var(--pad)*1.5)}
    .brand{display:flex;align-items:center;gap:10px;font-weight:800}
    .brand svg{width:28px;height:28px}
    main{padding:calc(var(--pad)*1.5);display:grid;grid-template-columns:minmax(320px,380px) 1fr;gap:var(--gap);align-items:start}
    .card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:var(--pad);box-shadow:var(--shadow)}
    h3{margin:0 0 10px 0}
    label{display:block;font-size:12px;color:var(--muted);margin:8px 0 6px}
    input,select,textarea{width:100%;display:block;padding:12px;border-radius:10px;border:1px solid var(--border);background:#0f0f0f;color:var(--text);outline:none}
    input:focus,select:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(255,50,50,.45)}
    button{padding:10px 14px;border:1px solid var(--border);background:#0f0f0f;color:var(--text);border-radius:10px;cursor:pointer}
    button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
    button.primary:hover{background:var(--accent-600)}
    a{color:#ff7b7b;text-decoration:none} a:hover{text-decoration:underline}
    .row{display:grid;grid-template-columns:1fr 1fr;gap:var(--gap)}
    @media (max-width:1100px){ main{grid-template-columns:1fr} .row{grid-template-columns:1fr} }
    table{width:100%;border-collapse:collapse;background:#0f0f0f;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
    thead th{background:#1f1f1f;color:#ff9c9c}
    th,td{padding:12px;border-bottom:1px solid var(--border);text-align:left;font-size:14px}
    .actions{display:flex;gap:8px}
    .muted{color:var(--muted)}
    .toast{position:fixed;right:16px;bottom:16px;background:var(--accent);color:#fff;padding:10px 14px;border-radius:10px;display:none;box-shadow:var(--shadow)}
    canvas{background:radial-gradient(ellipse at top,#151515,#0d0d0d);border:1px solid var(--border);border-radius:12px;padding:8px}
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff3232"/><stop offset="100%" stop-color="#cc2727"/></linearGradient></defs>
        <circle cx="20" cy="20" r="10" stroke="url(#g)" stroke-width="4"/>
        <path d="M28 28 L46 46 M46 46 h6 v6 h-6 v-6 m6 0 v-6 h-6" stroke="url(#g)" stroke-width="5" stroke-linecap="round"/>
        <circle cx="20" cy="20" r="3" fill="#ff3232"/>
      </svg>
      <span>{APP_TITLE}</span>
    </div>
    <div style="margin-left:auto;display:flex;gap:10px;align-items:center;">
      <span id="userName" class="muted"></span>
      <button onclick="logout()">Wyloguj</button>
    </div>
  </header>

  <main>
    <section class="card">
      <h3>Konto</h3>
      <div id="authBox">
        <div class="row">
          <div><label>Email</label><input id="regEmail" placeholder="uzytkownik@domena.pl"></div>
          <div><label>Imię</label><input id="regName" placeholder="Jan Kowalski"></div>
        </div>
        <label>Hasło</label><input id="regPass" type="password" placeholder="********">
        <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">
          <button class="primary" onclick="register()">Rejestracja</button>
          <button onclick="login()">Logowanie</button>
        </div>
        <p class="muted" style="font-size:12px;margin-top:8px;">Utwórz konto lub zaloguj się, aby zarządzać pojazdami i wpisami.</p>
      </div>

      <hr style="border-color:#262626;margin:14px 0;">

      <h3>Pojazdy</h3>
      <div>
        <label>Marka</label><input id="make" placeholder="Toyota">
        <label>Model</label><input id="model" placeholder="Corolla">
        <div class="row">
          <div><label>Rok</label><input id="year" type="number" placeholder="2018"></div>
          <div><label>VIN</label><input id="vin" placeholder="WVWZZZ..."></div>
        </div>
        <label>Nr rej.</label><input id="reg_plate" placeholder="WX 1234Y">
        <div style="margin-top:10px;"><button class="primary" onclick="addVehicle()">Dodaj pojazd</button></div>
      </div>
      <div style="margin-top:12px;">
        <label>Wybierz pojazd</label>
        <select id="vehicleSelect" onchange="refreshEntries()"></select>
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
        <button onclick="deleteSelectedVehicle()">Usuń wybrany pojazd</button>
        <a href="/api/export/csv" onclick="if(!window.loggedIn){alert('Najpierw zaloguj się.');return false;}">Eksport CSV</a>
      </div>
    </section>

    <section class="card">
      <h3>Wpisy serwisowe</h3>
      <div class="row">
        <div><label>Data</label><input id="date" type="date"></div>
        <div><label>Przebieg (km)</label><input id="mileage" type="number"></div>
      </div>
      <label>Typ usługi</label><input id="service_type" placeholder="Wymiana oleju">
      <label>Opis</label><textarea id="description" rows="3" placeholder="Szczegóły usługi..."></textarea>
      <div class="row">
        <div><label>Koszt (PLN)</label><input id="cost" type="number" step="0.01"></div>
        <div><label>Załącznik (jpg/png/pdf)</label><input id="file" type="file"></div>
      </div>
      <div style="margin-top:10px;"><button class="primary" onclick="addEntry()">Dodaj wpis</button></div>

      <div style="margin-top:16px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
        <input id="search" placeholder="Szukaj w typie/opisie" oninput="refreshEntries()" style="max-width:360px;">
        <span class="muted" style="font-size:12px;">Kliknij link w kolumnie „Plik”, aby podejrzeć załącznik.</span>
      </div>

      <div style="overflow:auto;margin-top:10px;">
        <table>
          <thead><tr><th>Data</th><th>Przebieg</th><th>Typ</th><th>Opis</th><th>Koszt</th><th>Plik</th><th></th></tr></thead>
          <tbody id="entriesTbody"></tbody>
        </table>
      </div>

      <hr style="border-color:#262626;margin:16px 0;">

      <h3>Przypomnienia</h3>
      <div class="row">
        <div>
          <label>Rodzaj</label>
          <select id="r_type" onchange="document.getElementById('r_type_custom_wrap').style.display=(this.value==='Inne'?'block':'none')">
            <option value="Przegląd techniczny">Przegląd techniczny</option>
            <option value="Naprawa u mechanika">Naprawa u mechanika</option>
            <option value="Ubezpieczenie OC/AC">Ubezpieczenie OC/AC</option>
            <option value="Wymiana oleju">Wymiana oleju</option>
            <option value="Inne">Inne</option>
          </select>
          <div id="r_type_custom_wrap" style="display:none;margin-top:8px;">
            <label>Własny powód</label><input id="r_type_custom" placeholder="np. wymiana opon">
          </div>
        </div>
        <div><label>Termin (data)</label><input id="r_date" type="date"></div>
      </div>
      <div class="row">
        <div><label>Termin (przebieg)</label><input id="r_mileage" type="number" placeholder="np. 120000"></div>
        <div><label>Pojazd (opcjonalnie)</label><select id="r_vehicle"></select></div>
      </div>
      <div class="row">
        <div><label><input type="checkbox" id="r_notify_mail" style="width:auto;display:inline-block;margin-right:8px;"> Wyślij e-mail</label></div>
        <div><label>Ile dni wcześniej</label><input id="r_notify_days" type="number" placeholder="np. 7"></div>
      </div>
      <div style="margin-top:8px;"><button class="primary" onclick="addReminder()">Dodaj przypomnienie</button></div>

      <div style="margin-top:12px;overflow:auto;">
        <table>
          <thead><tr><th></th><th>Rodzaj</th><th>Data</th><th>Przebieg</th><th>Mail</th><th>Dni wcześniej</th><th>Pojazd</th><th></th></tr></thead>
        </table>
        <tbody id="r_tbody"></tbody>
      </div>
    </section>
  </main>

  <!-- DASHBOARD -->
  <section class="card" style="margin:0 calc(var(--pad)*1.5) calc(var(--pad)*1.5);">
    <h3>📊 Dashboard</h3>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 14px;">
      <label style="margin:0;align-self:center;">Zakres dni:</label>
      <select id="dash_range" onchange="loadStats()" style="max-width:220px;">
        <option value="7">Ostatnie 7 dni</option>
        <option value="30" selected>Ostatnie 30 dni</option>
        <option value="90">Ostatnie 90 dni</option>
        <option value="0">Wszystko</option>
      </select>
    </div>
    <div>
      <h4 style="margin:0 0 8px">Koszty dziennie</h4>
      <canvas id="chartCost"></canvas>
    </div>
    <div style="margin-top:20px;">
      <h4 style="margin:0 0 8px">Ostatnie przebiegi</h4>
      <table>
        <thead><tr><th>Pojazd</th><th>Ostatni przebieg</th></tr></thead>
        <tbody id="mileageTbody"></tbody>
      </table>
    </div>
  </section>

  <div class="toast" id="toast">✓ Zapisano</div>

  <script>
    let currentVehicleId=null, editEntryId=null; window.loggedIn=false;
    function toast(msg){const t=document.getElementById('toast');t.textContent=msg||'✓ Zapisano';t.style.display='block';setTimeout(()=>t.style.display='none',1600);}

    async function register(){
      const body={email:regEmail.value,name:regName.value,password:regPass.value};
      try{
        await api('/api/register',{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json'}});
        toast('Konto utworzone. Zaloguj się.');
      }catch(e){
        alert(e?.error==='email_in_use'?'Ten e-mail już istnieje.':e?.error==='invalid_email'?'Nieprawidłowy e-mail.':'Błąd rejestracji.');
      }
    }
    async function login(){
      const body={email:regEmail.value,password:regPass.value};
      try{
        const res=await api('/api/login',{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json'}});
        userName.textContent=res.user.name; window.loggedIn=true; authBox.style.display='none';
        await loadVehicles(); await loadReminderVehicles(); await refreshEntries(); await loadStats(); await loadReminders();
      }catch(e){ alert('Błędne dane logowania.'); }
    }
    async function logout(){ try{await api('/api/logout',{method:'POST'});}catch(e){} window.loggedIn=false; location.reload(); }

    async function loadVehicles(){
      const list=await api('/api/vehicles'); const sel=vehicleSelect, rsel=document.getElementById('r_vehicle');
      sel.innerHTML=''; if(rsel) rsel.innerHTML='<option value=\"\">—</option>';
      list.forEach(v=>{
        const label=`${v.make} ${v.model} ${v.year||''} ${v.reg_plate||''}`.trim();
        const o=document.createElement('option'); o.value=v.id; o.textContent=label; sel.appendChild(o);
        if(rsel){ const o2=document.createElement('option'); o2.value=v.id; o2.textContent=label; rsel.appendChild(o2); }
      });
      if(list.length){ currentVehicleId=list[0].id; sel.value=currentVehicleId; }
    }
    async function addVehicle(){
      const body={make:make.value,model:model.value,year:parseInt(year.value||0)||null,vin:vin.value,reg_plate:reg_plate.value};
      try{ await api('/api/vehicles',{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json'}}); toast('Dodano pojazd'); await loadVehicles(); await loadStats(); await loadReminders(); }
      catch(e){ alert('Błąd dodawania pojazdu'); }
    }
    async function deleteSelectedVehicle(){
      if(!vehicleSelect.value) return alert('Wybierz pojazd');
      if(!confirm('Usunąć wybrany pojazd wraz z wpisami?')) return;
      await api('/api/vehicles/'+vehicleSelect.value,{method:'DELETE'}); toast('Usunięto pojazd');
      await loadVehicles(); await loadStats(); await loadReminders(); await refreshEntries();
    }

    async function addEntry(){
      if(!vehicleSelect.value) return alert('Najpierw dodaj pojazd.');
      const fd=new FormData();
      fd.append('vehicle_id',vehicleSelect.value); fd.append('date',date.value); fd.append('mileage',mileage.value);
      fd.append('service_type',service_type.value); fd.append('description',description.value); fd.append('cost',cost.value);
      const f=file.files[0]; if(f) fd.append('file',f);
      try{
        if(editEntryId){
          const body={date:date.value,mileage:mileage.value,service_type:service_type.value,description:description.value,cost:cost.value};
          await api('/api/entries/'+editEntryId,{method:'PUT',body:JSON.stringify(body),headers:{'Content-Type':'application/json'}});
          editEntryId=null; document.querySelector('button.primary').textContent='Dodaj wpis';
        }else{
          await api('/api/entries',{method:'POST',body:fd}); file.value='';
        }
        toast('Zapisano'); await refreshEntries();
      }catch(e){ alert('Błąd zapisu wpisu'); }
    }
    function editEntry(id,e){
      editEntryId=id; date.value=e.date||''; mileage.value=e.mileage||''; service_type.value=e.service_type||''; description.value=e.description||''; cost.value=e.cost||'';
      document.querySelector('button.primary').textContent='Zapisz zmiany'; window.scrollTo({top:0,behavior:'smooth'});
    }
    async function delEntry(id){ if(!confirm('Usunąć wpis?')) return; await api('/api/entries/'+id,{method:'DELETE'}); toast('Usunięto'); refreshEntries(); }

    async function refreshEntries(){
      currentVehicleId = vehicleSelect.value || null;
      const q = search.value || '';
      const params=new URLSearchParams(); if(currentVehicleId) params.set('vehicle_id',currentVehicleId); if(q) params.set('q',q);
      let list=[]; try{ list=await api('/api/entries?'+params.toString()); }catch(e){ return; }
      const tb=entriesTbody; tb.innerHTML='';
      list.forEach(e=>{
        const tr=document.createElement('tr');
        tr.innerHTML=`<td>${e.date}</td><td>${e.mileage?.toLocaleString?.('pl-PL')||''}</td><td>${e.service_type}</td>
                      <td>${e.description||''}</td>
                      <td>${(e.cost||0).toLocaleString('pl-PL',{minimumFractionDigits:2,maximumFractionDigits:2})}</td>
                      <td>${e.attachment?`<a target=_blank href='/uploads/${e.attachment}'>plik</a>`:''}</td>
                      <td class=actions>
                        <button onclick='editEntry(${e.id}, ${JSON.stringify(e).replace(/`/g,"\\`")})'>Edytuj</button>
                        <button onclick='delEntry(${e.id})'>Usuń</button>
                      </td>`;
        tb.appendChild(tr);
      });
      await loadStats();
    }

    // Dashboard
    async function loadStats(){
      try{
        const s=await api('/api/stats'); const range=parseInt(document.getElementById('dash_range')?.value||'0',10);
        let byDay=s.by_day||[];
        if(range>0 && byDay.length>0){
          const cutoff=new Date(); cutoff.setDate(cutoff.getDate()-range+1);
          byDay=byDay.filter(x=>{const d=new Date((x.ymd||'')+'T00:00:00'); return !isNaN(d) && d>=cutoff;});
        }
        byDay.sort((a,b)=> (a.ymd<b.ymd?-1:1));
        const labels=byDay.map(x=>x.ymd), costs=byDay.map(x=>Number(x.total_cost||0));
        const ctx=document.getElementById('chartCost')?.getContext('2d');
        if(ctx){ if(window._chartCost) window._chartCost.destroy();
          window._chartCost=new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Koszt (PLN) / dzień',data:costs,tension:.25,fill:false}]},
            options:{responsive:true,interaction:{mode:'index',intersect:false},
              scales:{x:{grid:{color:'#222'},ticks:{color:'#f3f4f6'}},y:{grid:{color:'#222'},ticks:{color:'#f3f4f6'}}},
              plugins:{legend:{labels:{color:'#f3f4f6'}}}}); }
        const tb=document.getElementById('mileageTbody'); if(tb){ tb.innerHTML='';
          (s.last_mileage||[]).forEach(r=>{const tr=document.createElement('tr'); tr.innerHTML=`<td>${r.label||'-'}</td><td>${(r.mileage||0).toLocaleString('pl-PL')}</td>`; tb.appendChild(tr);}); }
      }catch(e){}
    }

    // Reminders
    async function loadReminders(){
      try{
        const list=await api('/api/reminders'); const tb=document.getElementById('r_tbody'); if(!tb) return; tb.innerHTML='';
        list.forEach(r=>{
          const tr=document.createElement('tr'); const due=r.is_due?'🔔':'';
          tr.innerHTML=`<td>${due}</td><td>${r.title}</td><td>${r.due_date||''}</td><td>${r.due_mileage||''}</td>
                        <td>${r.notify_email?'tak':'nie'}</td><td>${r.notify_before_days??''}</td>
                        <td>${r.vehicle_id||''}</td>
                        <td class=actions><button onclick="completeReminder(${r.id})">Zakończ</button><button onclick="deleteReminder(${r.id})">Usuń</button></td>`;
          tb.appendChild(tr);
        });
      }catch(e){}
    }
    async function loadReminderVehicles(){
      try{
        const list=await api('/api/vehicles'); const rsel=document.getElementById('r_vehicle'); if(!rsel) return; rsel.innerHTML='<option value=\"\">—</option>';
        list.forEach(v=>{const o=document.createElement('option');o.value=v.id;o.textContent=`${v.make} ${v.model} ${v.year||''} ${v.reg_plate||''}`.trim(); rsel.appendChild(o);});
      }catch(e){}
    }
    async function addReminder(){
      const selType=document.getElementById('r_type'); const custom=document.getElementById('r_type_custom');
      const typeVal=selType && selType.value==='Inne' ? (custom.value||'').trim() : (selType?selType.value:'');
      if(!typeVal) return alert('Wybierz rodzaj lub wpisz własny powód.');
      const body={title:typeVal,due_date:r_date.value||null,due_mileage:r_mileage.value||null,vehicle_id:r_vehicle.value||null,
                  notify_email:document.getElementById('r_notify_mail').checked, notify_before_days:parseInt(r_notify_days.value||'')||null};
      await api('/api/reminders',{method:'POST',body:JSON.stringify(body),headers:{'Content-Type':'application/json'}});
      toast('Dodano przypomnienie');
      if(selType) selType.value='Przegląd techniczny'; if(custom) custom.value=''; r_date.value=''; r_mileage.value='';
      document.getElementById('r_type_custom_wrap').style.display='none'; document.getElementById('r_notify_mail').checked=false; r_notify_days.value='';
      await loadReminders();
    }
    async function completeReminder(id){ await api('/api/reminders/'+id,{method:'PUT',body:JSON.stringify({completed_at:new Date().toISOString()}),headers:{'Content-Type':'application/json'}}); await loadReminders(); }
    async function deleteReminder(id){ await api('/api/reminders/'+id,{method:'DELETE'}); await loadReminders(); }
  </script>
</body>
</html>
"""

@app.get("/")
def index_page():
    return INDEX_HTML.replace("{APP_TITLE}", APP_TITLE)

if __name__ == "__main__":
    init_db()
    print(f"\n{APP_TITLE} — start na http://127.0.0.1:5000\n")

    if _HAS_APS:
        scheduler = BackgroundScheduler(daemon=True)
        scheduler.add_job(run_email_reminder_job, "interval", hours=1, next_run_time=datetime.utcnow())
        scheduler.start()
        print("[INFO] APScheduler uruchomiony (maile co godzinę).")
    else:
        print("[WARN] APScheduler nie jest zainstalowany. Wysyłka przypomnień wykona się przynajmniej raz przy starcie.")
        try:
            run_email_reminder_job()
        except Exception as e:
            print("[WARN] run_email_reminder_job przy starcie nie powiódł się:", e)

    app.run(debug=True, host="127.0.0.1", port=5000)
