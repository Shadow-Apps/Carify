#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, re, csv, smtplib, ssl, logging, traceback
import datetime as dt
from decimal import Decimal
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory, make_response, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _HAS_APS = True
except Exception:
    BackgroundScheduler = None
    _HAS_APS = False

from sqlalchemy import create_engine, text

def _normalize_db_url(url: str) -> str:
    # Supabase/ogólnie Postgres URL -> dla SQLAlchemy + psycopg2
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+psycopg2://", 1)
    elif url.startswith("postgresql://") and "+psycopg2" not in url:
        url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
    return url

# --- DB: Supabase (wymaga SSL) ---
DB_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
ENGINE = None
if not DB_URL:
    print("[BOOT] Brak DATABASE_URL – dodaj Connection String z Supabase w Variables.")
else:
    DB_URL = _normalize_db_url(DB_URL)
    ENGINE = create_engine(DB_URL, pool_pre_ping=True, connect_args={"sslmode": "require"})
    print("[BOOT] DATABASE_URL OK.")

def row_to_dict(row):
    if row is None: return None
    m = row._mapping if hasattr(row, "_mapping") else row
    out = {}
    for k, v in dict(m).items():
        if isinstance(v, (dt.date, dt.datetime)): out[k] = v.isoformat()
        elif isinstance(v, Decimal): out[k] = float(v)
        else: out[k] = v
    return out

def db_all(sql, params=None):
    with ENGINE.connect() as conn:
        res = conn.execute(text(sql), params or {})
        return [row_to_dict(r) for r in res]

def db_one(sql, params=None):
    with ENGINE.connect() as conn:
        res = conn.execute(text(sql), params or {})
        r = res.fetchone()
        return row_to_dict(r) if r else None

def db_exec(sql, params=None, returning: bool=False):
    with ENGINE.begin() as conn:
        res = conn.execute(text(sql), params or {})
        if returning:
            r = res.fetchone()
            return row_to_dict(r) if r else None
        return res.rowcount

# --- App / pliki ---
APP_TITLE = "e-Dziennik Serwisowy"
BASE_DIR = os.path.dirname(__file__)
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")  # Render Free: efemeryczne (OK do demo)
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "webp"}

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("EDZIENNIK_SECRET", "dev-secret-change-me"),
    MAX_CONTENT_LENGTH=20 * 1024 * 1024,
    DEBUG=True,
    ENV="development",
    PROPAGATE_EXCEPTIONS=True,
)

logging.basicConfig(level=logging.INFO)

@app.before_request
def _log_request():
    g._start = datetime.utcnow()
    app.logger.info(">>> %s %s", request.method, request.path)

@app.after_request
def _log_response(resp):
    dtsec = (datetime.utcnow() - g._start).total_seconds() if getattr(g, "_start", None) else 0
    app.logger.info("<<< %s %s %s (%.3fs)", request.method, request.path, resp.status_code, dtsec)
    return resp

@app.errorhandler(Exception)
def _handle_error(e):
    app.logger.error("!! Unhandled exception: %s\n%s", e, traceback.format_exc())
    if request.path.startswith("/api"):
        return jsonify({"error":"server_error","detail":str(e)}), 500
    raise e

# --- SMTP (Gmail App Password) ---
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "carifynotification@gmail.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "")   # 16-znakowy App Password z Google
EMAIL_FROM = os.environ.get("EMAIL_FROM", "carifynotification@gmail.com")
DEFAULT_NOTIFY_BEFORE_DAYS = int(os.environ.get("NOTIFY_BEFORE_DAYS", "7"))

def send_email(to_email: str, subject: str, html: str, plain: str = None):
    if not (SMTP_HOST and SMTP_USER and EMAIL_FROM and SMTP_PASS):
        print("[MAIL] Brak SMTP_PASS/konfiguracji.")
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
    ctx = ssl.create_default_context()
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.starttls(context=ctx)
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)
    print(f"[MAIL] Wysłano do {to_email}")
    return True

# --- DB schema ---
def init_db():
    if ENGINE is None:
        return
    ddl = """
    CREATE TABLE IF NOT EXISTS users (
        id              BIGSERIAL PRIMARY KEY,
        email           TEXT UNIQUE NOT NULL,
        name            TEXT NOT NULL,
        password_hash   TEXT NOT NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vehicles (
        id          BIGSERIAL PRIMARY KEY,
        owner_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        make        TEXT NOT NULL,
        model       TEXT NOT NULL,
        year        INTEGER,
        vin         TEXT,
        reg_plate   TEXT,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS service_entries (
        id            BIGSERIAL PRIMARY KEY,
        vehicle_id    BIGINT NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
        date          DATE NOT NULL,
        mileage       INTEGER,
        service_type  TEXT NOT NULL,
        description   TEXT,
        cost          NUMERIC,
        attachment    TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS reminders (
        id                  BIGSERIAL PRIMARY KEY,
        user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        vehicle_id          BIGINT REFERENCES vehicles(id) ON DELETE CASCADE,
        title               TEXT NOT NULL,
        due_date            DATE,
        due_mileage         INTEGER,
        notify_email        BOOLEAN NOT NULL DEFAULT FALSE,
        notify_before_days  INTEGER NOT NULL DEFAULT 7,
        created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        completed_at        TIMESTAMPTZ
    );
    """
    with ENGINE.begin() as conn:
        for stmt in ddl.strip().split(";\n\n"):
            if stmt.strip():
                conn.execute(text(stmt))

_db_ready = False
@app.before_request
def _ensure_db_ready():
    global _db_ready
    if _db_ready: return
    if ENGINE is None: return
    try:
        db_one("SELECT 1")
        init_db()
        _db_ready = True
    except Exception as e:
        print("[DB] init error:", e)

# --- Helpers ---
def login_required(f):
    @wraps(f)
    def wrap(*a, **kw):
        if not session.get("user_id"):
            return jsonify({"error":"auth_required"}), 401
        return f(*a, **kw)
    return wrap

def find_due_email_reminders():
    today = dt.date.today()
    users = {u["id"]: u for u in db_all("SELECT id,email,name FROM users")}
    rows = db_all("""
        SELECT r.*, v.make, v.model, v.reg_plate
        FROM reminders r
        LEFT JOIN vehicles v ON v.id = r.vehicle_id
        WHERE r.completed_at IS NULL
    """)
    out = []
    for r in rows:
        email = users.get(r["user_id"], {}).get("email")
        if not email: continue
        should = False
        if r.get("notify_email"):
            nbd = int(r.get("notify_before_days") or DEFAULT_NOTIFY_BEFORE_DAYS)
            if r.get("due_date"):
                try:
                    due_date = dt.date.fromisoformat(str(r["due_date"]))
                    if today >= (due_date - timedelta(days=nbd)):
                        should = True
                except Exception:
                    pass
        if r.get("due_mileage") and r.get("vehicle_id"):
            last = db_one("SELECT MAX(COALESCE(mileage,0)) AS m FROM service_entries WHERE vehicle_id=:vid", {"vid": r["vehicle_id"]})
            if last and last.get("m") is not None:
                if int(last["m"]) >= (int(r["due_mileage"]) - 500):
                    should = True
        if should:
            out.append((email, r))
    return out

def run_email_reminder_job():
    if ENGINE is None: return
    for to_email, r in find_due_email_reminders():
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

# --- Health / test mail ---
@app.get("/api/health")
def health():
    try:
        if ENGINE is None:
            return jsonify({"ok": False, "error": "Brak DATABASE_URL (Supabase)"}), 500
        db_one("SELECT 1")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/test-mail")
@login_required
def test_mail():
    u = db_one("SELECT email FROM users WHERE id=:id", {"id": session["user_id"]})
    if not u: return jsonify({"error":"user_not_found"}), 404
    ok = send_email(u["email"], "Test: e-Dziennik Serwisowy", "<p>To jest testowy e-mail 🚗🔧</p>")
    return jsonify({"ok": bool(ok), "to": u["email"]})

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
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    name  = (data.get("name") or "").strip()
    password = data.get("password") or ""
    if not (email and name and password):
        return jsonify({"error":"missing_fields"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error":"invalid_email"}), 400
    try:
        db_exec("""
            INSERT INTO users(email,name,password_hash,created_at)
            VALUES (:email,:name,:ph,NOW())
        """, {"email": email, "name": name, "ph": generate_password_hash(password)})
        return jsonify({"ok": True})
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate key" in str(e).lower():
            return jsonify({"error":"email_in_use"}), 400
        raise

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not (email and password):
        return jsonify({"error":"missing_fields"}), 400
    row = db_one("SELECT * FROM users WHERE email=:email", {"email": email})
    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error":"invalid_credentials"}), 401
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
    rows = db_all("SELECT * FROM vehicles WHERE owner_id=:uid ORDER BY created_at DESC", {"uid": session["user_id"]})
    return jsonify(rows)

@app.post("/api/vehicles")
@login_required
def add_vehicle():
    d = request.get_json(silent=True) or {}
    make  = (d.get("make") or "").strip()
    model = (d.get("model") or "").strip()
    year  = d.get("year")
    vin   = (d.get("vin") or "").strip()
    reg   = (d.get("reg_plate") or "").strip()
    if not (make and model): return jsonify({"error":"missing_fields"}), 400
    row = db_exec("""
        INSERT INTO vehicles(owner_id,make,model,year,vin,reg_plate,created_at)
        VALUES (:uid,:make,:model,:year,:vin,:reg,NOW())
        RETURNING id
    """, {"uid": session["user_id"], "make": make, "model": model, "year": year, "vin": vin, "reg": reg}, returning=True)
    return jsonify({"ok": True, "id": row["id"]})

@app.delete("/api/vehicles/<int:vehicle_id>")
@login_required
def delete_vehicle(vehicle_id):
    db_exec("DELETE FROM vehicles WHERE id=:id AND owner_id=:uid", {"id": vehicle_id, "uid": session["user_id"]})
    return jsonify({"ok": True})

# --- Entries ---
@app.get("/api/entries")
@login_required
def list_entries():
    vehicle_id = request.args.get("vehicle_id", type=int)
    q = request.args.get("q", type=str)
    params = {"uid": session["user_id"]}
    sql = "SELECT e.* FROM service_entries e JOIN vehicles v ON v.id=e.vehicle_id WHERE v.owner_id=:uid"
    if vehicle_id:
        sql += " AND e.vehicle_id=:vid"; params["vid"] = vehicle_id
    if q:
        sql += " AND (e.service_type ILIKE :q OR e.description ILIKE :q)"; params["q"] = f"%{q}%"
    sql += " ORDER BY e.date DESC, e.id DESC"
    return jsonify(db_all(sql, params))

@app.post("/api/entries")
@login_required
def add_entry():
    data = request.form if request.form else (request.get_json(silent=True) or {})
    try:
        vehicle_id = int(data.get("vehicle_id"))
    except Exception:
        return jsonify({"error":"vehicle_id_required"}), 400

    date = data.get("date") or datetime.utcnow().date().isoformat()
    mileage = int(data.get("mileage") or 0)
    service_type = (data.get("service_type") or "").strip()
    description  = (data.get("description") or "").strip()
    cost = float(data.get("cost") or 0)
    if not service_type: return jsonify({"error":"service_type_required"}), 400

    attachment_name = None
    if "file" in request.files and request.files["file"].filename:
        f = request.files["file"]
        fname = secure_filename(f.filename)
        ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error":"file_type_not_allowed"}), 400
        ts = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        attachment_name = f"{ts}_{fname}"
        f.save(os.path.join(UPLOAD_DIR, attachment_name))

    row = db_exec("""
        INSERT INTO service_entries(vehicle_id,date,mileage,service_type,description,cost,attachment,created_at)
        VALUES (:vid, :date, :mileage, :stype, :descr, :cost, :att, NOW())
        RETURNING id
    """, {"vid": vehicle_id, "date": date, "mileage": mileage, "stype": service_type, "descr": description, "cost": cost, "att": attachment_name},
       returning=True)
    return jsonify({"ok": True, "id": row["id"], "attachment": attachment_name})

@app.put("/api/entries/<int:entry_id>")
@login_required
def update_entry(entry_id):
    data = request.get_json(silent=True) or {}
    fields, params = [], {"id": entry_id, "uid": session["user_id"]}
    mapping = {"date":"date","mileage":"mileage","service_type":"service_type","description":"description","cost":"cost"}
    for k in mapping:
        if k in data:
            fields.append(f"{mapping[k]} = :{k}")
            params[k] = data[k]
    if not fields: return jsonify({"error":"no_fields"}), 400
    sql = "UPDATE service_entries SET " + ", ".join(fields) + ", updated_at=NOW() WHERE id=:id AND vehicle_id IN (SELECT id FROM vehicles WHERE owner_id=:uid)"
    db_exec(sql, params)
    return jsonify({"ok": True})

@app.delete("/api/entries/<int:entry_id>")
@login_required
def delete_entry(entry_id):
    db_exec("DELETE FROM service_entries WHERE id=:id AND vehicle_id IN (SELECT id FROM vehicles WHERE owner_id=:uid)",
            {"id": entry_id, "uid": session["user_id"]})
    return jsonify({"ok": True})

# --- Files ---
@app.get("/uploads/<path:filename>")
@login_required
def get_upload(filename):
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=False)

# --- Export ---
@app.get("/api/export/csv")
@login_required
def export_csv():
    vehicle_id = request.args.get("vehicle_id", type=int)
    params = {"uid": session["user_id"]}
    sql = ("SELECT e.id,e.vehicle_id,e.date,e.mileage,e.service_type,e.description,e.cost,e.attachment "
           "FROM service_entries e JOIN vehicles v ON v.id=e.vehicle_id WHERE v.owner_id=:uid")
    if vehicle_id: sql += " AND e.vehicle_id=:vid"; params["vid"] = vehicle_id
    sql += " ORDER BY e.date DESC, e.id DESC"
    rows = db_all(sql, params)
    out_path = os.path.join(BASE_DIR, "export.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id","vehicle_id","date","mileage","service_type","description","cost","attachment"])
        for r in rows:
            w.writerow([r.get("id"), r.get("vehicle_id"), r.get("date"), r.get("mileage"),
                        r.get("service_type"), r.get("description"), r.get("cost"), r.get("attachment")])
    resp = make_response(open(out_path, "rb").read())
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = "attachment; filename=service_entries.csv"
    return resp

# --- Statystyki: koszty dziennie + ostatnie przebiegi ---
@app.get("/api/stats")
@login_required
def stats():
    uid = session["user_id"]
    by_day = db_all("""
        SELECT e.date AS ymd, SUM(COALESCE(e.cost,0)) AS total_cost, COUNT(*) AS entries
        FROM service_entries e JOIN vehicles v ON v.id=e.vehicle_id
        WHERE v.owner_id=:uid
        GROUP BY e.date
        ORDER BY e.date
    """, {"uid": uid})
    last_mileage = db_all("""
        SELECT v.id, (v.make || ' ' || v.model) AS label,
               (SELECT e.mileage FROM service_entries e
                 WHERE e.vehicle_id=v.id AND e.mileage IS NOT NULL
                 ORDER BY e.date DESC, e.id DESC LIMIT 1) AS mileage
        FROM vehicles v
        WHERE v.owner_id=:uid
        ORDER BY v.id
    """, {"uid": uid})
    return jsonify({"by_day": by_day, "last_mileage": last_mileage})

# --- Przypomnienia ---
@app.get("/api/reminders")
@login_required
def list_reminders():
    uid = session["user_id"]
    rows = db_all("SELECT * FROM reminders WHERE user_id=:uid ORDER BY COALESCE(due_date, DATE '9999-12-31'), id DESC", {"uid": uid})
    result = []
    for r in rows:
        rec = dict(r); due = False
        if rec.get("due_date"):
            try:
                due = due or (str(rec["due_date"]) <= dt.date.today().isoformat())
            except Exception:
                pass
        if rec.get("due_mileage") and rec.get("vehicle_id"):
            last = db_one("SELECT MAX(COALESCE(mileage,0)) AS m FROM service_entries WHERE vehicle_id=:vid", {"vid": rec["vehicle_id"]})
            if last and last.get("m") is not None:
                due = due or (int(last["m"]) >= int(rec["due_mileage"] or 0))
        rec["is_due"] = bool(due)
        result.append(rec)
    return jsonify(result)

@app.post("/api/reminders")
@login_required
def create_reminder():
    d = request.get_json(silent=True) or {}
    title = (d.get("title") or "").strip()
    if not title: return jsonify({"error":"title_required"}), 400
    due_date = d.get("due_date") or None
    due_mileage = d.get("due_mileage") if d.get("due_mileage") not in ("", None) else None
    vehicle_id = d.get("vehicle_id") if d.get("vehicle_id") not in ("", None) else None
    notify_email = str(d.get("notify_email")).lower() in ("1","true","on")
    try:
        notify_before_days = int(d.get("notify_before_days")) if d.get("notify_before_days") not in ("", None) else DEFAULT_NOTIFY_BEFORE_DAYS
    except Exception:
        notify_before_days = DEFAULT_NOTIFY_BEFORE_DAYS
    row = db_exec("""
        INSERT INTO reminders(user_id,vehicle_id,title,due_date,due_mileage,notify_email,notify_before_days,created_at)
        VALUES (:uid,:vid,:title,:dd,:dm,:ne,:nbd,NOW())
        RETURNING id
    """, {"uid": session["user_id"], "vid": vehicle_id, "title": title, "dd": due_date,
          "dm": due_mileage, "ne": notify_email, "nbd": notify_before_days}, returning=True)
    return jsonify({"ok": True, "id": row["id"]})

@app.put("/api/reminders/<int:rid>")
@login_required
def update_reminder(rid):
    d = request.get_json(silent=True) or {}
    fields, params = [], {"rid": rid, "uid": session["user_id"]}
    for k in ("title","due_date","due_mileage","vehicle_id","completed_at","notify_email","notify_before_days"):
        if k in d:
            fields.append(f"{k} = :{k}")
            params[k] = d[k]
    if not fields: return jsonify({"error":"no_fields"}), 400
    db_exec("UPDATE reminders SET " + ", ".join(fields) + " WHERE id=:rid AND user_id=:uid", params)
    return jsonify({"ok": True})

@app.delete("/api/reminders/<int:rid>")
@login_required
def delete_reminder(rid):
    db_exec("DELETE FROM reminders WHERE id=:rid AND user_id=:uid", {"rid": rid, "uid": session["user_id"]})
    return jsonify({"ok": True})

# --- Frontend (carbon + czerwony) ---
INDEX_HTML = """
<!doctype html>
<html lang=pl>
<head>
  <meta charset=utf-8>
  <meta name=viewport content="width=device-width,initial-scale=1">
  <title>{APP_TITLE}</title>

  <script>
    // Helper: fetch JSON z ładnym błędem
    async function api(path, opts = {}) {
      try {
        const res = await fetch(path, Object.assign({ headers: {} }, opts));
        const ct = res.headers.get('content-type') || '';
        let data = null;
        if (ct.includes('application/json')) data = await res.json().catch(() => null);
        else data = await res.text().catch(() => null);
        if (!res.ok) {
          console.error('[API ERR]', path, res.status, data);
          const msg = (data && (data.error || data.detail || data.message)) || String(data) || 'Błąd';
          throw new Error('[' + res.status + '] ' + msg);
        }
        return data;
      } catch (e) {
        console.error('[API EXC]', path, e);
        throw e;
      }
    }
    // globalne łapanie błędów JS
    window.addEventListener('error', ev => { console.error('[window.error]', ev.message); alert('Błąd JS: ' + ev.message); });
    window.addEventListener('unhandledrejection', ev => { console.error('[unhandledrejection]', ev.reason); alert('Błąd: ' + (ev.reason?.message || ev.reason || 'Nieznany')); });
  </script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

  <style>
    :root { --bg:#0a0a0a; --bg2:#1a0000; --card:#141414; --text:#f3f4f6; --muted:#9ca3af; --border:#262626; --accent:#ff3232; --accent-600:#cc2727; --r:14px; --pad:14px; --gap:18px; --sh:0 10px 28px rgba(0,0,0,.7) }
    * { box-sizing:border-box }
    body { margin:0; background:linear-gradient(180deg,var(--bg),var(--bg2)); color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial }
    header { position:sticky; top:0; z-index:10; background:#0f0f0f; border-bottom:1px solid var(--border); display:flex; align-items:center; gap:var(--gap); padding:var(--pad) calc(var(--pad)*1.5) }
    .brand { display:flex; align-items:center; gap:10px; font-weight:800 }
    .brand svg { width:28px; height:28px }
    main { padding:calc(var(--pad)*1.5); display:grid; grid-template-columns:minmax(320px,380px) 1fr; gap:var(--gap); align-items:start }
    .card { background:var(--card); border:1px solid var(--border); border-radius:var(--r); padding:var(--pad); box-shadow:var(--sh) }
    h3 { margin:0 0 10px }
    label { display:block; font-size:12px; color:var(--muted); margin:8px 0 6px }
    input, select, textarea { width:100%; display:block; padding:12px; border-radius:10px; border:1px solid var(--border); background:#0f0f0f; color:#f3f4f6; outline:none }
    input:focus, select:focus, textarea:focus { border-color:var(--accent); box-shadow:0 0 0 2px rgba(255,50,50,.45) }
    button { padding:10px 14px; border:1px solid var(--border); background:#0f0f0f; color:#f3f4f6; border-radius:10px; cursor:pointer }
    button.primary { background:var(--accent); border-color:var(--accent); color:#fff }
    button.primary:hover { background:var(--accent-600) }
    a { color:#ff7b7b; text-decoration:none }
    a:hover { text-decoration:underline }
    .row { display:grid; grid-template-columns:1fr 1fr; gap:var(--gap) }
    @media (max-width:1100px) {
      main { grid-template-columns:1fr }
      .row { grid-template-columns:1fr }
    }
    table { width:100%; border-collapse:collapse; background:#0f0f0f; border:1px solid var(--border); border-radius:var(--r); overflow:hidden }
    thead th { background:#1f1f1f; color:#ff9c9c }
    th, td { padding:12px; border-bottom:1px solid var(--border); text-align:left; font-size:14px }
    .actions { display:flex; gap:8px; flex-wrap:wrap }
    .muted { color:var(--muted) }
    .toast { position:fixed; right:16px; bottom:16px; background:var(--accent); color:#fff; padding:10px 14px; border-radius:10px; display:none; box-shadow:var(--sh) }
    canvas { background:radial-gradient(ellipse at top,#151515,#0d0d0d); border:1px solid var(--border); border-radius:12px; padding:8px }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <!-- proste logo "koło + klucz" w gradiencie -->
      <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff3232"/><stop offset="100%" stop-color="#cc2727"/></linearGradient></defs>
        <circle cx="20" cy="20" r="10" stroke="url(#g)" stroke-width="4"/>
        <path d="M28 28 L46 46 M46 46 h6 v6 h-6 v-6 m6 0 v-6 h-6" stroke="url(#g)" stroke-width="5" stroke-linecap="round"/>
        <circle cx="20" cy="20" r="3" fill="#ff3232"/>
      </svg>
      <span>{APP_TITLE}</span>
    </div>
    <div style="margin-left:auto; display:flex; gap:10px; align-items:center;">
      <span id="userName" class="muted"></span>
      <button type="button" onclick="logout()">Wyloguj</button>
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
        <div style="display:flex; gap:8px; margin-top:10px; flex-wrap:wrap;">
          <button type="button" class="primary" onclick="register()">Rejestracja</button>
          <button type="button" onclick="login()">Logowanie</button>
        </div>
        <p class="muted" style="font-size:12px; margin-top:8px;">Utwórz konto lub zaloguj się, aby zarządzać pojazdami i wpisami.</p>
      </div>

      <hr style="border-color:#262626; margin:14px 0;">

      <h3>Pojazdy</h3>
<div>
  <label>Marka</label>
  <select id="makeSelect" onchange="onMakeChange()"></select>
  <div id="makeCustomWrap" style="display:none; margin-top:8px;">
    <label>Inna marka</label>
    <input id="makeCustom" placeholder="np. Zastava">
  </div>

  <label>Model</label>
  <select id="modelSelect"></select>
  <div id="modelCustomWrap" style="display:none; margin-top:8px;">
    <label>Inny model</label>
    <input id="modelCustom" placeholder="np. 750">
  </div>

  <div class="row" style="margin-top:8px;">
    <div><label>Rok</label><input id="year" type="number" placeholder="2018"></div>
    <div><label>VIN</label><input id="vin" placeholder="WVWZZZ..."></div>
  </div>
  <label>Nr rej.</label><input id="reg_plate" placeholder="WX 1234Y">
  <div style="margin-top:10px;"><button type="button" class="primary" onclick="addVehicle()">Dodaj pojazd</button></div>
</div>
<div style="margin-top:12px;">
  <label>Wybierz pojazd</label>
  <select id="vehicleSelect" onchange="refreshEntries()"></select>
</div>
<div style="margin-top:10px; display:flex; gap:8px; flex-wrap:wrap;">
  <button type="button" onclick="deleteSelectedVehicle()">Usuń wybrany pojazd</button>
  <a href="/api/export/csv" onclick="if(!window.loggedIn){ alert('Najpierw zaloguj się.'); return false; }">Eksport CSV</a>
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
      <div style="margin-top:10px;"><button type="button" class="primary" onclick="addEntry()">Dodaj wpis</button></div>

      <div style="margin-top:16px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
        <input id="search" placeholder="Szukaj w typie/opisie" oninput="refreshEntries()" style="max-width:360px;">
        <span class="muted" style="font-size:12px;">Kliknij link w kolumnie „Plik”, aby podejrzeć załącznik.</span>
      </div>

      <div style="overflow:auto; margin-top:10px;">
        <table>
          <thead><tr><th>Data</th><th>Przebieg</th><th>Typ</th><th>Opis</th><th>Koszt</th><th>Plik</th><th></th></tr></thead>
          <tbody id="entriesTbody"></tbody>
        </table>
      </div>

      <hr style="border-color:#262626; margin:16px 0;">

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
          <div id="r_type_custom_wrap" style="display:none; margin-top:8px;">
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
      <div style="margin-top:8px;"><button type="button" class="primary" onclick="addReminder()">Dodaj przypomnienie</button></div>

      <div style="margin-top:12px; overflow:auto;">
        <table>
          <thead><tr><th></th><th>Rodzaj</th><th>Data</th><th>Przebieg</th><th>Mail</th><th>Dni wcześniej</th><th>Pojazd</th><th></th></tr></thead>
          <tbody id="r_tbody"></tbody>
        </table>
      </div>
    </section>
  </main>

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
    const $ = (id) => document.getElementById(id);
    window.loggedIn = false;
    window._entriesCache = [];

    // ====== TOAST ======
    window.toast = function(msg){
      const t = $('toast');
      t.textContent = msg || '✓ Zapisano';
      t.style.display = 'block';
      setTimeout(() => t.style.display = 'none', 1600);
    };

    // ====== KONTO ======
    window.register = async function(){
      try{
        const email = $('regEmail').value || '';
        const name  = $('regName').value || '';
        const pass  = $('regPass').value || '';
        if(!email || !name || !pass) return alert('Uzupełnij e-mail, imię i hasło.');
        await api('/api/register', {
          method:'POST',
          body: JSON.stringify({ email, name, password: pass }),
          headers:{'Content-Type':'application/json'}
        });
        toast('Konto utworzone. Zaloguj się.');
      }catch(e){ alert('Rejestracja nieudana: ' + (e.message||'')); }
    };
    // ====== BAZA: marki → modele (Europa; popularne) ======
const CAR_DATA = {
  "Audi": ["A1","A3","A4","A5","A6","A7","A8","Q2","Q3","Q5","Q7","Q8","TT","e-tron"],
  "BMW": ["1 Series","2 Series","3 Series","4 Series","5 Series","7 Series","X1","X3","X5","X7","i3","i4","iX"],
  "Mercedes-Benz": ["A-Class","B-Class","C-Class","E-Class","S-Class","GLA","GLB","GLC","GLE","GLS","CLA","CLS","EQC","EQA"],
  "Volkswagen": ["up!","Polo","Golf","Passat","Tiguan","T-Roc","Touareg","Arteon","ID.3","ID.4","ID.5"],
  "Škoda": ["Fabia","Scala","Octavia","Superb","Kamiq","Karoq","Kodiaq","Enyaq"],
  "SEAT": ["Ibiza","Arona","Leon","Ateca","Tarraco"],
  "Cupra": ["Born","Formentor","Ateca","Leon"],
  "Renault": ["Clio","Captur","Megane","Austral","Arkana","Kadjar","Koleos","Twingo","Scenic"],
  "Dacia": ["Sandero","Logan","Duster","Jogger","Spring"],
  "Peugeot": ["108","208","308","508","2008","3008","5008","Rifter","e-208","e-2008"],
  "Citroën": ["C1","C3","C3 Aircross","C4","C4 Cactus","C5 Aircross","Berlingo","ë-C4"],
  "DS": ["DS 3","DS 4","DS 7","DS 9"],
  "Opel": ["Corsa","Astra","Insignia","Mokka","Crossland","Grandland","Combo"],
  "Vauxhall": ["Corsa","Astra","Insignia","Mokka","Crossland","Grandland"],
  "Ford": ["Ka+","Fiesta","Puma","Focus","Mondeo","Kuga","EcoSport","S-Max","Galaxy","Mustang","Mach-E"],
  "Fiat": ["500","500X","Panda","Tipo","Punto","Doblo"],
  "Alfa Romeo": ["Giulia","Giulietta","Stelvio","Tonale","MiTo"],
  "Lancia": ["Ypsilon"],
  "Abarth": ["595","695"],
  "Toyota": ["Aygo","Yaris","Corolla","Camry","C-HR","RAV4","Auris","Avensis","Highlander","Proace"],
  "Lexus": ["CT","IS","ES","GS","NX","RX","UX","LC"],
  "Nissan": ["Micra","Leaf","Juke","Qashqai","X-Trail","Note"],
  "Mazda": ["2","3","6","CX-3","CX-30","CX-5","MX-5"],
  "Honda": ["Jazz","Civic","Accord","HR-V","CR-V","e"],
  "Subaru": ["Impreza","XV","Forester","Outback","Levorg"],
  "Suzuki": ["Swift","Ignis","Baleno","Vitara","S-Cross","Jimny"],
  "Hyundai": ["i10","i20","i30","Elantra","Tucson","Kona","Santa Fe","Ioniq","Ioniq 5"],
  "Kia": ["Picanto","Rio","Ceed","Proceed","Stonic","Sportage","Sorento","Niro","EV6"],
  "Volvo": ["S60","S90","V60","V90","XC40","XC60","XC90","EX30","EX90"],
  "Saab": ["9-3","9-5"],
  "Jaguar": ["XE","XF","XJ","E-Pace","F-Pace","I-Pace","F-Type"],
  "Land Rover": ["Defender","Discovery Sport","Discovery","Range Rover Evoque","Range Rover Velar","Range Rover Sport","Range Rover"],
  "MINI": ["3 Door","5 Door","Clubman","Countryman","Convertible","Electric"],
  "Porsche": ["718","911","Taycan","Panamera","Macan","Cayenne"],
  "Tesla": ["Model 3","Model Y","Model S","Model X"],
  "Smart": ["fortwo","forfour","#1"],
  "Mitsubishi": ["Space Star","ASX","Eclipse Cross","Outlander","L200"],
  "Jeep": ["Renegade","Compass","Cherokee","Grand Cherokee","Wrangler"],
  "Cupra": ["Born","Formentor","Ateca","Leon"],
  "Saab": ["9-3","9-5"]
};
// Dodajemy globalnie dopisywalne opcji „Inna marka/ Inny model”
const OTHER_MAKE = "Inna marka…";
const OTHER_MODEL = "Inny model…";

function populateMakes() {
  const makeSel = document.getElementById('makeSelect');
  if (!makeSel) return;
  makeSel.innerHTML = '';
  const makes = Object.keys(CAR_DATA).sort();
  // Pierwsze opcje
  const def = document.createElement('option'); def.value = ''; def.textContent = '— wybierz markę —'; makeSel.appendChild(def);
  makes.forEach(m => { const o = document.createElement('option'); o.value = m; o.textContent = m; makeSel.appendChild(o); });
  const other = document.createElement('option'); other.value = OTHER_MAKE; other.textContent = OTHER_MAKE; makeSel.appendChild(other);
  // Zainicjalizuj modele
  onMakeChange();
}

function onMakeChange() {
  const makeSel = document.getElementById('makeSelect');
  const modelSel = document.getElementById('modelSelect');
  const makeCustomWrap = document.getElementById('makeCustomWrap');
  const modelCustomWrap = document.getElementById('modelCustomWrap');

  const makeVal = makeSel.value;
  const showMakeCustom = (makeVal === OTHER_MAKE);
  makeCustomWrap.style.display = showMakeCustom ? 'block' : 'none';

  modelSel.innerHTML = '';
  const def = document.createElement('option'); def.value=''; def.textContent='— wybierz model —'; modelSel.appendChild(def);

  let models = [];
  if (makeVal && makeVal !== OTHER_MAKE) {
    models = CAR_DATA[makeVal] || [];
  }
  models.forEach(md => { const o = document.createElement('option'); o.value = md; o.textContent = md; modelSel.appendChild(o); });

  const other = document.createElement('option'); other.value = OTHER_MODEL; other.textContent = OTHER_MODEL; modelSel.appendChild(other);

  // schowaj pole „Inny model” dopóki nie zostanie wybrane
  modelCustomWrap.style.display = 'none';
}

document.addEventListener('change', (ev) => {
  if (ev.target && ev.target.id === 'modelSelect') {
    const modelCustomWrap = document.getElementById('modelCustomWrap');
    modelCustomWrap.style.display = (ev.target.value === OTHER_MODEL) ? 'block' : 'none';
  }
});

function getSelectedMakeModel() {
  const makeSel = document.getElementById('makeSelect');
  const modelSel = document.getElementById('modelSelect');
  const makeCustom = document.getElementById('makeCustom');
  const modelCustom = document.getElementById('modelCustom');

  let make = '';
  let model = '';

  if (makeSel.value === OTHER_MAKE) {
    make = (makeCustom.value || '').trim();
  } else {
    make = makeSel.value || '';
  }

  if (modelSel.value === OTHER_MODEL) {
    model = (modelCustom.value || '').trim();
  } else {
    model = modelSel.value || '';
  }

  return { make, model };
}

// Zainicjuj listy przy załadowaniu strony
document.addEventListener('DOMContentLoaded', populateMakes);

    window.login = async function(){
      try{
        const res = await api('/api/login', {
          method:'POST',
          body: JSON.stringify({ email: $('regEmail').value, password: $('regPass').value }),
          headers:{'Content-Type':'application/json'}
        });
        $('userName').textContent = res.user.name;
        window.loggedIn = true;
        $('authBox').style.display = 'none';
        await window.loadVehicles(); await window.loadReminderVehicles();
        await window.refreshEntries(); await window.loadStats(); await window.loadReminders();
      }catch(e){ alert('Błędne dane logowania.'); }
    };

    window.logout = async function(){
      try{ await api('/api/logout', {method:'POST'}); }catch(e){}
      window.loggedIn = false; location.reload();
    };

    // ====== POJAZDY ======
    window.loadVehicles = async function(){
      const list = await api('/api/vehicles');
      const sel = $('vehicleSelect'), rsel = $('r_vehicle');
      sel.innerHTML = '';
      if(rsel) rsel.innerHTML = '<option value="">—</option>';
      list.forEach(v => {
        const label = (v.make + ' ' + v.model + ' ' + (v.year||'') + ' ' + (v.reg_plate||'')).trim();
        const o = document.createElement('option'); o.value = v.id; o.textContent = label; sel.appendChild(o);
        if(rsel){ const o2 = document.createElement('option'); o2.value = v.id; o2.textContent = label; rsel.appendChild(o2); }
      });
      if(list.length){ sel.value = String(list[0].id); }
    };

    window.addVehicle = async function(){
  try{
    const { make, model } = getSelectedMakeModel();
    if (!make || !model) return alert('Wybierz markę i model (lub wpisz własne).');

    const body = {
      make,
      model,
      year: parseInt(document.getElementById('year').value || 0) || null,
      vin: document.getElementById('vin').value,
      reg_plate: document.getElementById('reg_plate').value,
    };
    await api('/api/vehicles', { method:'POST', body: JSON.stringify(body), headers:{'Content-Type':'application/json'} });
    toast('Dodano pojazd');
    await loadVehicles(); await loadStats(); await loadReminders();
  }catch(e){ alert('Błąd dodawania pojazdu'); }
};

    window.deleteSelectedVehicle = async function(){
      const sel = $('vehicleSelect');
      if(!sel.value) return alert('Wybierz pojazd');
      if(!confirm('Usunąć wybrany pojazd wraz z wpisami?')) return;
      await api('/api/vehicles/' + sel.value, {method:'DELETE'});
      toast('Usunięto pojazd');
      await loadVehicles(); await loadStats(); await loadReminders(); await refreshEntries();
    };

    // ====== WPISY ======
    window.addEntry = async function(){
      const sel = $('vehicleSelect');
      if(!sel.value) return alert('Najpierw dodaj pojazd.');

      const fd = new FormData();
      fd.append('vehicle_id', sel.value);
      fd.append('date', $('date').value);
      fd.append('mileage', $('mileage').value);
      fd.append('service_type', $('service_type').value);
      fd.append('description', $('description').value);
      fd.append('cost', $('cost').value);
      const f = $('file').files[0];
      if (f) fd.append('file', f);

      try{
        if(window.editEntryId){
          const body = {
            date: $('date').value,
            mileage: $('mileage').value,
            service_type: $('service_type').value,
            description: $('description').value,
            cost: $('cost').value
          };
          await api('/api/entries/' + window.editEntryId, { method:'PUT', body: JSON.stringify(body), headers:{'Content-Type':'application/json'} });
          window.editEntryId = null;
          document.querySelector('button.primary').textContent = 'Dodaj wpis';
        } else {
          await api('/api/entries', { method:'POST', body: fd });
          $('file').value = '';
        }
        toast('Zapisano'); await refreshEntries();
      }catch(e){ alert('Błąd zapisu wpisu'); }
    };

    window.editEntryId = null;
    window.editEntry = function(id){
      const e = (window._entriesCache||[]).find(x => String(x.id) === String(id));
      if(!e) return;
      window.editEntryId = id;
      $('date').value = e.date || '';
      $('mileage').value = e.mileage || '';
      $('service_type').value = e.service_type || '';
      $('description').value = e.description || '';
      $('cost').value = e.cost || '';
      document.querySelector('button.primary').textContent = 'Zapisz zmiany';
      window.scrollTo({ top: 0, behavior: 'smooth' });
    };

    window.delEntry = async function(id){
      if(!confirm('Usunąć wpis?')) return;
      await api('/api/entries/' + id, {method:'DELETE'});
      toast('Usunięto'); refreshEntries();
    };

    window.refreshEntries = async function(){
      const sel = $('vehicleSelect');
      const currentVehicleId = sel.value || null;
      const q = $('search').value || '';
      const params = new URLSearchParams();
      if(currentVehicleId) params.set('vehicle_id', currentVehicleId);
      if(q) params.set('q', q);
      let list = [];
      try{ list = await api('/api/entries?' + params.toString()); } catch(e){ return; }
      window._entriesCache = list;
      const tb = $('entriesTbody'); tb.innerHTML = '';
      list.forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML =
          '<td>' + e.date + '</td>' +
          '<td>' + (e.mileage?.toLocaleString?.("pl-PL") || "") + '</td>' +
          '<td>' + e.service_type + '</td>' +
          '<td>' + (e.description || "") + '</td>' +
          '<td>' + Number(e.cost||0).toLocaleString("pl-PL",{minimumFractionDigits:2, maximumFractionDigits:2}) + '</td>' +
          '<td>' + (e.attachment ? ('<a target=_blank href="/uploads/' + e.attachment + '">plik</a>') : '') + '</td>' +
          '<td class="actions">' +
            '<button type="button" onclick="editEntry(' + e.id + ')">Edytuj</button> ' +
            '<button type="button" onclick="delEntry(' + e.id + ')">Usuń</button>' +
          '</td>';
        tb.appendChild(tr);
      });
      await loadStats();
    };

    // ====== STATYSTYKI ======
    window.loadStats = async function(){
      try{
        const s = await api('/api/stats');
        const range = parseInt(($('dash_range')?.value || '0'), 10);
        let byDay = s.by_day || [];
        if(range > 0 && byDay.length > 0){
          const cut = new Date(); cut.setDate(cut.getDate() - range + 1);
          byDay = byDay.filter(x => { const d = new Date((x.ymd||'') + 'T00:00:00'); return !isNaN(d) && d >= cut; });
        }
        byDay.sort((a,b)=> (a.ymd < b.ymd ? -1 : 1));
        const labels = byDay.map(x => x.ymd), costs = byDay.map(x => Number(x.total_cost||0));
        const ctx = $('chartCost')?.getContext('2d');
        if(ctx){
          if(window._chartCost) window._chartCost.destroy();
          window._chartCost = new Chart(ctx, {
            type:'line',
            data:{ labels, datasets:[{ label:'Koszt (PLN) / dzień', data:costs, tension:.25, fill:false }]},
            options:{ responsive:true, interaction:{ mode:'index', intersect:false },
              scales:{ x:{ grid:{color:'#222'}, ticks:{color:'#f3f4f6'} }, y:{ grid:{color:'#222'}, ticks:{color:'#f3f4f6'} } },
              plugins:{ legend:{ labels:{ color:'#f3f4f6' } } }
            }
          });
        }
        const tb = $('mileageTbody');
        if(tb){
          tb.innerHTML = '';
          (s.last_mileage || []).forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>' + (r.label || '-') + '</td><td>' + Number(r.mileage||0).toLocaleString('pl-PL') + '</td>';
            tb.appendChild(tr);
          });
        }
      }catch(e){}
    };

    // ====== PRZYPOMNIENIA ======
    window.loadReminders = async function(){
      try{
        const list = await api('/api/reminders');
        const tb = $('r_tbody'); if(!tb) return; tb.innerHTML = '';
        list.forEach(r => {
          const tr = document.createElement('tr');
          const due = r.is_due ? '🔔' : '';
          tr.innerHTML =
            '<td>' + due + '</td><td>' + r.title + '</td><td>' + (r.due_date||'') + '</td><td>' + (r.due_mileage||'') + '</td>' +
            '<td>' + (r.notify_email ? 'tak' : 'nie') + '</td><td>' + (r.notify_before_days ?? '') + '</td>' +
            '<td>' + (r.vehicle_id || '') + '</td>' +
            '<td class="actions"><button type="button" onclick="completeReminder(' + r.id + ')">Zakończ</button> <button type="button" onclick="deleteReminder(' + r.id + ')">Usuń</button></td>';
          tb.appendChild(tr);
        });
      }catch(e){}
    };

    window.loadReminderVehicles = async function(){
      try{
        const list = await api('/api/vehicles');
        const rsel = $('r_vehicle'); if(!rsel) return;
        rsel.innerHTML = '<option value="">—</option>';
        list.forEach(v => {
          const o = document.createElement('option');
          o.value = v.id;
          o.textContent = (v.make + ' ' + v.model + ' ' + (v.year||'') + ' ' + (v.reg_plate||'')).trim();
          rsel.appendChild(o);
        });
      }catch(e){}
    };

    window.addReminder = async function(){
      const selType = $('r_type');
      const custom = $('r_type_custom');
      const typeVal = selType && selType.value === 'Inne' ? (custom.value||'').trim() : (selType ? selType.value : '');
      if(!typeVal) return alert('Wybierz rodzaj lub wpisz własny powód.');
      const body = {
        title: typeVal,
        due_date: $('r_date').value || null,
        due_mileage: $('r_mileage').value || null,
        vehicle_id: $('r_vehicle').value || null,
        notify_email: $('r_notify_mail').checked,
        notify_before_days: parseInt($('r_notify_days').value || '') || null
      };
      await api('/api/reminders', { method:'POST', body: JSON.stringify(body), headers:{'Content-Type':'application/json'} });
      toast('Dodano przypomnienie');
      selType.value='Przegląd techniczny'; if(custom) custom.value='';
      $('r_date').value=''; $('r_mileage').value='';
      $('r_type_custom_wrap').style.display='none';
      $('r_notify_mail').checked=false;
      $('r_notify_days').value='';
      await loadReminders();
    };

    window.completeReminder = async function(id){
      await api('/api/reminders/' + id, { method:'PUT', body: JSON.stringify({ completed_at: new Date().toISOString() }), headers:{'Content-Type':'application/json'} });
      await loadReminders();
    };

    window.deleteReminder = async function(id){
      await api('/api/reminders/' + id, { method:'DELETE' });
      await loadReminders();
    };
  </script>
</body>
</html>
"""



@app.get("/")
def index_page():
    return INDEX_HTML.replace("{APP_TITLE}", APP_TITLE)

if __name__ == "__main__":
    init_db()
    print(f"\n{APP_TITLE} — start lokalnie na http://127.0.0.1:5000 (Render użyje gunicorn)\n")
    if _HAS_APS:
        scheduler = BackgroundScheduler(daemon=True)
        scheduler.add_job(run_email_reminder_job, "interval", hours=1, next_run_time=datetime.utcnow())
        scheduler.start()
        print("[INFO] APScheduler działa (maile co godzinę).")
    else:
        try: run_email_reminder_job()
        except Exception as e: print("[WARN] job na starcie:", e)
    app.run(debug=True, host="127.0.0.1", port=5000)
