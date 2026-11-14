"""
MorphPot: An Adaptive Honeypot System
====================================
Main Flask application integrating adaptive threat scoring, dynamic tarpitting,
honeytoken traps, deceptive corporate personas, and live SOC administration.
"""

import os
import csv
import json
import time
import datetime
import threading
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, send_from_directory, abort, Response

from engine.adaptive import AdaptiveEngine
from engine.canary import CanaryManager
from engine.ml_detector import MLThreatDetector

# --- CONFIG & PATHS ---
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))

# Vercel serverless functions have a read-only filesystem except for /tmp
if os.environ.get("VERCEL"):
    DATA_DIR = "/tmp/data"
    os.makedirs(DATA_DIR, exist_ok=True)
    # Seed files from read-only package into /tmp/data on first invocation
    src_data = os.path.join(BASE, "data")
    if os.path.exists(src_data):
        for fname in os.listdir(src_data):
            src_f = os.path.join(src_data, fname)
            dst_f = os.path.join(DATA_DIR, fname)
            if not os.path.exists(dst_f) and os.path.isfile(src_f):
                try:
                    shutil.copy2(src_f, dst_f)
                except Exception:
                    pass
else:
    DATA_DIR = os.path.join(BASE, "data")
    os.makedirs(DATA_DIR, exist_ok=True)

CFG_PATH = os.path.join(BASE, "templates", "config.json")
cfg = {}
if os.path.exists(CFG_PATH):
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)

PORT = int(os.environ.get("PORT", cfg.get("PORT", 5000)))
SECRET_KEY = os.environ.get("SECRET_KEY", cfg.get("SECRET_KEY", "smvitm_adaptive_honeypot_secret_2026"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", cfg.get("ADMIN_TOKEN", "secretadmin123"))
DEMO_USERNAME = os.environ.get("DEMO_USERNAME", cfg.get("DEMO_USERNAME", "faculty@smvitm.ac.in"))
DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", cfg.get("DEMO_PASSWORD", "demo123"))
ORG_NAME = os.environ.get("ORGANIZATION", cfg.get("ORGANIZATION", "Shri Madhwa Vadiraja Institute of Technology & Management"))
INSTITUTION_SHORT = os.environ.get("INSTITUTION_SHORT", cfg.get("INSTITUTION_SHORT", "SMVITM, Bantakal"))
CAMPUS_AFFILIATION = os.environ.get("CAMPUS_AFFILIATION", cfg.get("CAMPUS_AFFILIATION", "Affiliated to VTU, Belagavi | Approved by AICTE | Accredited with NAAC 'A' Grade"))

# Email notification credentials
SMTP_HOST = os.environ.get("SMTP_HOST", cfg.get("SMTP_HOST", ""))
SMTP_PORT = int(os.environ.get("SMTP_PORT", cfg.get("SMTP_PORT", 587)))
SMTP_USER = os.environ.get("SMTP_USER", cfg.get("SMTP_USER", ""))
SMTP_PASS = os.environ.get("SMTP_PASS", cfg.get("SMTP_PASS", ""))
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", cfg.get("ADMIN_EMAIL", "cyber-defense@smvitm.ac.in"))
ALERT_FROM = os.environ.get("ALERT_FROM", cfg.get("ALERT_FROM", "honeypot-alert@smvitm.ac.in"))

LOG_FILE = os.path.join(DATA_DIR, "logs.json")
TRAP_FILE = os.path.join(DATA_DIR, "trapped.json")
BLOCK_FILE = os.path.join(DATA_DIR, "blocklist.json")
EMPLOYEE_FILE = os.path.join(DATA_DIR, "employees.csv")

# Ensure files exist
for p, default in [
    (LOG_FILE, []),
    (TRAP_FILE, []),
    (BLOCK_FILE, {"ips": [], "usernames": []})
]:
    if not os.path.exists(p):
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2)
        except Exception:
            pass

# Initialize engines
adaptive_cfg = cfg.get("ADAPTIVE_ENGINE", {})
adaptive_engine = AdaptiveEngine(adaptive_cfg)
canary_mgr = CanaryManager(DATA_DIR)
ml_detector = MLThreatDetector()

# --- FLASK APP ---
# Explicit absolute paths ensure templates and public assets resolve properly on Vercel
app = Flask(
    __name__,
    static_folder=os.path.join(BASE, "public"),
    static_url_path="/static",
    template_folder=os.path.join(BASE, "templates")
)
app.secret_key = SECRET_KEY

# In-memory attempts map: ip -> list of attempts (dicts)
attempts = {}

# --- HELPER FUNCTIONS ---
def read_json(path, fallback):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return fallback

def write_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[Storage Notice] Could not write to {path}: {e}")

def append_log(entry):
    logs = read_json(LOG_FILE, [])
    logs.append(entry)
    write_json(LOG_FILE, logs)

def save_trapped_entry(entry):
    trapped = read_json(TRAP_FILE, [])
    trapped.append(entry)
    write_json(TRAP_FILE, trapped)

def is_ip_blocked(ip):
    blocklist = read_json(BLOCK_FILE, {"ips": [], "usernames": []})
    return ip in blocklist.get("ips", [])

def get_client_ip():
    # Prefer X-Forwarded-For (if proxied), else remote_addr
    if "X-Forwarded-For" in request.headers:
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def check_admin_auth():
    token = request.args.get("token", "")
    if not token and "Authorization" in request.headers:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1].strip()
        else:
            token = auth_header.strip()
    return token == ADMIN_TOKEN

def load_employees():
    employees = []
    if os.path.exists(EMPLOYEE_FILE):
        try:
            with open(EMPLOYEE_FILE, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    employees.append(row)
        except Exception as e:
            print("Error loading employees CSV:", e)
    return employees

def send_alert_email(ip, username, passwords):
    def _send():
        if not (SMTP_HOST and SMTP_USER and SMTP_PASS and ADMIN_EMAIL):
            print("[MorphPot Notification] Email config incomplete — skipping external SMTP mail.")
            print(f"[MorphPot ALERT] Attacker Trapped: IP={ip}, Target User={username}, Passwords={passwords}")
            return
        subj = f"[SMVITM Honeypot ALERT] Attacker Trapped from IP: {ip}"
        body = (
            "SMVITM MorphPot Adaptive Honeypot Detection Alert\n"
            "==================================================\n\n"
            f"Attacker IP: {ip}\n"
            f"Target Account: {username}\n"
            f"Passwords Attempted: {passwords}\n"
            f"Detection Timestamp: {datetime.datetime.utcnow().isoformat()}Z\n\n"
            "Action Taken: Attacker routed to deceptive campus faculty portal.\n"
            "Telemetry: Recorded in data/trapped.json and data/logs.json.\n"
        )
        msg = MIMEText(body)
        msg["Subject"] = subj
        msg["From"] = ALERT_FROM
        msg["To"] = ADMIN_EMAIL
        try:
            s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(ALERT_FROM, [ADMIN_EMAIL], msg.as_string())
            s.quit()
            print(f"[MorphPot] Email alert successfully dispatched to {ADMIN_EMAIL}")
        except Exception as e:
            print("[MorphPot] Email dispatch failed:", e)

    threading.Thread(target=_send, daemon=True).start()

# --- REQUEST HOOKS & ADAPTIVE FILTER ---
@app.before_request
def adaptive_filter():
    # Allow static assets and admin page to bypass blocking
    if request.path.startswith("/public/") or request.path.startswith("/static/"):
        return

    ip = get_client_ip()

    # Blocked check
    if is_ip_blocked(ip) and not request.path.startswith("/admin"):
        return jsonify({
            "error": "Access Denied",
            "message": "Your IP address has been flagged and suspended by corporate firewall policy.",
            "incident_id": f"BL-SEC-{int(time.time())}"
        }), 403

    # Run adaptive inspection
    body_str = ""
    try:
        body_str = request.get_data(as_text=True)
    except Exception:
        pass

    violations = adaptive_engine.inspect_request(
        ip=ip,
        path=request.path,
        method=request.method,
        headers=dict(request.headers),
        body_text=body_str
    )

    # Log significant non-login violations (SQLi, path traversal, scanner probes)
    if violations and not request.path.startswith("/admin") and request.path != "/login":
        profile = adaptive_engine.get_or_create_profile(ip)
        entry = {
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "ip": ip,
            "path": request.path,
            "method": request.method,
            "threat_level": profile["threat_level"],
            "threat_score": profile["threat_score"],
            "attack_type": violations[0]["type"],
            "detail": violations[0]["detail"],
            "user_agent": request.headers.get("User-Agent", "Unknown")
        }
        append_log(entry)

    # Apply adaptive tarpit delay if flagged
    if not request.path.startswith("/admin"):
        adaptive_engine.apply_tarpit(ip)

@app.after_request
def deceptive_response_headers(response):
    headers = adaptive_engine.get_deceptive_headers()
    for k, v in headers.items():
        response.headers[k] = v
    return response

# ---------------------------
# ROUTES (USER REFERENCE + ADAPTIVE)
# ---------------------------

@app.route("/")
def index():
    # Main login page
    return render_template(
        "login.html",
        org_name=ORG_NAME,
        inst_short=INSTITUTION_SHORT,
        affiliation=CAMPUS_AFFILIATION,
        honeypot_name=cfg.get("HONEYPOT_NAME", "SMVITM Adaptive Honeypot")
    )

@app.route("/dashboard")
def dashboard():
    # Deceptive dashboard shown to authenticated user or trapped attacker
    employees = load_employees()
    return render_template(
        "dashboard.html",
        org_name=ORG_NAME,
        inst_short=INSTITUTION_SHORT,
        affiliation=CAMPUS_AFFILIATION,
        employee_count=len(employees)
    )

@app.route("/employees")
def employees():
    # Employee directory honeypot page
    emp_list = load_employees()
    return render_template("employees.html", employees=emp_list)

@app.route("/payments")
def payments():
    # Fake payment transactions ledger
    return render_template("payments.html")

@app.route("/files")
def files_view():
    # Decoy file repository with honeytokens
    canaries = canary_mgr.get_all()
    return render_template("files.html", canaries=canaries)

@app.route("/files/download/<path:filename>")
def files_download(filename):
    # Attacker attempting to exfiltrate decoy honeytoken files
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "Unknown")

    hit = canary_mgr.record_hit(filename, ip, ua)
    profile = adaptive_engine.get_or_create_profile(ip)
    profile["threat_score"] = min(100, profile["threat_score"] + 30)
    adaptive_engine._update_threat_level(profile)

    # Log canary hit as critical honeypot tripwire event
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    entry = {
        "ts": ts,
        "ip": ip,
        "username": "N/A (Exfiltration Probe)",
        "threat_level": "CRITICAL",
        "threat_score": profile["threat_score"],
        "attack_type": "HONEYTOKEN_CANARY_TRIPPED",
        "detail": f"Decoy file '{filename}' was exfiltrated by client.",
        "user_agent": ua
    }
    append_log(entry)

    # Return realistic decoy content
    content = canary_mgr.generate_decoy_content(filename)
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route("/terminal")
def terminal_page():
    # Interactive decoy shell for trapped attacker
    return render_template("terminal.html")

@app.route("/api/terminal/exec", methods=["POST"])
def terminal_exec():
    # Simulated restricted shell command processor
    data = request.get_json() or {}
    cmd = data.get("command", "")
    ip = get_client_ip()

    output = adaptive_engine.simulate_shell_command(cmd, ip)
    profile = adaptive_engine.get_or_create_profile(ip)

    # Log command execution
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    entry = {
        "ts": ts,
        "ip": ip,
        "username": "terminal_session",
        "threat_level": profile["threat_level"],
        "threat_score": profile["threat_score"],
        "attack_type": "HONEYPOT_SHELL_COMMAND",
        "detail": f"Command executed in trap shell: {cmd}",
        "user_agent": request.headers.get("User-Agent", "Unknown")
    }
    append_log(entry)

    return jsonify({"command": cmd, "output": output})

@app.route("/admin.html")
def admin_page():
    # Admin SOC console view
    return render_template(
        "admin.html",
        admin_token=ADMIN_TOKEN,
        demo_user=DEMO_USERNAME,
        demo_pass=DEMO_PASSWORD
    )

# --- LOGIN ENDPOINT (ADAPTIVE BRUTE FORCE TRAP & PUBLIC ACCESS) ---
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or request.form or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    mode = (data.get("mode") or "").strip().lower()
    sim_trap = data.get("sim_trap", False)
    ip = get_client_ip()
    ua = request.headers.get("User-Agent", "Unknown")
    ts = datetime.datetime.utcnow().isoformat() + "Z"

    # 1. Instant Honeypot Trap Simulation (for demo / evaluators)
    if sim_trap:
        target_name = username or "4MW21CS001"
        pws = ["vtu@2025", "smvitm123", "password2026"]
        profile = adaptive_engine.get_or_create_profile(ip)
        profile["is_trapped"] = True
        profile["threat_score"] = 95
        profile["threat_level"] = "CRITICAL"
        entry = {
            "ip": ip,
            "username": target_name,
            "passwords": pws,
            "time": ts,
            "threat_score": 95,
            "action": "Redirected to Deceptive Honeypot Dashboard (Trap Simulated)"
        }
        save_trapped_entry(entry)
        send_alert_email(ip, target_name, pws)
        log_entry = {
            "ts": ts,
            "ip": ip,
            "username": target_name,
            "password": pws[-1],
            "threat_level": "CRITICAL",
            "threat_score": 95,
            "attack_type": "SIMULATED_BRUTE_FORCE_TRAP",
            "user_agent": ua
        }
        append_log(log_entry)
        return jsonify({
            "ok": True,
            "trap": True,
            "message": "Intruder trap triggered! Diverting to deceptive sandbox..."
        })

    # 2. Authorized Faculty Credentials Check
    if username.lower() in [DEMO_USERNAME.lower(), "faculty", "faculty@smvitm.ac.in"] and password in [DEMO_PASSWORD, "demo123"]:
        attempts.pop(ip, None)
        return jsonify({"ok": True, "authenticated": True, "role": "Faculty", "user": username})

    # 3. Public / Student / Guest Demo Access Check
    # Anyone can log in with password 'student123' or 'demo123', or by clicking Guest Access
    is_guest_mode = (
        data.get("guest") is True
        or data.get("public_access") is True
        or mode == "guest"
        or username.lower() in ["student", "guest", "student@smvitm.ac.in", "public", "demo"]
        or password in ["student123", "demo123", "smvitm123", "guest123", "public123"]
    )
    if is_guest_mode:
        attempts.pop(ip, None)
        display_user = username if username else "SMVITM Student"
        return jsonify({
            "ok": True,
            "authenticated": True,
            "role": "Student",
            "user": display_user,
            "message": f"Welcome, {display_user}!"
        })

    # 4. Evaluate Login Attempt with Adaptive Engine (Brute-force / Trapping)
    is_trapped_now, action = adaptive_engine.record_login_attempt(ip, username, password, is_success=False)
    profile = adaptive_engine.get_or_create_profile(ip)

    # Log attempt to file (always)
    log_entry = {
        "ts": ts,
        "ip": ip,
        "username": username,
        "password": password,
        "threat_level": profile["threat_level"],
        "threat_score": profile["threat_score"],
        "attack_type": "BRUTE_FORCE_PROBE" if is_trapped_now else "FAILED_LOGIN",
        "user_agent": ua
    }
    append_log(log_entry)

    # Store in memory
    attempts.setdefault(ip, []).append({"ts": ts, "username": username, "password": password})
    if len(attempts[ip]) > 20:
        attempts[ip] = attempts[ip][-20:]

    # DETECTION: Last 3 attempts, same username but 3 different passwords
    if len(attempts[ip]) >= 3:
        last3 = attempts[ip][-3:]
        unames = [a["username"] for a in last3]
        pws = [a["password"] for a in last3]

        if len(set(unames)) == 1 and len(set(pws)) >= 3:
            # TRAP! Save and alert
            # Run ML classification on the credential payload
            ml_payload = f"POST /login username={unames[0]} passwords={','.join(pws)}"
            ml_label, ml_malicious = ml_detector.predict(ml_payload)

            entry = {
                "ip": ip,
                "username": unames[0],
                "passwords": pws,
                "time": ts,
                "threat_score": 95,
                "ml_label": ml_label if ml_malicious else "Brute_Force",
                "action": "Redirected to Deceptive Honeypot Dashboard"
            }
            save_trapped_entry(entry)
            send_alert_email(ip, unames[0], pws)

            # Return trap response (frontend will redirect to /dashboard)
            return jsonify({
                "ok": True,
                "trap": True,
                "message": "Authentication successful (Session Decoy Initialized)"
            })

    # Default: Invalid credentials with helpful hint for public users
    return jsonify({
        "ok": False,
        "message": "Invalid password for this account. (Tip: Anyone can sign in with password 'student123' or click 'Instant Student / Guest Access' below!)"
    })

# --- ADMIN API ENDPOINTS (AUTHENTICATED) ---

@app.route("/admin/logs")
def admin_logs():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403
    logs = read_json(LOG_FILE, [])
    return jsonify(logs)

@app.route("/admin/trapped")
def admin_trapped():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403
    trapped = read_json(TRAP_FILE, [])
    return jsonify(trapped)

@app.route("/admin/stats")
def admin_stats():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403

    logs = read_json(LOG_FILE, [])
    trapped = read_json(TRAP_FILE, [])
    blocklist = read_json(BLOCK_FILE, {"ips": [], "usernames": []})
    canaries = canary_mgr.get_all()

    unique_ips = set(l.get("ip") for l in logs if "ip" in l)
    high_threat_count = sum(1 for l in logs if l.get("threat_level") in ["HIGH", "CRITICAL"])
    canary_hits = sum(c.get("downloads", 0) for c in canaries)

    return jsonify({
        "total_attacks": len(logs),
        "trapped_sessions": len(trapped),
        "unique_attacker_ips": len(unique_ips),
        "blocked_ips_count": len(blocklist.get("ips", [])),
        "high_threat_attacks": high_threat_count,
        "canary_downloads": canary_hits,
        "current_persona": adaptive_engine.current_persona,
        "tarpit_active": adaptive_cfg.get("TARPIT_ENABLED", True)
    })

@app.route("/admin/blocklist", methods=["GET", "POST", "DELETE"])
def admin_blocklist():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403

    blocklist = read_json(BLOCK_FILE, {"ips": [], "usernames": []})

    if request.method == "GET":
        return jsonify(blocklist)

    data = request.get_json() or {}
    ip = (data.get("ip") or "").strip()

    if not ip:
        return jsonify({"ok": False, "message": "IP address is required"}), 400

    if request.method == "POST":
        if ip not in blocklist["ips"]:
            blocklist["ips"].append(ip)
            write_json(BLOCK_FILE, blocklist)
        return jsonify({"ok": True, "message": f"IP {ip} added to firewall blocklist", "blocklist": blocklist})

    elif request.method == "DELETE":
        if ip in blocklist["ips"]:
            blocklist["ips"].remove(ip)
            write_json(BLOCK_FILE, blocklist)
        return jsonify({"ok": True, "message": f"IP {ip} removed from blocklist", "blocklist": blocklist})

@app.route("/admin/canaries")
def admin_canaries():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403
    return jsonify(canary_mgr.get_all())

@app.route("/admin/adaptive-config", methods=["GET", "POST"])
def admin_adaptive_config():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403

    if request.method == "POST":
        data = request.get_json() or {}
        if "tarpit_enabled" in data:
            adaptive_engine.config["TARPIT_ENABLED"] = bool(data["tarpit_enabled"])
        if "max_delay" in data:
            adaptive_engine.config["MAX_TARPIT_DELAY_SEC"] = float(data["max_delay"])
        if "persona" in data and data["persona"] in adaptive_engine.personas:
            adaptive_engine.current_persona = data["persona"]
        return jsonify({
            "ok": True,
            "message": "Adaptive engine parameters updated",
            "current_config": adaptive_engine.config,
            "current_persona": adaptive_engine.current_persona
        })

    return jsonify({
        "config": adaptive_engine.config,
        "persona": adaptive_engine.current_persona,
        "available_personas": adaptive_engine.personas
    })

@app.route("/admin/clear", methods=["POST"])
def admin_clear():
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403
    write_json(LOG_FILE, [])
    write_json(TRAP_FILE, [])
    attempts.clear()
    return jsonify({"ok": True, "message": "Telemetry logs and trapped sessions reset successfully."})

@app.route("/admin/simulate", methods=["POST"])
def admin_simulate():
    """
    Simulation tool invoked from the admin dashboard to demo honeypot reactions.
    """
    if not check_admin_auth():
        return jsonify({"message": "Forbidden - wrong token"}), 403

    data = request.get_json() or {}
    sim_type = data.get("type", "brute_force")
    sim_ip = data.get("ip", "192.168.1.188")
    target_user = data.get("username", "admin@company.com")

    ts = datetime.datetime.utcnow().isoformat() + "Z"

    if sim_type == "brute_force":
        pws = ["Password123", "Spring2025!", "Admin@2025!"]
        for p in pws:
            log_entry = {
                "ts": datetime.datetime.utcnow().isoformat() + "Z",
                "ip": sim_ip,
                "username": target_user,
                "password": p,
                "threat_level": "CRITICAL",
                "threat_score": 95,
                "attack_type": "SIMULATED_BRUTE_FORCE_TRAP",
                "user_agent": "Hydra/9.5 (Kali Linux)"
            }
            append_log(log_entry)

        entry = {
            "ip": sim_ip,
            "username": target_user,
            "passwords": pws,
            "time": ts,
            "threat_score": 95,
            "ml_label": "Brute_Force",
            "action": "Sandboxed in Deceptive Honeypot Dashboard"
        }
        save_trapped_entry(entry)
        return jsonify({"ok": True, "message": f"Simulated 3-step credential stuffing trap triggered from {sim_ip}"})

    elif sim_type == "sqli":
        payload = "' UNION SELECT null, username, password_hash FROM enterprise_users--"
        entry = {
            "ts": ts,
            "ip": sim_ip,
            "username": payload,
            "password": "N/A",
            "threat_level": "HIGH",
            "threat_score": 75,
            "attack_type": "SQL_INJECTION",
            "detail": f"Simulated SQLi pattern in authentication vector: {payload}",
            "user_agent": "sqlmap/1.7#stable"
        }
        append_log(entry)
        return jsonify({"ok": True, "message": f"Simulated SQL injection attack recorded from {sim_ip}"})

    elif sim_type == "traversal":
        entry = {
            "ts": ts,
            "ip": sim_ip,
            "username": "N/A",
            "threat_level": "HIGH",
            "threat_score": 70,
            "attack_type": "PATH_TRAVERSAL",
            "detail": "Simulated directory traversal targeting /etc/shadow and .env secrets",
            "user_agent": "Nikto/2.1.6"
        }
        append_log(entry)
        return jsonify({"ok": True, "message": f"Simulated traversal probe recorded from {sim_ip}"})

    return jsonify({"ok": False, "message": "Unknown simulation type"}), 400

# Catch-all scanner trap (404s on sensitive paths)
@app.errorhandler(404)
def page_not_found(e):
    ip = get_client_ip()
    path = request.path
    if not path.startswith("/public/") and not path.startswith("/static/"):
        profile = adaptive_engine.get_or_create_profile(ip)
        profile["threat_score"] = min(100, profile["threat_score"] + 15)
        adaptive_engine._update_threat_level(profile)

        ts = datetime.datetime.utcnow().isoformat() + "Z"
        entry = {
            "ts": ts,
            "ip": ip,
            "path": path,
            "threat_level": profile["threat_level"],
            "threat_score": profile["threat_score"],
            "attack_type": "RECON_SCANNER_PROBE",
            "detail": f"Probing non-existent sensitive path {path}",
            "user_agent": request.headers.get("User-Agent", "Unknown")
        }
        append_log(entry)

    return render_template(
        "login.html",
        error="Resource not found or unauthorized.",
        org_name=cfg.get("ORGANIZATION", "Acme Global Systems Ltd.")
    ), 404

# Static files route
@app.route("/public/<path:fn>")
def public_files(fn):
    return send_from_directory("public", fn)

if __name__ == "__main__":
    print("=" * 60)
    print("  MorphPot - Adaptive Honeypot System Starting...")
    print(f"  Listening on: http://0.0.0.0:{PORT}")
    print(f"  Admin SOC Console: http://127.0.0.1:{PORT}/admin.html")
    print(f"  Admin Access Token: {ADMIN_TOKEN}")
    print(f"  Demo Employee Login: {DEMO_USERNAME} / {DEMO_PASSWORD}")
    print("=" * 60)
    app.run(host="0.0.0.0", port=PORT, debug=False)
