"""
MorphPot: Adaptive Engine (SMVITM Academic & Enterprise Edition)
----------------------------------------------------------------
Handles threat scoring, attacker profiling, behavioral fingerprinting,
dynamic tarpit latency throttling, and deceptive persona morphing.
"""

import time
import re
import datetime
from urllib.parse import unquote

# Signatures for common automated reconnaissance & exploitation
SQLI_PATTERNS = [
    r"(\b(SELECT|UNION|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|TRUNCATE)\b)",
    r"(--|#|/\*|\*/)",
    r"('|\")\s*(OR|AND)\s*('|\")?\d+('|\")?\s*=\s*('|\")?\d+",
    r"('|\")\s*(OR|AND)\s*1\s*=\s*1",
    r"\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\s+DELAY\b",
    r"INFORMATION_SCHEMA|PG_SLEEP"
]

TRAVERSAL_PATTERNS = [
    r"\.\./|\.\.\\",
    r"/etc/passwd|/etc/shadow|/etc/hosts",
    r"win\.ini|boot\.ini|system32",
    r"\.env|\.git/|\.aws/|id_rsa|wp-config\.php",
    r"/proc/self/|/dev/null"
]

XSS_PATTERNS = [
    r"<script\b[^>]*>",
    r"javascript:",
    r"onerror\s*=|onload\s*=|onclick\s*=",
    r"alert\s*\(|prompt\s*\(|confirm\s*\("
]

SCANNER_USER_AGENTS = [
    "sqlmap", "nikto", "hydra", "dirbuster", "gobuster",
    "nmap", "masscan", "zgrab", "wpscan", "metasploit",
    "burpcollaborator", "curl", "python-requests", "postman"
]

SUSPICIOUS_PATHS = [
    "wp-login.php", "wp-admin", ".env", ".git", "phpmyadmin",
    "actuator", "swagger", "console", "server-status", "debug",
    "shell", "cmd", "config.json", "database.sql", "id_rsa",
    "exam", "marks", "vtu", "results"
]

class AdaptiveEngine:
    def __init__(self, config=None):
        self.config = config or {}
        self.profiles = {}  # ip -> profile dict
        self.personas = ["smvitm_academic", "enterprise_corp", "fintech_bank", "cloud_portal"]
        self.current_persona = self.config.get("DEFAULT_PERSONA", "smvitm_academic")

    def get_or_create_profile(self, ip):
        if ip not in self.profiles:
            self.profiles[ip] = {
                "ip": ip,
                "first_seen": datetime.datetime.utcnow().isoformat() + "Z",
                "last_seen": datetime.datetime.utcnow().isoformat() + "Z",
                "request_count": 0,
                "threat_score": 10,
                "threat_level": "LOW",
                "violations": [],
                "user_agents": set(),
                "credentials_tried": [],
                "is_trapped": False,
                "persona_presented": self.current_persona
            }
        return self.profiles[ip]

    def inspect_request(self, ip, path, method, headers, body_text=""):
        """
        Inspect incoming request for threat indicators and return detection metadata.
        """
        profile = self.get_or_create_profile(ip)
        profile["request_count"] += 1
        profile["last_seen"] = datetime.datetime.utcnow().isoformat() + "Z"

        ua = headers.get("User-Agent", "").lower()
        if ua:
            profile["user_agents"].add(headers.get("User-Agent"))

        violations_found = []
        raw_target = unquote(f"{path} {body_text}")

        # 1. SQL Injection check
        for pattern in SQLI_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                violations_found.append({"type": "SQL_INJECTION", "detail": f"Matched pattern: {pattern[:25]}..."})
                break

        # 2. Path Traversal & Sensitive File probe
        for pattern in TRAVERSAL_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                violations_found.append({"type": "PATH_TRAVERSAL", "detail": f"Probing sensitive path: {path}"})
                break

        # 3. XSS check
        for pattern in XSS_PATTERNS:
            if re.search(pattern, raw_target, re.IGNORECASE):
                violations_found.append({"type": "XSS_PROBE", "detail": "Script injection attempt"})
                break

        # 4. Scanner User Agent
        for scanner in SCANNER_USER_AGENTS:
            if scanner in ua:
                violations_found.append({"type": "AUTOMATED_SCANNER", "detail": f"Scanner agent detected ({scanner})"})
                break

        # 5. Suspicious endpoint targeting
        for susp_path in SUSPICIOUS_PATHS:
            if susp_path in path.lower():
                violations_found.append({"type": "SUSPICIOUS_PATH", "detail": f"Targeting sensitive endpoint /{susp_path}"})
                break

        # Score recalculation
        for v in violations_found:
            profile["violations"].append(v)
            if v["type"] == "SQL_INJECTION":
                profile["threat_score"] += 35
            elif v["type"] == "PATH_TRAVERSAL":
                profile["threat_score"] += 30
            elif v["type"] == "AUTOMATED_SCANNER":
                profile["threat_score"] += 20
            elif v["type"] == "SUSPICIOUS_PATH":
                profile["threat_score"] += 15
            elif v["type"] == "XSS_PROBE":
                profile["threat_score"] += 20

        # Cap score at 100
        profile["threat_score"] = min(100, profile["threat_score"])
        self._update_threat_level(profile)

        return violations_found

    def record_login_attempt(self, ip, username, password, is_success=False):
        """
        Record and evaluate login attempts for credential stuffing / brute-force patterns.
        """
        profile = self.get_or_create_profile(ip)
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        profile["credentials_tried"].append({"username": username, "password": password, "ts": ts})

        if is_success:
            return False, "AUTHENTICATED"

        # Increase base threat score for repeated failures
        profile["threat_score"] = min(100, profile["threat_score"] + 10)

        # Check for credential stuffing: multiple different passwords against same username
        history = profile["credentials_tried"]
        if len(history) >= 3:
            last3 = history[-3:]
            unames = [a["username"] for a in last3]
            pws = [a["password"] for a in last3]

            if len(set(unames)) == 1 and len(set(pws)) >= 3:
                profile["is_trapped"] = True
                profile["threat_score"] = 95
                profile["threat_level"] = "CRITICAL"
                profile["violations"].append({
                    "type": "BRUTE_FORCE_TRAP",
                    "detail": f"Tripped 3-step credential stuffing trap for target '{unames[0]}'"
                })
                return True, "BRUTE_FORCE_TRAPPED"

        self._update_threat_level(profile)
        return False, "INVALID_CREDENTIALS"

    def _update_threat_level(self, profile):
        score = profile["threat_score"]
        if score >= 85 or profile["is_trapped"]:
            profile["threat_level"] = "CRITICAL"
        elif score >= 60:
            profile["threat_level"] = "HIGH"
        elif score >= 35:
            profile["threat_level"] = "MEDIUM"
        else:
            profile["threat_level"] = "LOW"

    def compute_tarpit_delay(self, ip):
        """
        Calculates dynamic latency delay (in seconds) to throttle aggressive attackers.
        """
        if not self.config.get("TARPIT_ENABLED", True):
            return 0.0

        profile = self.get_or_create_profile(ip)
        max_delay = float(self.config.get("MAX_TARPIT_DELAY_SEC", 3.0))

        level = profile["threat_level"]
        if level == "CRITICAL":
            delay = max_delay
        elif level == "HIGH":
            delay = max_delay * 0.65
        elif level == "MEDIUM":
            delay = max_delay * 0.30
        else:
            delay = 0.0

        return delay

    def apply_tarpit(self, ip):
        """
        Sleeps for the computed tarpit delay to starve attacker threads.
        """
        delay = self.compute_tarpit_delay(ip)
        if delay > 0:
            time.sleep(delay)
        return delay

    def get_deceptive_headers(self, persona=None):
        """
        Returns dynamic HTTP response headers to mislead fingerprinting tools.
        """
        active_persona = persona or self.current_persona
        if active_persona == "smvitm_academic":
            return {
                "Server": "Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2",
                "X-Powered-By": "PHP/8.1.2-SMVITM-ERP",
                "X-Institution": "Shri Madhwa Vadiraja Institute of Technology & Management",
                "X-Academic-Portal": "e-Shikshana v4.8",
                "X-Honeypot-Signature": "Protected by MorphPot Adaptive Defense"
            }
        elif active_persona == "cloud_portal":
            return {
                "Server": "CloudFront / AWS-ALB-v2",
                "X-Powered-By": "Next.js / Node.js 20",
                "X-Frame-Options": "SAMEORIGIN"
            }
        elif active_persona == "fintech_bank":
            return {
                "Server": "Microsoft-IIS/10.0",
                "X-Powered-By": "ASP.NET 4.8",
                "X-AspNet-Version": "4.8.4515",
                "X-Frame-Options": "DENY"
            }
        else:
            return {
                "Server": "Apache/2.4.52 (Ubuntu Enterprise)",
                "X-Powered-By": "PHP/8.1.18",
                "X-Honeypot-Signature": "Protected by MorphShield Adaptive Filter"
            }

    def simulate_shell_command(self, cmd, client_ip):
        """
        Safely simulates bash / terminal commands inside the honeypot decoy.
        Logs attacker exploration while returning realistic responses.
        """
        cmd = (cmd or "").strip()
        parts = cmd.split()
        if not parts:
            return ""

        base_cmd = parts[0].lower()
        args = parts[1:]

        # Log to threat violations
        profile = self.get_or_create_profile(client_ip)
        profile["violations"].append({"type": "HONEYPOT_SHELL_EXEC", "detail": f"Command executed: {cmd}"})
        profile["threat_score"] = min(100, profile["threat_score"] + 10)
        self._update_threat_level(profile)

        if base_cmd in ["whoami"]:
            return "smvitm_sysadmin"
        elif base_cmd in ["id"]:
            return "uid=1001(smvitm_admin) gid=1001(smvitm_admin) groups=1001(smvitm_admin),27(sudo),44(vtu_exam_vault)"
        elif base_cmd in ["pwd"]:
            return "/var/www/smvitm-academic-portal"
        elif base_cmd in ["uname"]:
            if "-a" in args:
                return "Linux smvitm-campus-core01 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux"
            return "Linux"
        elif base_cmd in ["ls", "dir"]:
            if "-la" in args or "-l" in args:
                return (
                    "total 64\n"
                    "drwxr-xr-x  6 smvitm_admin smvitm_admin 4096 Oct 14 09:12 .\n"
                    "drwxr-xr-x 14 root         root         4096 Oct 12 18:30 ..\n"
                    "-rw-r--r--  1 smvitm_admin smvitm_admin 1840 Oct 14 09:11 .env\n"
                    "-rw-r--r--  1 smvitm_admin smvitm_admin 4120 Oct 14 09:10 app.py\n"
                    "-rw-r--r--  1 smvitm_admin smvitm_admin  920 Oct 14 09:10 config.json\n"
                    "-rw-r--r--  1 smvitm_admin exam_vault   8920 Oct 14 09:11 vtu_endsem_qp_draft.xlsx\n"
                    "-rw-------  1 smvitm_admin smvitm_admin 1204 Oct 14 09:12 campus_vpn.key\n"
                    "drwxr-xr-x  2 smvitm_admin smvitm_admin 4096 Oct 14 09:10 student_records\n"
                    "drwxr-xr-x  2 smvitm_admin smvitm_admin 4096 Oct 14 09:10 templates\n"
                    "drwxr-xr-x  2 smvitm_admin smvitm_admin 4096 Oct 14 09:10 data"
                )
            return "app.py  config.json  data  .env  campus_vpn.key  vtu_endsem_qp_draft.xlsx  student_records  templates"
        elif base_cmd in ["cat"]:
            target = args[0] if args else ""
            if "passwd" in target:
                return (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    "smvitm_admin:x:1001:1001:SMVITM Campus SysAdmin,,,:/home/smvitm_admin:/bin/bash\n"
                    "exam_controller:x:1002:1002:VTU Exam Cell Controller:/home/exam_controller:/bin/bash\n"
                    "student_portal:x:1003:1003:Campus ERP Daemon:/var/lib/erp:/bin/false"
                )
            elif ".env" in target or "config" in target:
                return (
                    "PORTAL_ENV=production\n"
                    "COLLEGE_CODE=SMVITM_BANTAKAL\n"
                    "VTU_AFFILIATION_ID=4MW\n"
                    "SECRET_KEY=smvitm_canary_sec_key_4mw2026\n"
                    "DB_HOST=10.10.4.15\n"
                    "DB_NAME=smvitm_student_master\n"
                    "DB_USER=smvitm_db_user\n"
                    "DB_PASS=SMVITM@P@ssw0rd!2026\n"
                    "VTU_PORTAL_API_KEY=VTU_CANARY_API_KEY_991823"
                )
            elif "vpn" in target or "key" in target:
                return (
                    "-----BEGIN PRIVATE KEY-----\n"
                    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC+3n61s8xZ0A4Y\n"
                    "... [SMVITM CAMPUS DECOY VPN KEY - ACCESS LOGGED TO SOC] ...\n"
                    "-----END PRIVATE KEY-----"
                )
            elif "qp" in target or "vtu" in target:
                return "Confidential: 21CS71 Cryptography & Cyber Security (VTU Dec 2025 Draft) - Stored in encrypted honeytoken vault."
            return f"cat: {target}: Permission denied or file encrypted"
        elif base_cmd in ["ps"]:
            return (
                "  PID TTY          TIME CMD\n"
                "    1 ?        00:00:05 systemd\n"
                "  380 ?        00:00:18 postgres\n"
                "  892 ?        00:00:02 apache2\n"
                " 1050 ?        00:00:09 python3 app.py\n"
                " 1120 pts/0    00:00:00 bash\n"
                " 1135 pts/0    00:00:00 ps"
            )
        elif base_cmd in ["help"]:
            return "SMVITM Restricted Shell Console (v4.2). Available commands: ls, cat, pwd, whoami, id, uname, ps, clear, exit"
        elif base_cmd in ["clear"]:
            return "\033[2J\033[H"
        else:
            return f"bash: {base_cmd}: command not found (audit security event logged to campus SOC)"
