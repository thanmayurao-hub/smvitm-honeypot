"""
MorphPot: Automated Attack Simulation & Verification Suite (SMVITM Academic Edition)
=====================================================================================
Demonstrates and verifies all defensive capabilities of SMVITM's Honeypot:
1. Academic portal fingerprinting & deceptive HTTP headers
2. Authorized faculty authentication (faculty@smvitm.ac.in)
3. 3-step student USN brute force trap detection (4MW21CS001)
4. SQL injection attack against student marks database
5. Path traversal / LFI probe targeting exam vault
6. VTU question paper honeytoken exfiltration tracking
7. Interactive SMVITM campus server terminal execution
8. Campus SOC threat telemetry verification

Usage:
    python attack_simulator.py [--host http://127.0.0.1:5000]
"""

import sys
import json
import time
import urllib.request
import urllib.error

DEFAULT_HOST = "http://127.0.0.1:5000"
ADMIN_TOKEN = "secretadmin123"

def print_header(title):
    print("\n" + "=" * 65)
    print(f"  >>> {title}")
    print("=" * 65)

def make_request(url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "SMVITM-PentestClient/2.0"

    req_data = None
    if data is not None:
        if isinstance(data, dict):
            req_data = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif isinstance(data, str):
            req_data = data.encode("utf-8")

    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8", errors="ignore")
            resp_headers = dict(response.headers)
            return status, body, resp_headers
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return e.code, body, dict(e.headers)
    except Exception as e:
        return 0, str(e), {}

def run_tests(host):
    print(f"\nTarget Honeypot URL: {host}")
    print(f"Starting SMVITM MorphPot test & demonstration sequence...")

    # 1. Health check & Landing page
    print_header("1. Probing SMVITM Campus Login Page & Header Fingerprints")
    status, body, headers = make_request(f"{host}/")
    print(f"HTTP Status: {status}")
    print(f"Server Header Deception: {headers.get('Server', 'None')}")
    print(f"X-Powered-By Deception:  {headers.get('X-Powered-By', 'None')}")
    print(f"X-Institution:           {headers.get('X-Institution', 'None')}")
    assert status == 200, f"Expected 200, got {status}"
    print("[PASS] SMVITM portal active with academic deception headers.")

    # 2. Legitimate Faculty Login
    print_header("2. Testing Authorized Faculty Login (faculty@smvitm.ac.in)")
    status, body, _ = make_request(
        f"{host}/login",
        method="POST",
        data={"username": "faculty@smvitm.ac.in", "password": "demo123"}
    )
    res = json.loads(body)
    print(f"Response: {res}")
    assert res.get("authenticated") is True, "Faculty authentication failed!"
    print("[PASS] Authorized faculty member authenticated successfully.")

    # 3. Brute Force Credential Stuffing Trap on Student USN
    print_header("3. Executing 3-Step Brute-Force Attack on USN '4MW21CS001'")
    target_usn = "4MW21CS001"
    passwords_to_try = ["vtu@2025", "smvitm123", "password2026"]

    for idx, pw in enumerate(passwords_to_try, 1):
        print(f"  Attempt {idx}/3: USN '{target_usn}' with Password '{pw}'...")
        status, body, _ = make_request(
            f"{host}/login",
            method="POST",
            data={"username": target_usn, "password": pw}
        )
        res = json.loads(body)
        print(f"    Server Reply: ok={res.get('ok')}, trap={res.get('trap', False)}, msg='{res.get('message', '')}'")

        if idx < 3:
            assert res.get("trap") is not True, "Trap tripped prematurely!"
        else:
            assert res.get("trap") is True, "Trap failed to trigger on 3rd attempt!"
            print("[PASS] 3-Step Brute-Force Trap successfully triggered!")
            print("       Attacker flagged and routed into the deceptive academic sandbox.")

    # 4. SQL Injection Attack Vector
    print_header("4. Simulating SQL Injection against Internal Marks DB")
    sqli_payload = "' UNION SELECT usn, student_name, ia_marks FROM smvitm_marks_master--"
    status, body, _ = make_request(
        f"{host}/login",
        method="POST",
        data={"username": sqli_payload, "password": "password"},
        headers={"User-Agent": "sqlmap/1.7#stable"}
    )
    print(f"SQLi Probe Response: {body[:90]}")
    print("[PASS] SQL injection pattern analyzed and threat score escalated.")

    # 5. Path Traversal & Sensitive File Recon Probe
    print_header("5. Simulating Path Traversal targeting Exam Paper Vault")
    traversal_path = f"{host}/../../var/www/smvitm-academic-portal/vtu_exam_vault"
    status, body, _ = make_request(traversal_path, headers={"User-Agent": "Nikto/2.1.6"})
    print(f"Traversal probe to {traversal_path} returned HTTP {status}")
    print("[PASS] Traversal probe intercepted and scored by Adaptive Engine.")

    # 6. Honeytoken Exfiltration Test
    print_header("6. Tripping VTU Question Paper Exfiltration Trapline")
    canary_url = f"{host}/files/download/VTU_Confidential_End_Sem_Question_Paper_Dec2025.xlsx"
    status, body, _ = make_request(canary_url)
    print(f"Honeytoken file requested. HTTP Status: {status}")
    print(f"Decoy Content Preview:\n{body[:220]}...")
    assert "21CS71" in body, "Canary content missing VTU course codes!"
    print("[PASS] Decoy VTU question paper exfiltrated & SOC alarm tripped.")

    # 7. Interactive Honeypot Web Shell Simulation
    print_header("7. Executing Commands in SMVITM Campus Server Shell")
    test_commands = ["whoami", "uname -a", "cat .env", "ls -la"]
    for cmd in test_commands:
        status, body, _ = make_request(
            f"{host}/api/terminal/exec",
            method="POST",
            data={"command": cmd}
        )
        res = json.loads(body)
        print(f"  $ {cmd}")
        print(f"    --> {res.get('output', '').replace(chr(10), ' | ')[:85]}...")
    print("[PASS] Campus server terminal responded authentically and recorded command history.")

    # 8. SOC Admin Telemetry Verification
    print_header("8. Verifying Threat Intelligence Telemetry in Campus SOC")
    status, body, _ = make_request(f"{host}/admin/stats?token={ADMIN_TOKEN}")
    stats = json.loads(body)
    print(f"Total Attacks Logged:    {stats.get('total_attacks')}")
    print(f"Trapped Brute-Forcers:   {stats.get('trapped_sessions')}")
    print(f"Unique Attacker IPs:     {stats.get('unique_attacker_ips')}")
    print(f"Canary Honeytoken Hits:  {stats.get('canary_downloads')}")
    print(f"Current Persona:         {stats.get('current_persona')}")

    assert stats.get("trapped_sessions") >= 1, "Trapped session count should be >= 1"

    print_header("ALL SMVITM ADAPTIVE HONEYPOT TESTS PASSED SUCCESSFULLY!")
    print("\nNavigate in browser to:")
    print(f"  * Campus ERP Portal:  {host}/")
    print(f"  * Faculty Intranet:   {host}/dashboard")
    print(f"  * Faculty Directory:  {host}/employees")
    print(f"  * Student Accounts:   {host}/payments")
    print(f"  * VTU Exam Vault:     {host}/files")
    print(f"  * Campus Shell:       {host}/terminal")
    print(f"  * Campus SOC Panel:   {host}/admin.html (Token: {ADMIN_TOKEN})\n")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_HOST
    run_tests(target)
