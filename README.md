# MorphPot: SMVITM Adaptive Campus Honeypot System

![Institution](https://img.shields.io/badge/Institution-SMVITM%20Bantakal-amber?style=for-the-badge&logo=shield)
![Affiliation](https://img.shields.io/badge/VTU-Belagavi%204MW-blue?style=for-the-badge)
![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-green?style=for-the-badge&logo=python)
![Defense Mode](https://img.shields.io/badge/Deception-Dynamic%20Tarpit%20%26%20Honeytokens-rose?style=for-the-badge)

---

## 🏛️ Project Overview: SMVITM Campus Edition

**MorphPot (SMVITM Academic Edition)** is an intelligent, adaptive cyber deception and intrusion telemetry system specifically developed for **Shri Madhwa Vadiraja Institute of Technology & Management (SMVITM), Bantakal, Udupi** (Affiliated to VTU Belagavi, Approved by AICTE).

It emulates the official **SMVITM Campus ERP & Academic Management Portal (e-Shikshana)** to detect, profile, throttle, and analyze unauthorized student or external intrusions—such as brute-force attacks on student USNs, examination question paper exfiltration probes, and SQL injection attempts against internal marks databases.

---

## 🛡️ Key Adaptive Features for SMVITM

1. **Academic Portal Deception (e-Shikshana)**:
   - Emulates the campus ERP sign-on portal (`/`) for faculty and students.
   - Deceptive post-trap intranet (`/dashboard`) showcasing academic department KPIs, course allocations, and campus notifications.
2. **Student USN & Faculty Brute-Force Trap**:
   - Detects when an adversary attempts 3 different passwords for any student USN (e.g., `4MW21CS001`) or faculty identity.
   - Automatically traps the session (`threat_score: 95`, `threat_level: CRITICAL`) and diverts them into a sandboxed honeypot view while alerting the Campus SOC.
3. **VTU Examination Honeytokens & Canary Beacons (`/files`)**:
   - High-value academic decoys that students and attackers frequently target:
     - `VTU_Confidential_End_Sem_Question_Paper_Dec2025.xlsx` (Decoy VTU scheme for 5th/7th Sem CSE/AIML/ECE).
     - `SMVITM_Final_Internal_Assessment_Marks_Ledger.xlsx` (Decoy faculty IA marks & attendance percentages).
     - `smvitm_student_erp_backup_dump.sql` (Simulated PostgreSQL student table dump).
     - `smvitm_faculty_campus_vpn.ovpn` (Encrypted campus staff VPN configuration).
   - Any download attempt immediately triggers a critical alarm and records the exfiltrator's IP and fingerprint into persistent telemetry.
4. **Dynamic Tarpitting (Adaptive Sloth Throttling)**:
   - Automatically injects up to 3.0 seconds of latency into responses for hostile scanners and brute-force bots, exhausting attacker thread pools.
5. **Interactive Campus Server Shell (`/terminal`)**:
   - Restricted terminal emulator simulating `smvitm-campus-core01.internal.smvitm.ac.in` (`whoami`, `cat .env`, `ls -la`, `cat /etc/passwd`).
6. **Campus SOC Threat Command Center (`/admin.html`)**:
   - Real-time auto-polling telemetry feed, trapped brute-force sessions, honeytoken exfiltration hits, dynamic firewall IP blocklisting, and a built-in one-click attack simulator.

---

## 📂 Project Directory Structure

```
morphot/
│
├── app.py                      # Core Flask server and route interceptors
├── attack_simulator.py         # Multi-vector automated test suite for SMVITM
├── requirements.txt            # Python dependencies (Flask >= 3.0)
├── README.md                   # Complete documentation and viva defense reference
├── run_honeypot.bat            # Windows 1-click launcher for the honeypot
├── run_attack_simulation.bat   # Windows 1-click launcher for attack tests
│
├── engine/                     # Deception & Adaptive Core
│   ├── __init__.py
│   ├── adaptive.py             # Threat scoring, tarpit delay, regex inspection, shell emulator
│   └── canary.py               # Academic honeytoken generator and exfiltration tracker
│
├── templates/                  # Frontend Web Views (SMVITM Themed)
│   ├── config.json             # Institution parameters, credentials, and adaptive settings
│   ├── login.html              # SMVITM e-Shikshana ERP Portal (Trap trigger)
│   ├── dashboard.html          # Deceptive faculty intranet dashboard
│   ├── employees.html          # SMVITM verified faculty & staff directory (CSE, AIML, ECE, Mech, Civil)
│   ├── payments.html           # Student fee collections & VTU examination remittance ledger
│   ├── files.html              # Examination vault containing decoy honeytokens
│   ├── terminal.html           # Sandboxed campus server shell honeypot
│   └── admin.html              # SMVITM Campus SOC Command Center
│
├── public/                     # Static Assets
│   ├── css/
│   │   └── style.css           # Custom cyber aesthetics, badges, and layout
│   └── js/
│       └── admin.js            # SOC dashboard live polling, blocklist manager, and charts
│
└── data/                       # Persistent Forensic Telemetry
    ├── employees.csv           # Verified SMVITM faculty records (Principal, Deans, HODs, Professors)
    ├── logs.json               # Full forensic log of all probes, SQLi, and scanner attempts
    ├── trapped.json            # Sessions that triggered the brute-force trap
    ├── blocklist.json          # Dynamic firewall blocked IPs
    └── canaries.json           # Honeytoken download records and tracking
```

---

## 🌐 Live Public Shareable Access & Instant Login

The SMVITM Campus Portal is configured to be **publicly accessible from any mobile phone, laptop, or remote network worldwide**.

### Active Public Shareable URL:
🔗 **`https://hospitals-margaret-reliability-therefore.trycloudflare.com`**

### Instant One-Click Login Options (Accessible for Anyone):
1. **🎓 Student / Guest Demo Access**:
   - Anyone can click the **"Student / Guest"** one-click button on the login screen, OR enter any USN / name with password **`student123`**.
   - Immediate access to the student intranet dashboard with zero friction.
2. **👨‍🏫 Authorized Faculty Access**:
   - Click **"Faculty Member"** or log in with **`faculty@smvitm.ac.in`** / **`demo123`**.
3. **🪤 One-Click Intruder Trap Simulation**:
   - Click **"Test Trap Mode"** (or type 3 wrong passwords on any USN) to immediately trigger the Honeypot's 3-step credential stuffing trap and enter the monitored deceptive sandbox!
4. **🛡️ Campus SOC Defender Console**:
   - Direct access at **`/admin.html`** with token **`secretadmin123`**.

---

## 🚀 One-Click Windows Launchers

- **`start_public_portal.bat`**: Starts the Flask server and launches the Cloudflare public tunnel, providing an instant shareable HTTPS link.
- **`run_honeypot.bat`**: Runs the honeypot locally on `http://127.0.0.1:5000` and campus Wi-Fi `http://10.14.133.222:5000`.
- **`run_attack_simulation.bat`**: Runs the automated 8-vector attack verification suite.

---

## 🚀 24/7 Production Deployment on Vercel

MorphPot is fully optimized for **Vercel Serverless Python** (`@vercel/python`) with zero server maintenance and 100% uptime:

### 1. Push / Upload to GitHub
1. Create a new GitHub repository (e.g. `smvitm-honeypot`).
2. Upload all files from this project directory (`morphot`) to your repository:
   - Root files: `app.py`, `requirements.txt`, `vercel.json`, `.vercelignore`, `.env.example`, `api/`, `templates/`, `public/`, `data/`, `engine/`.
   - *Note*: `.gitignore` automatically keeps sensitive local files and large binaries out of git.

### 2. Deploy on Vercel
1. Log in to [vercel.com](https://vercel.com) (sign up free with your GitHub account).
2. Click **"Add New..."** -> **"Project"**.
3. Import your `smvitm-honeypot` repository.
4. Under **Environment Variables**, configure the production credentials (see table below).
5. Click **Deploy**. Vercel will build and assign you a permanent production URL:
   `https://<your-project-name>.vercel.app`

### 3. Production Environment Variables (Vercel Dashboard)

| Variable Name | Production Default / Recommended | Purpose |
| :--- | :--- | :--- |
| `SECRET_KEY` | `smvitm_prod_sec_key_e8f294ab82c94318` | Cryptographic session security token |
| `ADMIN_TOKEN` | `secretadmin123` | Security token to access SOC admin dashboard |
| `DEMO_USERNAME`| `faculty@smvitm.ac.in` | Valid faculty email for clean login demo |
| `DEMO_PASSWORD`| `demo123` | Faculty demo password |
| `ORGANIZATION` | `Shri Madhwa Vadiraja Institute of Technology & Management` | Institution header branding |
| `INSTITUTION_SHORT` | `SMVITM, Bantakal` | Short campus label |
| `CAMPUS_AFFILIATION` | `Affiliated to VTU, Belagavi \| Approved by AICTE` | Official campus accreditations |
| `ADMIN_EMAIL` | `cyber-defense@smvitm.ac.in` | SOC alert notification recipient (optional) |
| `ALERT_FROM` | `honeypot-alert@smvitm.ac.in` | Sender address for alert emails |

---

## 🔑 Default Credentials & Tokens

| Component | Identifier | Key / Password | Role |
| :--- | :--- | :--- | :--- |
| **Campus SOC Panel** | URL Parameter | `?token=secretadmin123` | Security Analyst / Operator |
| **Authorized Faculty** | `faculty@smvitm.ac.in` | `demo123` | Verified SMVITM Professor |
| **Trap Testing USN** | `4MW21CS001` (or any USN) | *Any 3 distinct passwords* | Student Brute-Force Trap |

---

## 🎯 Viva & Evaluation Demonstration Steps

1. **Authorized Faculty Access**:
   - Go to [http://127.0.0.1:5000/](http://127.0.0.1:5000/)
   - Login with `faculty@smvitm.ac.in` and `demo123`.
   - Normal login succeeds with 0 threat score penalty.

2. **Student USN Brute-Force Trap**:
   - Return to login page.
   - Enter USN `4MW21CS001` with password `pass1` -> Click Sign In (Fails).
   - Enter password `pass2` -> Click Sign In (Fails).
   - Enter password `pass3` -> Click Sign In.
   - **MorphPot trips the trap!** Attacker is routed into the deceptive faculty intranet.
   - Switch to the SOC Admin panel (`/admin.html`) -> **Trapped Attackers** tab to view the logged password attempts!

3. **VTU Exam Paper Exfiltration**:
   - In the deceptive portal, click **Exam Papers & IA Marks** (`/files`).
   - Click **Download Decoy Asset** on `VTU_Confidential_End_Sem_Question_Paper_Dec2025.xlsx`.
   - The user gets a realistic fake question paper with cryptographic canary beacons.
   - The SOC immediately registers a `HONEYTOKEN_CANARY_TRIPPED` critical incident.

4. **Campus Server Shell**:
   - Click **Campus Shell** (`/terminal`).
   - Run `whoami`, `uname -a`, `cat .env`, `ls -la`.
   - Observe how the restricted terminal serves authentic outputs and logs all commands to telemetry.

5. **Firewall Blocklist**:
   - In `/admin.html`, go to **Campus Firewall Blocklist**.
   - Add an IP address to block it instantly with HTTP 403 Access Denied.

---

## 🧪 Automated Testing Suite

Run the automated simulation script:
```powershell
python attack_simulator.py
```
This tests all 8 attack vectors in seconds, verifying end-to-end functionality.
