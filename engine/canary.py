"""
MorphPot: Honeytoken & Canary Management Engine (SMVITM Academic Edition)
--------------------------------------------------------------------------
Generates enticing academic deception bait (VTU question papers, internal marks,
student database backups) and tracks unauthorized downloads to pinpoint breaches.
"""

import os
import json
import datetime

class CanaryManager:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.canary_file = os.path.join(data_dir, "canaries.json")
        self._ensure_canaries()

    def _ensure_canaries(self):
        if not os.path.exists(self.canary_file):
            default = [
                {
                    "id": "canary_vtu_qp_2025",
                    "filename": "VTU_Confidential_End_Sem_Question_Paper_Dec2025.xlsx",
                    "description": "Confidential VTU scheme & question paper drafts for 5th & 7th Semester",
                    "type": "EXAM_QUESTION_DECOY",
                    "downloads": 0,
                    "last_accessed": None,
                    "tripped_by": []
                },
                {
                    "id": "canary_ia_marks",
                    "filename": "SMVITM_Final_Internal_Assessment_Marks_Ledger.xlsx",
                    "description": "Faculty consolidated IA marks, lab records & attendance percentages",
                    "type": "ACADEMIC_MARKS_DECOY",
                    "downloads": 0,
                    "last_accessed": None,
                    "tripped_by": []
                },
                {
                    "id": "canary_erp_db_backup",
                    "filename": "smvitm_student_erp_backup_dump.sql",
                    "description": "Simulated PostgreSQL dump of student logins, USNs, and fee payment hashes",
                    "type": "DATABASE_DUMP",
                    "downloads": 0,
                    "last_accessed": None,
                    "tripped_by": []
                },
                {
                    "id": "canary_campus_vpn",
                    "filename": "smvitm_faculty_campus_vpn.ovpn",
                    "description": "Encrypted campus staff OpenVPN profile for internal grading servers",
                    "type": "CAMPUS_VPN_PROFILE",
                    "downloads": 0,
                    "last_accessed": None,
                    "tripped_by": []
                }
            ]
            self._save_canaries(default)

    def _load_canaries(self):
        try:
            with open(self.canary_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_canaries(self, data):
        try:
            with open(self.canary_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[Canary Notice] Could not save canaries: {e}")

    def get_all(self):
        return self._load_canaries()

    def record_hit(self, filename, client_ip, user_agent):
        canaries = self._load_canaries()
        hit_record = None
        ts = datetime.datetime.utcnow().isoformat() + "Z"

        for c in canaries:
            if c["filename"].lower() == filename.lower() or c["id"] == filename:
                c["downloads"] += 1
                c["last_accessed"] = ts
                hit_info = {
                    "ip": client_ip,
                    "timestamp": ts,
                    "user_agent": user_agent
                }
                c["tripped_by"].append(hit_info)
                hit_record = c
                break

        if hit_record:
            self._save_canaries(canaries)

        return hit_record

    def generate_decoy_content(self, filename):
        """
        Generates realistic decoy content for SMVITM academic honeytokens.
        """
        fn = filename.lower()
        if "question" in fn or "vtu" in fn:
            return (
                "Course_Code,Subject_Title,Module_No,Question_Text,Max_Marks,Bloom_Taxonomy,Confidential_Reviewer\n"
                "21CS71,Cryptography & Cyber Security,Module 1,Explain RSA asymmetric encryption algorithm with a numerical example (p=7, q=11, e=17).,10,L3 (Apply),Dr. Sowmya J. Bhat\n"
                "21CS71,Cryptography & Cyber Security,Module 2,Compare DES, Triple-DES and AES in terms of block size, key length and security rounds.,10,L2 (Understand),Prof. Manoj T.\n"
                "21AI72,Deep Learning Architecture,Module 1,Derive the backpropagation gradient equations for a multi-layer perceptron with cross-entropy loss.,10,L4 (Analyze),Dr. Surabhi R.\n"
                "21EC73,IoT & Embedded Systems,Module 3,Illustrate the MQTT protocol handshake and QoS delivery levels with sequence diagram.,10,L2 (Understand),Dr. Balachandra Achar\n"
                "# VTU-EXAM-BEACON-ID: SMVITM-EXAM-CANARY-QP-99128 HASH=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            )
        elif "marks" in fn or "ia" in fn:
            return (
                "Student_USN,Student_Name,Dept,Sem,Sub_Code,IA_1_Marks,IA_2_Marks,IA_3_Marks,Final_Avg_IA,Attendance_Pct,Eligibility\n"
                "4MW21CS001,Abhishek Rao,CSE,7,21CS71,28,29,30,29.5,92%,Eligible\n"
                "4MW21CS014,Bhavya Nayak,CSE,7,21CS71,25,27,28,27.0,88%,Eligible\n"
                "4MW21AI005,Darshan Hegde,AIML,7,21AI72,29,30,28,29.0,95%,Eligible\n"
                "4MW21EC022,Karthik Prabhu,ECE,7,21EC73,22,24,26,25.0,86%,Eligible\n"
                "4MW21CS089,Suraj Shenoy,CSE,7,21CS71,18,19,20,19.5,72%,Condonation Required\n"
                "# CONFIDENTIAL FACULTY RECORD - AUDITED BY SMVITM EXAM CELL CONTROLLER\n"
            )
        elif "erp" in fn or "backup" in fn or fn.endswith(".sql"):
            return (
                "-- SMVITM Campus ERP PostgreSQL Database Dump v15.2 (e-Shikshana Portal)\n"
                "-- Generated at: 2026-10-14 02:30:00 IST by pg_dump\n"
                "SET client_encoding = 'UTF8';\n\n"
                "CREATE TABLE public.smvitm_student_master (\n"
                "    usn varchar(10) PRIMARY KEY,\n"
                "    full_name varchar(100) NOT NULL,\n"
                "    email varchar(120) UNIQUE NOT NULL,\n"
                "    password_hash varchar(255) NOT NULL,\n"
                "    department varchar(50) NOT NULL,\n"
                "    semester integer NOT NULL,\n"
                "    fee_clearance_status varchar(20) DEFAULT 'CLEARED'\n"
                ");\n\n"
                "INSERT INTO public.smvitm_student_master VALUES ('4MW21CS001', 'Abhishek Rao', '4mw21cs001@smvitm.ac.in', '$2b$12$K1V5f9qN8H0wM1.CANARYHASH09923847', 'CSE', 7, 'CLEARED');\n"
                "INSERT INTO public.smvitm_student_master VALUES ('4MW21AI005', 'Darshan Hegde', '4mw21ai005@smvitm.ac.in', '$2b$12$L7R3m8pQ9S2vN4.CANARYHASH18823411', 'AIML', 7, 'CLEARED');\n"
                "-- HONEYTOKEN SIGNATURE: SMVITM-CANARY-PGSQL-2026\n"
            )
        elif "vpn" in fn or fn.endswith(".ovpn"):
            return (
                "client\n"
                "dev tun\n"
                "proto udp\n"
                "remote campus-vpn.smvitm.ac.in 1194\n"
                "resolv-retry infinite\n"
                "nobind\n"
                "persist-key\n"
                "persist-tun\n"
                "remote-cert-tls server\n"
                "cipher AES-256-GCM\n"
                "auth SHA512\n"
                "<ca>\n"
                "-----BEGIN CERTIFICATE-----\n"
                "MIIB/zCCAaWgAwIBAgIUCanaryCaCertSMVITM9827491029410294... [SMVITM HONEYTOKEN BEACON] ...\n"
                "-----END CERTIFICATE-----\n"
                "</ca>\n"
            )
        else:
            return f"# SMVITM Academic Decoy Asset: {filename}\nGenerated for campus network integrity monitoring.\n"
