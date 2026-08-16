# Kubernetes Cluster Security Analysis & Monitoring System

A lightweight security dashboard and analysis tool for local Kubernetes clusters (e.g., Minikube). It monitors the cluster for security misconfigurations, weak RBAC rules, and image vulnerabilities, outputting a security score and an exportable report.

---

## 🚀 Features

- **Workload Security Scans:** Detects container risk indicators such as running as root, privileged containers, and `hostNetwork` usage.
- **RBAC Analysis:** Inspects cluster role bindings and permissions to flag overly permissive rules.
- **Vulnerability Scanning:** Leverages [Trivy](https://trivy.dev/) to scan container images for known CVEs.
- **Security Scoring Dashboard:** Modern web UI with a Flask back-end that calculates a global security score and highlights high-priority risks.
- **Report Exporting:** Generates structured Markdown security reports (`security_report.md`).

---

## 🛠️ Getting Started (One-time Setup)

Follow these steps to set up the tool on your system.

### Step 1. Prerequisites
- **Python 3.11+** installed and added to your system `PATH`.
- **kubectl** CLI installed.
- **Docker Desktop** (or equivalent) and **Minikube** installed.
- *(Optional)* [Trivy](https://trivy.dev/) installed for image vulnerability scanning.

### Step 2. Project Setup
Clone this repository and navigate to the project directory:
```bash
cd Kubernetes_Security_Monitor_Code
```

Create a Python virtual environment:
```bash
# Create venv
python3 -m venv .venv

# Activate venv (macOS/Linux)
source .venv/bin/activate

# Activate venv (Windows)
.venv\Scripts\activate
```

Install dependencies:
```bash
pip3 install -r requirements.txt
```

---

## 🧪 Quick Test (Offline Self-Check)

Verify that the local security detection and scoring engine work correctly without requiring a live cluster:

```bash
python3 -m k8s_security_monitor.selfcheck
```

**Expected Output:**
```text
Findings: 3
 - MC-004: hostNetwork enabled
 - MC-002: Privileged container
 - MC-001: Container running as root
Score: 70 (Medium)
Self-check passed.
```

---

## 💻 Running the Live Dashboard

### 1. Set Up Kubernetes Resources
Ensure Minikube is started:
```bash
minikube start
```

Deploy the sample secure and insecure resources to your cluster:
```bash
kubectl apply -f k8s_security_monitor/manifests/secure_baseline.yaml
kubectl apply -f k8s_security_monitor/manifests/insecure_workloads.yaml
```

Check that your pods are running:
```bash
kubectl get pods
```

### 2. Launch the Web Application
Start the Flask development server:
```bash
python3 -m k8s_security_monitor.app
```
Open your browser and navigate to **`http://127.0.0.1:5000`**.

### 3. Log In
Use the default credential credentials:
- **Username:** `admin`
- **Password:** `ChangeMe123!`

---

## 🧹 Cleaning Up

To stop all background services and delete test workloads:

1. Press `Ctrl + C` in the terminal running Flask.
2. Stop the local Minikube cluster:
   ```bash
   minikube stop
   ```
3. Remove the test workloads from your cluster:
   ```bash
   kubectl delete -f k8s_security_monitor/manifests/insecure_workloads.yaml
   kubectl delete -f k8s_security_monitor/manifests/secure_baseline.yaml
   ```

---

## ❓ Troubleshooting

| Issue | Resolution |
| :--- | :--- |
| `python3: command not found` | Install Python 3 or try using the `python` command instead. |
| `ModuleNotFoundError` | Verify you activated the virtual environment and ran `pip3 install -r requirements.txt`. |
| `Kubernetes client unavailable` | Ensure your local cluster is up and running via `minikube start` and is responsive to `kubectl get nodes`. |
| `Login page says Invalid credentials` | Double-check that username is `admin` and password is `ChangeMe123!` (case sensitive, no spaces). |
