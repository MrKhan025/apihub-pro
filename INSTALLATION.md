# Step-by-Step Installation & Execution Guide by Operating System

This guide provides complete, copy-pasteable instructions for running **APIHub-Pro (`apihub-pro`) v3.0** across **Windows**, **Linux**, **macOS**, **Android Termux**, **Docker Compose**, and **Kubernetes / Helm**.

---

## 1. Windows 10 / Windows 11 (PowerShell & CMD)

### Prerequisites
- Install [Python 3.11+](https://www.python.org/downloads/windows/) (check **"Add python.exe to PATH"** during installation).
- Install [Git for Windows](https://git-scm.com/download/win).

### Step-by-Step Execution (PowerShell)
```powershell
# 1. Clone the repository
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro

# 2. Create and activate a Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# 4. Create local environment file
Copy-Item .env.example .env

# 5. Run database migrations and seed demo data
$env:PYTHONPATH="."
python main.py migrate
python main.py seed-demo

# 6. Run the automated test suite and security audit
python -m unittest discover -s tests -v
python main.py security-audit

# 7. Launch the APIHub-Pro server
python main.py serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000/dashboard`** in your browser.

---

## 2. Linux (Ubuntu / Debian / Kali / Fedora / Arch)

### Step-by-Step Execution
```bash
# 1. Install system packages (Ubuntu/Debian example)
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git sqlite3

# 2. Clone the repository
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro

# 3. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# 5. Initialize environment, database migrations, and demo workspace
cp .env.example .env
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo

# 6. Run automated tests and security audit
PYTHONPATH=. python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 main.py security-audit

# 7. Start the gateway server
PYTHONPATH=. python3 main.py serve --host 0.0.0.0 --port 8000
```

---

## 3. macOS (Intel & Apple Silicon M1/M2/M3/M4)

### Step-by-Step Execution
```bash
# 1. Install Python 3.11+ via Homebrew (if not already installed)
brew install python@3.11 git

# 2. Clone the repository
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro

# 3. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
pip install --upgrade pip
pip install -r requirements-dev.txt

# 5. Run migrations, seed workspace, and verify tests
cp .env.example .env
PYTHONPATH=. python3 main.py migrate
PYTHONPATH=. python3 main.py seed-demo
PYTHONPATH=. python3 -m unittest discover -s tests -v

# 6. Start the gateway server
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

---

## 4. Android Termux (Mobile / ARM64)

APIHub-Pro is specially engineered to run on **Android Termux** without requiring heavy Rust/C compiler toolchains:

```bash
# 1. Update Termux packages and install Python & Git
pkg update -y && pkg upgrade -y
pkg install -y python git sqlite redis

# 2. Clone the repository
git clone https://github.com/MrKhan025/apihub-pro.git
cd apihub-pro

# 3. Run the automated Termux setup script
bash scripts/termux-setup.sh

# 4. Start the server and open http://127.0.0.1:8000/dashboard in Chrome on Android
source .venv/bin/activate
PYTHONPATH=. python3 main.py serve --host 127.0.0.1 --port 8000
```

---

## 5. Docker & Docker Compose (Production PostgreSQL 16 + Redis 7)

```bash
# 1. Copy environment file and set strong secrets
cp .env.example .env

# 2. Build and launch PostgreSQL 16, Redis 7, and APIHub-Pro Gateway
docker compose --profile production up -d --build

# 3. Check container health
curl http://localhost:8000/health
```

---

## 6. Kubernetes & Helm v3 (Cloud-Native Production)

```bash
# Option A: Deploy raw Kubernetes manifests (Namespace, ConfigMap, Deployment, Service, HPA, Ingress, PDB)
kubectl apply -f deploy/k8s/

# Option B: Deploy via Helm v3 Chart
helm upgrade --install apihub-pro ./deploy/helm/apihub-pro \
  --namespace apihub-pro \
  --create-namespace
```
