# RepoShield — Phase 1: Static Threat Intelligence

Automated open-source repository threat analysis platform.
Phase 1 covers static code inspection, dependency CVE scanning,
MITRE ATT&CK mapping, risk scoring, and structured report generation.

---

## Requirements

- Python 3.10+
- PostgreSQL
- Git (for cloning repos)
- Internet access (for OSV.dev CVE lookups)

---

## Setup (Ubuntu or Kali)

### 1. Install PostgreSQL

```bash
sudo apt update
sudo apt install postgresql postgresql-contrib git -y
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### 2. Create the database

```bash
sudo -u postgres psql
```

Inside the postgres prompt:
```sql
CREATE DATABASE reposhield;
CREATE USER reposhield WITH PASSWORD 'reposhield';
GRANT ALL PRIVILEGES ON DATABASE reposhield TO reposhield;
\q
```

### 3. Install Python dependencies

```bash
cd reposhield_p1/
pip install -r requirements.txt --break-system-packages
```

### 4. Run

```bash
python3 run.py
```

Open your browser at: **http://localhost:5000**

---

## First Login

1. Go to `/register` and create your account
2. The **first user** is automatically made **admin** and is active immediately
3. Every user after that starts as **pending** and must be approved by you in the Admin panel

---

## Pipeline (Phase 1)

```
GitHub URL
    ↓  Clone repo (shallow, max 50 MB)
    ↓  Static scan — all .py files for suspicious patterns
    ↓  Dependency scan — OSV.dev CVE lookup + typosquatting detection
    ↓  TTP mapping — MITRE ATT&CK technique identification
    ↓  Risk scoring — weighted composite score, 4-tier classification
    ↓  Report generation — structured JSON + executive summary
```

## Risk Tiers

| Score  | Tier     |
|--------|----------|
| 0–25   | Low      |
| 26–50  | Medium   |
| 51–75  | High     |
| 76–100 | Critical |

---

## Phase 2 (Coming Next)

- Docker sandbox — run repo in isolated container with strace monitoring
- CAPE dynamic sandbox — submit artifacts for full behavioral analysis
- Hybrid static + dynamic score correlation
