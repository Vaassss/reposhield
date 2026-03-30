# ============================================================
# config.py — RepoShield Configuration
# Edit these values before running.
# ============================================================

import os

# ── Database ─────────────────────────────────────────────────
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://reposhield:reposhield@localhost/reposhield_p1"
)

# ── Flask ────────────────────────────────────────────────────
SECRET_KEY = os.environ.get(
    "REPOSHIELD_SECRET_KEY",
    "change-this-to-something-random-before-running"
)

# ── Repo Intake ──────────────────────────────────────────────
CLONE_BASE_DIR   = "/tmp/reposhield_clones"
MAX_REPO_SIZE_MB = 50

# ── Ollama AI Analysis ───────────────────────────────────────
# Ollama runs locally — no API key, no cost, no internet needed.
OLLAMA_BASE_URL       = "http://localhost:11434"
OLLAMA_MODEL          = "deepseek-coder:6.7b"
MAX_AI_FILES          = 5      # top N risky files sent to AI
MAX_FILE_CHARS_FOR_AI = 6000   # truncate files larger than this

# ── Risk Scoring Thresholds (out of 100) ─────────────────────
TIER_LOW      = 25   # 0–25    = Low
TIER_MEDIUM   = 50   # 26–50   = Medium
TIER_HIGH     = 75   # 51–75   = High
               #        76–100  = Critical

# ── Ollama AI Analysis ───────────────────────────────────────
OLLAMA_URL     = "http://localhost:11434"
OLLAMA_MODEL   = "deepseek-coder:6.7b"
MAX_AI_FILES   = 5
MAX_FILE_CHARS = 6000
