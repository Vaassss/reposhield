"""
scoring_engine/scorer.py
Advanced multi-factor scoring with dynamic + AI influence.

UPGRADED:
- Dominant signal override
- Execution-aware escalation
- Chain-based critical detection
"""

import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from config import TIER_LOW, TIER_MEDIUM, TIER_HIGH
from typing import List, Dict, Tuple

CRITICAL_TECHNIQUES = {"T1055", "T1059"}  # Added execution technique


# -----------------------------
# Static baseline
# -----------------------------
def _static_raw(ttps: List[Dict]) -> float:
    return min(sum(t.get("weight", 10) for t in ttps), 100.0)


# -----------------------------
# Confidence model
# -----------------------------
def _confidence(scanned_files, total_findings, packages_analysed, ai_ran, dynamic_score) -> int:
    score = 0

    if scanned_files > 0:
        score += min(scanned_files * 2, 25)

    if packages_analysed > 0:
        score += min(packages_analysed * 3, 20)

    if total_findings > 0:
        score += 20

    if ai_ran:
        score += 15

    if dynamic_score > 0:
        score += 20

    return min(score, 100)


# -----------------------------
# MAIN SCORING
# -----------------------------
def calculate_score(
    static_ttps:       List[Dict],
    dep_risk_score:    float,
    ai_score:          float,
    ai_ran:            bool,
    scanned_files:     int,
    total_findings:    int,
    packages_analysed: int,
    dynamic_score:     float = 0,
) -> Tuple[int, str, int]:

    # --- Static baseline ---
    static_raw = _static_raw(static_ttps)

    # -----------------------------
    # Base score (keep but reduce influence)
    # -----------------------------
    if ai_ran:
        base_score = (
            (static_raw * 0.25) +
            (ai_score * 0.35) +   # ↑ AI weight increased
            (dep_risk_score * 0.15)
        )
    else:
        base_score = (
            (static_raw * 0.50) +
            (dep_risk_score * 0.30)
        )

    # -----------------------------
    # Dynamic amplification
    # -----------------------------
    dynamic_factor = 1.0

    if dynamic_score >= 70:
        dynamic_factor = 1.6
    elif dynamic_score >= 40:
        dynamic_factor = 1.35
    elif dynamic_score > 0:
        dynamic_factor = 1.2

    final = base_score * dynamic_factor

    # -----------------------------
    # 🔥 DOMINANT SIGNAL OVERRIDE
    # -----------------------------

    found_ids = {t["technique_id"] for t in static_ttps}

    # --- Rule 1: AI malicious override ---
    if ai_ran and ai_score >= 85:
        final = max(final, 75)

    # --- Rule 2: Execution technique present ---
    if "T1059" in found_ids:
        final = max(final, 70)

    # --- Rule 3: Strong combined signal ---
    if ai_ran and ai_score >= 85 and ("T1059" in found_ids):
        final = max(final, 85)

    # --- Rule 4: Dynamic execution ---
    if dynamic_score >= 50:
        final = max(final, 80)

    # --- Rule 5: Critical techniques ---
    if found_ids & CRITICAL_TECHNIQUES:
        final = max(final, 90)

    # -----------------------------
    # Normalize
    # -----------------------------
    final = min(round(final), 100)

    # -----------------------------
    # Classification
    # -----------------------------
    if final >= 85:
        classification = "Critical"
    elif final >= 70:
        classification = "High"
    elif final >= 40:
        classification = "Medium"
    else:
        classification = "Low"

    # -----------------------------
    # Confidence
    # -----------------------------
    confidence = _confidence(
        scanned_files,
        total_findings,
        packages_analysed,
        ai_ran,
        dynamic_score
    )

    # -----------------------------
    # Debug output
    # -----------------------------
    print(
        f"[score] Static={static_raw:.0f} AI={ai_score:.0f} "
        f"Dep={dep_risk_score:.0f} Dyn={dynamic_score:.0f} "
        f"Factor={dynamic_factor:.2f} -> Final={final} "
        f"[{classification}] Confidence={confidence}%"
    )

    return final, classification, confidence
