"""
report_generator/report.py
Assembles final structured JSON threat intelligence report.
Includes multi-stage AI + Dynamic analysis results.
"""

import json
from datetime import datetime, timezone
from typing import Dict, List


def _executive_summary(repo_url, score, classification, confidence,
                        static_ttps, dep_findings, ai_analysis,
                        dynamic_results) -> str:
    tier_desc = {
        "Critical": "a CRITICAL threat level — immediate review required",
        "High":     "a HIGH threat level — significant suspicious patterns detected",
        "Medium":   "a MEDIUM threat level — suspicious patterns present, review recommended",
        "Low":      "a LOW apparent threat level — minimal suspicious patterns found",
    }

    all_ids    = [t["technique_id"] for t in static_ttps]
    cve_count  = dep_findings.get("total_cves", 0)
    flagged    = len(dep_findings.get("flagged_packages", []))
    file_res   = ai_analysis.get("file_results", [])
    correlation = ai_analysis.get("correlation", {})

    # --- AI Summary ---
    ai_summary = ""
    if file_res:
        malicious  = sum(1 for r in file_res if r["verdict"] == "malicious")
        suspicious = sum(1 for r in file_res if r["verdict"] == "suspicious")
        chains     = sum(len(r.get("chains", [])) for r in file_res)

        ai_summary = (
            f" AI deep analysis of {len(file_res)} high-risk file(s) found "
            f"{malicious} malicious and {suspicious} suspicious."
        )

        if chains:
            ai_summary += f" {chains} dangerous logic chain(s) detected."

        if correlation.get("coordinated"):
            ai_summary += " Cross-file correlation detected a coordinated attack pattern."

    # --- Dynamic Summary ---
    dynamic_summary = ""
    if dynamic_results:
        behaviors = list({
            finding
            for r in dynamic_results
            for finding in r.get("findings", [])
        })

        if behaviors:
            dynamic_summary = (
                f" Dynamic execution revealed behaviors such as: "
                f"{', '.join(behaviors)}."
            )

    return (
        f"RepoShield analysis of '{repo_url.split('/')[-1]}' indicates "
        f"{tier_desc.get(classification, classification)} "
        f"with a risk score of {score}/100 (confidence: {confidence}%). "
        f"Static analysis identified {len(static_ttps)} unique MITRE ATT&CK "
        f"technique(s): {', '.join(all_ids) if all_ids else 'none'}."
        f"{ai_summary} "
        f"Dependency analysis flagged {flagged} package(s) with {cve_count} known CVE(s)."
        f"{dynamic_summary}"
    )


# ✅ FIXED PARAMETER ORDER
def generate_report(
    # 🔥 REQUIRED FIRST (NO DEFAULTS)
    repo_url:        str,
    static_findings: Dict,
    static_ttps:     List[Dict],
    dep_findings:    Dict,
    ai_analysis:     Dict,

    dynamic_results: List[Dict],
    dynamic_score:   float,

    risk_score:      int,
    classification:  str,
    confidence:      int,

    # 🔥 OPTIONAL AFTER
    dynamic_correlation=None,
    dynamic_ai_correlation=None,
) -> Dict:

    file_res    = ai_analysis.get("file_results", [])
    correlation = ai_analysis.get("correlation", {})
    ai_score    = ai_analysis.get("ai_score", 0.0)

    return {
        "reposhield_report": {
            "metadata": {
                "generated_at":   datetime.now(timezone.utc).isoformat(),
                "tool":           "RepoShield",
                "version":        "1.4.0-dynamic-correlation",
                "phase":          "Static + AI + Dynamic + Correlation",
                "repository_url": repo_url,
            },

            "executive_summary": _executive_summary(
                repo_url, risk_score, classification, confidence,
                static_ttps, dep_findings, ai_analysis,
                dynamic_results
            ),

            "risk_assessment": {
                "unified_score":  risk_score,
                "classification": classification,
                "confidence_pct": confidence,
                "score_breakdown": {
                    "static_techniques_found": len(static_ttps),
                    "ai_files_analysed":       len(file_res),
                    "ai_score":                ai_score,
                    "coordinated_attack":      correlation.get("coordinated", False),

                    "dep_packages_analysed":   dep_findings.get("packages_analysed", 0),
                    "dep_packages_flagged":    len(dep_findings.get("flagged_packages", [])),
                    "total_cves":              dep_findings.get("total_cves", 0),

                    "dynamic_score": dynamic_score,
                },
            },

            "mitre_techniques": [
                {
                    "id":          t["technique_id"],
                    "name":        t["technique_name"],
                    "weight":      t["weight"],
                    "triggers":    t["triggers"],
                    "occurrences": t["occurrences"],
                }
                for t in static_ttps
            ],

            "ai_analysis": {
                "ai_score":        ai_score,
                "files_analysed":  len(file_res),
                "file_results":    file_res,
                "correlation":     correlation,
            },

            "static_analysis": {
                "files_scanned":  static_findings.get("scanned_files", 0),
                "total_findings": static_findings.get("total_findings", 0),
                "pattern_counts": static_findings.get("pattern_counts", {}),
                "findings":       static_findings.get("findings", []),
            },

            "dependency_analysis": {
                "dep_files_found":   dep_findings.get("dep_files_found", []),
                "packages_analysed": dep_findings.get("packages_analysed", 0),
                "total_cves":        dep_findings.get("total_cves", 0),
                "dep_risk_score":    dep_findings.get("dep_risk_score", 0),
                "flagged_packages":  dep_findings.get("flagged_packages", []),
            },

            "dynamic_analysis": {
                "dynamic_score": dynamic_score,
                "files_executed": len(dynamic_results),
                "results": dynamic_results,
                "correlation": dynamic_correlation,
                "ai_correlation": dynamic_ai_correlation,
                "summary": {
                    "suspicious_behaviors": list({
                        finding
                        for r in dynamic_results
                        for finding in r.get("findings", [])
                    })
                }
            },
        }
    }
