"""
ttp_engine/mapper.py
Maps static code findings to MITRE ATT&CK techniques.
"""

import json
import os
from typing import List, Dict

RULES_PATH = os.path.join(os.path.dirname(__file__), "ttp_rules.json")


def _load_rules() -> Dict:
    with open(RULES_PATH, "r") as f:
        return json.load(f)


def map_static_findings(findings: List[Dict]) -> List[Dict]:
    """
    Takes a list of static scanner findings.
    Returns a deduplicated list of matched MITRE ATT&CK techniques.
    Each technique includes which patterns triggered it and how many times.
    """
    rules = _load_rules()["static"]
    technique_map = {}

    for finding in findings:
        pattern = finding.get("pattern")
        if not pattern or pattern not in rules:
            continue

        rule = rules[pattern]
        tid  = rule["id"]

        if tid not in technique_map:
            technique_map[tid] = {
                "technique_id":   tid,
                "technique_name": rule["name"],
                "weight":         rule["weight"],
                "triggers":       [],
                "occurrences":    0,
            }

        technique_map[tid]["occurrences"] += 1
        if pattern not in technique_map[tid]["triggers"]:
            technique_map[tid]["triggers"].append(pattern)

    result = list(technique_map.values())
    print(f"[ttp] Unique MITRE techniques identified: {len(result)}")
    return result
