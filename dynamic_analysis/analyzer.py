def analyze_trace(trace_path):
    findings = []

    try:
        with open(trace_path, "r", errors="ignore") as f:
            data = f.read()

        # --- Command execution ---
        if "execve(" in data or "system(" in data:
            findings.append("Command execution detected")

        # --- Network activity ---
        if "connect(" in data or "socket(" in data:
            findings.append("Network activity detected")

        # --- File access ---
        if "open(" in data:
            findings.append("File access detected")

        # --- Sensitive file access ---
        sensitive_targets = [
            "/etc/passwd",
            "/etc/shadow",
            ".ssh",
            "/root"
        ]
        for target in sensitive_targets:
            if target in data:
                findings.append("Sensitive file access")

        # --- Process spawning ---
        if "clone(" in data or "fork(" in data:
            findings.append("Process spawning detected")

        # --- File write ---
        if "write(" in data:
            findings.append("File write detected")

    except Exception as e:
        findings.append(f"Trace analysis error: {str(e)}")

    return list(set(findings))  # remove duplicates
