def calculate_dynamic_score(findings):
    score = 0

    for f in findings:
        if "Command execution" in f:
            score += 40
        elif "Network" in f:
            score += 30
        elif "Sensitive" in f:
            score += 40
        elif "Process spawning" in f:
            score += 25
        elif "File write" in f:
            score += 20
        elif "File access" in f:
            score += 10

    return min(score, 100)
