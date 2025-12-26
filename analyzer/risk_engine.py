def calculate_risk(dangerous_permissions):
    score = 0

    for p in dangerous_permissions:
        score += 15

    if score >= 70:
        level = "High Risk"
    elif score >= 40:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    return min(score, 100), level
