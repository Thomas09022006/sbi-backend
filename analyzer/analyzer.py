from androguard.misc import AnalyzeAPK
from analyzer.permission_engine import check_permissions
from analyzer.risk_engine import calculate_risk

def analyze_apk(apk_path):
    # Use official androguard API (stable)
    a, _, _ = AnalyzeAPK(apk_path)

    permissions = a.get_permissions()
    dangerous = check_permissions(permissions)
    score, level = calculate_risk(dangerous)

    return {
        "package": a.get_package(),
        "total_permissions": len(permissions),
        "dangerous_permissions": dangerous,
        "risk_score": score,
        "risk_level": level
    }
