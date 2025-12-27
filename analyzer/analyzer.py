from androguard.misc import AnalyzeAPK
from analyzer.permission_engine import check_permissions
from analyzer.risk_engine import calculate_risk

def analyze_apk(apk_path):
    # ⚡ Lightweight static analysis
    a, _, _ = AnalyzeAPK(apk_path, skip_analysis=True)

    permissions = a.get_permissions()
    dangerous = check_permissions(permissions)
    score, level = calculate_risk(dangerous)

    return {
        "package_name": a.get_package(),
        "total_permissions": len(permissions),
        "dangerous_permissions": dangerous,
        "risk_score": score,
        "risk_level": level
    }
