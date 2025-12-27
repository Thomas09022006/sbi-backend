from androguard.misc import AnalyzeAPK
from analyzer.permission_engine import check_permissions
from analyzer.risk_engine import calculate_risk

def analyze_apk(apk_path):
    try:
        # ✅ Correct for androguard 4.1.2
        a, _, _ = AnalyzeAPK(apk_path)
    except Exception as e:
        raise Exception(f"Androguard failed: {e}")

    permissions = a.get_permissions() or []
    dangerous = check_permissions(permissions)
    score, level = calculate_risk(dangerous)

    return {
        "package_name": a.get_package(),
        "total_permissions": len(permissions),
        "dangerous_permissions": dangerous,
        "risk_score": score,
        "risk_level": level
    }
